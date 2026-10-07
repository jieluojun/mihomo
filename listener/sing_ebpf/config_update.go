//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"slices"
	"time"

	LC "github.com/metacubex/mihomo/listener/config"

	E "github.com/metacubex/sing/common/exceptions"
)

// ErrRebuildRequired reports a difference this inbound will not take in place.
// The listener maps it to "not handled" rather than to a failure, so the caller
// rebuilds exactly as it would have without an Update at all -- no error is
// logged, because nothing went wrong.
//
// It exists so the reasons a change needs a rebuild can live here, next to the
// data planes that impose them, rather than in the option layer which cannot
// see which planes are running.
var ErrRebuildRequired = E.New("eBPF inbound requires a rebuild to apply this change")

// Update applies a config difference to the running inbound.
//
// The caller has already established that the difference is confined to the
// fields handled here -- see the EBPF listener's Update, which compares the two
// options with exactly these fields cleared -- so anything else this reads is
// the same in both. That split is deliberate: the raw option struct is the only
// place a field added later can be caught, and the reasons a field can or
// cannot be applied in place live down here with the data planes.
//
// Every write is reversible and they are applied as one transaction, so a
// failure leaves the inbound coherent on its previous config rather than half
// on each. The caller still falls back to a rebuild, but it may not get one:
// Listen can fail too, and an inbound that is going to keep running until the
// next reload should not be running on a configuration that never existed.
func (i *Inbound) Update(options LC.EBPF) error {
	steps := i.udpTimeoutSteps(resolveUDPTimeout(options.UDPTimeout))
	bypassStep, err := i.bypassRuleSetStep(options)
	if err != nil {
		return err
	}
	if bypassStep != nil {
		steps = append(steps, *bypassStep)
	}
	if step := i.bypassTUNDirectStep(resolveBypassTUNDirect(options.BypassTUNDirect)); step != nil {
		steps = append(steps, *step)
	}
	return applyReversibleSteps(steps)
}

// udpTimeoutSteps writes the new session timeout to the in-memory value every
// userspace sweep reads and to each data plane's control record. The kernel
// compares the timeout against a flow's last-seen stamp rather than storing a
// deadline, so the change reaches the sessions that already exist.
func (i *Inbound) udpTimeoutSteps(next time.Duration) []reversibleStep {
	previous := i.udpTimeoutValue()
	if next == previous {
		return nil
	}
	steps := []reversibleStep{{
		name:   "UDP timeout",
		apply:  func() error { i.udpTimeout.Store(int64(next)); return nil },
		revert: func() error { i.udpTimeout.Store(int64(previous)); return nil },
	}}
	if backend := i.cgroupBackendInstance(); backend != nil {
		steps = append(steps, reversibleStep{
			name:   "cgroup UDP timeout",
			apply:  func() error { return backend.SetUDPTimeout(next) },
			revert: func() error { return backend.SetUDPTimeout(previous) },
		})
	}
	if backend := i.sharedRewriteBackend(); backend != nil {
		steps = append(steps, reversibleStep{
			name:   "shared packet-rewrite UDP timeout",
			apply:  func() error { return backend.SetUDPTimeout(next) },
			revert: func() error { return backend.SetUDPTimeout(previous) },
		})
	}
	return steps
}

// bypassRuleSetStep swaps the configured rule-set tags, for both scopes, and
// recompiles the kernel bypass policy from them. Only the tags are held, so
// this is a slice swap and a refresh the rule-provider callback already
// performs on its own schedule; refreshBypassCIDRsLocked is itself
// transactional across the data planes.
//
// A tag that does not resolve is refused here rather than dropped. Dropping is
// right when a rule-provider disappears from under a running listener -- the
// honest policy is one without it -- but a tag the user just typed into this
// listener's own config is a typo, and starting with it silently missing is the
// same failure New refuses outright.
func (i *Inbound) bypassRuleSetStep(options LC.EBPF) (*reversibleStep, error) {
	nextLocal, nextShared := effectiveBypassRuleSets(options, i.localEnabled, i.sharedEnabled)
	i.bypassRuleSetAccess.Lock()
	currentLocal, currentShared := i.localBypassTags, i.sharedBypassTags
	i.bypassRuleSetAccess.Unlock()
	if slices.Equal(nextLocal, currentLocal) && slices.Equal(nextShared, currentShared) {
		return nil, nil
	}
	// Whether the scopes share one bypass table is decided when the data
	// planes are built: the shared packet-rewrite plane either borrows the
	// cgroup's table or creates its own. Moving between the two takes a rebuild.
	if bypassScopesSplit(i.localEnabled, i.sharedEnabled, nextLocal, nextShared) != i.bypassSplit {
		return nil, ErrRebuildRequired
	}
	// The shared packet-rewrite backend sizes its bypass flow cache to a single
	// entry when nothing is bypassed, and that size is fixed when the map is
	// created. Only that plane has the constraint -- the cgroup and TC bypass
	// maps are fixed-capacity either way -- so only an inbound actually running
	// it has to be rebuilt when its list crosses between empty and non-empty.
	if i.sharedRewrite != nil && (len(nextShared) == 0) != (len(currentShared) == 0) {
		return nil, ErrRebuildRequired
	}
	if i.providerTunnel == nil {
		return nil, E.New("tunnel does not expose rule providers")
	}
	providers := i.providerTunnel.RuleProviders()
	for _, tag := range mergeRuleSetTags(nextLocal, nextShared) {
		if _, loaded := providers[tag]; !loaded {
			return nil, E.New("parse bypass_rule_set: rule-set not found: ", tag)
		}
	}
	type scopeTags struct{ local, shared []string }
	next := scopeTags{nextLocal, nextShared}
	var previous scopeTags
	swap := func(to scopeTags) error {
		i.bypassRuleSetAccess.Lock()
		defer i.bypassRuleSetAccess.Unlock()
		restore := scopeTags{i.localBypassTags, i.sharedBypassTags}
		restoreAll := i.bypassRuleSetTags
		i.localBypassTags, i.sharedBypassTags = to.local, to.shared
		i.bypassRuleSetTags = mergeRuleSetTags(to.local, to.shared)
		if err := i.refreshBypassCIDRsLocked(); err != nil {
			i.localBypassTags, i.sharedBypassTags = restore.local, restore.shared
			i.bypassRuleSetTags = restoreAll
			return err
		}
		return nil
	}
	return &reversibleStep{
		name: "bypass_rule_set",
		apply: func() error {
			i.bypassRuleSetAccess.Lock()
			previous = scopeTags{i.localBypassTags, i.sharedBypassTags}
			i.bypassRuleSetAccess.Unlock()
			return swap(next)
		},
		revert: func() error { return swap(previous) },
	}, nil
}

// bypassTUNDirectStep republishes the coexistence registry entry, which the
// dial path reads through resolver.EBPFBypassedDirect to decide whether a
// bypassed destination goes direct. It touches no kernel state, which is why it
// cannot fail, and no listener has to notice: the flag feeds only the bypass
// policy value, never the route exclusion a TUN device is built from, so
// nothing about that device goes stale.
func (i *Inbound) bypassTUNDirectStep(next bool) *reversibleStep {
	i.bypassRuleSetAccess.Lock()
	previous := i.bypassTUNDirect
	i.bypassRuleSetAccess.Unlock()
	if next == previous {
		return nil
	}
	publish := func(value bool) error {
		i.bypassRuleSetAccess.Lock()
		defer i.bypassRuleSetAccess.Unlock()
		i.bypassTUNDirect = value
		i.publishBypassPolicyLocked()
		return nil
	}
	return &reversibleStep{
		name:   "bypass_tun_direct",
		apply:  func() error { return publish(next) },
		revert: func() error { return publish(previous) },
	}
}
