//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestResolveEnableAliases(t *testing.T) {
	yes, no := boolPtr(true), boolPtr(false)
	for _, test := range []struct {
		name    string
		enable  *bool
		enabled *bool
		want    *bool
		wantErr bool
	}{
		{name: "neither", want: nil},
		{name: "enable only", enable: yes, want: yes},
		{name: "enabled only", enabled: no, want: no},
		{name: "both agree", enable: yes, enabled: yes, want: yes},
		{name: "both disagree", enable: yes, enabled: no, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, err := resolveEnableAliases(LC.EBPF{
				Local:  LC.EBPFLocal{Enable: test.enable, Enabled: test.enabled},
				Shared: LC.EBPFShared{Enable: test.enable, Enabled: test.enabled},
			})
			if test.wantErr {
				if err == nil {
					t.Fatal("disagreeing enable and enabled were accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for scope, got := range map[string]*bool{"local": options.Local.Enabled, "shared": options.Shared.Enabled} {
				if (got == nil) != (test.want == nil) || (got != nil && *got != *test.want) {
					t.Fatalf("%s.enabled = %v, want %v", scope, got, test.want)
				}
			}
			if options.Local.Enable != nil || options.Shared.Enable != nil {
				t.Fatal("the enable spelling was left behind after folding")
			}
		})
	}
}

// local.enable / shared.enable select the same data planes the matching mode
// does, and combining them with mode stays refused as with enabled.
func TestEnableSpellingSelectsTheSameScopesAsMode(t *testing.T) {
	yes := boolPtr(true)
	shared := LC.EBPFShared{Enable: yes, Interface: []string{"br0"}}
	for _, test := range []struct {
		name          string
		options       LC.EBPF
		local, shared bool
	}{
		{name: "local", options: LC.EBPF{Local: LC.EBPFLocal{Enable: yes}}, local: true},
		{name: "shared", options: LC.EBPF{Shared: shared}, shared: true},
		{name: "hybrid", options: LC.EBPF{Local: LC.EBPFLocal{Enable: yes}, Shared: shared}, local: true, shared: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, _, err := applyLegacyOptions(test.options)
			if err != nil {
				t.Fatal(err)
			}
			selection, err := normalizeDataPlanes(options)
			if err != nil {
				t.Fatal(err)
			}
			if selection.localEnabled != test.local || selection.sharedEnabled != test.shared {
				t.Fatalf("local=%v shared=%v, want local=%v shared=%v",
					selection.localEnabled, selection.sharedEnabled, test.local, test.shared)
			}
		})
	}
	options, _, err := applyLegacyOptions(LC.EBPF{Mode: "hybrid", Local: LC.EBPFLocal{Enable: yes}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = normalizeDataPlanes(options); err == nil {
		t.Fatal("mode combined with local.enable was accepted")
	}
}

func TestEffectiveBypassRuleSets(t *testing.T) {
	for _, test := range []struct {
		name          string
		options       LC.EBPF
		local, shared bool
		wantLocal     []string
		wantShared    []string
		wantSplit     bool
	}{
		{
			name:      "top level, both scopes",
			options:   LC.EBPF{BypassRuleSet: []string{"cn"}},
			local:     true,
			shared:    true,
			wantLocal: []string{"cn"}, wantShared: []string{"cn"},
		},
		{
			name:      "top level, local only",
			options:   LC.EBPF{BypassRuleSet: []string{"cn"}},
			local:     true,
			wantLocal: []string{"cn"},
		},
		{
			name: "a scope adds to the top level",
			options: LC.EBPF{
				BypassRuleSet: []string{"cn"},
				Local:         LC.EBPFLocal{BypassRuleSet: []string{"lan"}},
			},
			local:     true,
			shared:    true,
			wantLocal: []string{"cn", "lan"}, wantShared: []string{"cn"},
			wantSplit: true,
		},
		{
			name: "per scope, the same sets in another order",
			options: LC.EBPF{
				Local:  LC.EBPFLocal{BypassRuleSet: []string{"cn", "lan"}},
				Shared: LC.EBPFShared{BypassRuleSet: []string{"lan", "cn"}},
			},
			local:     true,
			shared:    true,
			wantLocal: []string{"cn", "lan"}, wantShared: []string{"lan", "cn"},
		},
		{
			name: "a tag listed twice counts once",
			options: LC.EBPF{
				BypassRuleSet: []string{"cn"},
				Local:         LC.EBPFLocal{BypassRuleSet: []string{"cn"}},
			},
			local:     true,
			wantLocal: []string{"cn"},
		},
		{
			name: "a disabled scope bypasses nothing",
			options: LC.EBPF{
				Shared: LC.EBPFShared{BypassRuleSet: []string{"cn"}},
			},
			local: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local, shared := effectiveBypassRuleSets(test.options, test.local, test.shared)
			if !slices.Equal(local, test.wantLocal) || !slices.Equal(shared, test.wantShared) {
				t.Fatalf("local=%v shared=%v, want local=%v shared=%v", local, shared, test.wantLocal, test.wantShared)
			}
			if split := bypassScopesSplit(test.local, test.shared, local, shared); split != test.wantSplit {
				t.Fatalf("split=%v, want %v", split, test.wantSplit)
			}
		})
	}
}

// Both disabled scopes ignore populated templates, including rule-set names.
func TestInactiveScopeBypassRuleSet(t *testing.T) {
	local, _, err := applyLegacyOptions(LC.EBPF{
		Shared: LC.EBPFShared{Enable: boolPtr(true)},
		Local:  LC.EBPFLocal{BypassRuleSet: []string{"cn"}},
	})
	if err != nil || len(local.Local.BypassRuleSet) != 0 {
		t.Fatalf("disabled local rule sets survived: %+v, %v", local.Local, err)
	}
	options, _, err := applyLegacyOptions(LC.EBPF{
		Local:  LC.EBPFLocal{Enable: boolPtr(true)},
		Shared: LC.EBPFShared{BypassRuleSet: []string{"cn"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Shared.BypassRuleSet) != 0 {
		t.Fatalf("shared.bypass-rule-set = %v survived with the shared scope disabled", options.Shared.BypassRuleSet)
	}
}

func splitInboundForTest(t *testing.T, providerTunnel *fakeRuleProviderTunnel, local, shared []string) *Inbound {
	t.Helper()
	i := &Inbound{
		providerTunnel:    providerTunnel,
		localEnabled:      true,
		sharedEnabled:     true,
		bypassRuleSetTags: mergeRuleSetTags(local, shared),
		localBypassTags:   local,
		sharedBypassTags:  shared,
		bypassSplit:       bypassScopesSplit(true, true, local, shared),
	}
	i.udpTimeout.Store(int64(300 * time.Second))
	i.bypassTUNDirect = true
	i.bypassPublisher = resolver.NewEBPFBypassPublisher()
	t.Cleanup(i.bypassPublisher.Close)
	i.bypassRuleSetAccess.Lock()
	err := i.refreshBypassCIDRsLocked()
	i.bypassRuleSetAccess.Unlock()
	if err != nil {
		t.Fatalf("seed bypass policy: %v", err)
	}
	return i
}

// Split, each scope's policy carries only its own rule sets, while the DNS
// fake-ip set and the TUN coexistence policy are built from both.
func TestSplitRefreshCompilesAPolicyPerScope(t *testing.T) {
	china := netip.MustParsePrefix("10.0.0.0/8")
	lan := netip.MustParsePrefix("192.168.0.0/16")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"cn":  newFakeIPCIDRRuleProvider(t, "cn", china),
		"lan": newFakeIPCIDRRuleProvider(t, "lan", lan),
	}}
	i := splitInboundForTest(t, providerTunnel, []string{"cn", "lan"}, []string{"cn"})
	if !i.bypassSplit {
		t.Fatal("different scope rule sets did not split")
	}
	if got := i.bypassRuleSetPolicy.Prefixes(); !slices.Contains(got, china) || !slices.Contains(got, lan) {
		t.Fatalf("local policy = %v, want %v and %v", got, china, lan)
	}
	if got := i.sharedBypassRuleSetPolicy.Prefixes(); !slices.Equal(got, []netip.Prefix{china}) {
		t.Fatalf("shared policy = %v, want only %v", got, china)
	}
	if !slices.Contains(i.bypassCIDR, china) || !slices.Contains(i.bypassCIDR, lan) {
		t.Fatalf("published union = %v, want %v and %v", i.bypassCIDR, china, lan)
	}
	if i.dnsBypassSet == nil || !i.dnsBypassSet.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("the DNS fake-ip set lost the local-only rule set")
	}
}

// Whether the scopes share a bypass table is fixed when the data planes are
// built, so a config change that moves between shared and split tables takes
// a rebuild, while one that stays split is applied in place.
func TestUpdateOfScopedBypassRuleSets(t *testing.T) {
	china := netip.MustParsePrefix("10.0.0.0/8")
	lan := netip.MustParsePrefix("192.168.0.0/16")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"cn":  newFakeIPCIDRRuleProvider(t, "cn", china),
		"lan": newFakeIPCIDRRuleProvider(t, "lan", lan),
	}}

	joint := splitInboundForTest(t, providerTunnel, []string{"cn"}, []string{"cn"})
	err := joint.Update(LC.EBPF{UDPTimeout: 300, BypassRuleSet: []string{"cn"}, Local: LC.EBPFLocal{BypassRuleSet: []string{"lan"}}})
	if !errors.Is(err, ErrRebuildRequired) {
		t.Fatalf("splitting the scopes in place = %v, want a rebuild request", err)
	}

	split := splitInboundForTest(t, providerTunnel, []string{"cn", "lan"}, []string{"cn"})
	err = split.Update(LC.EBPF{UDPTimeout: 300, Local: LC.EBPFLocal{BypassRuleSet: []string{"lan"}}, Shared: LC.EBPFShared{BypassRuleSet: []string{"cn"}}})
	if err != nil {
		t.Fatalf("a change that stays split: %v", err)
	}
	if !slices.Equal(split.localBypassTags, []string{"lan"}) || !slices.Equal(split.sharedBypassTags, []string{"cn"}) {
		t.Fatalf("tags local=%v shared=%v after update", split.localBypassTags, split.sharedBypassTags)
	}
	if got := split.bypassRuleSetPolicy.Prefixes(); !slices.Equal(got, []netip.Prefix{lan}) {
		t.Fatalf("local policy = %v after update, want only %v", got, lan)
	}

	err = split.Update(LC.EBPF{UDPTimeout: 300, BypassRuleSet: []string{"cn", "lan"}})
	if !errors.Is(err, ErrRebuildRequired) {
		t.Fatalf("joining the scopes in place = %v, want a rebuild request", err)
	}

	sharedOnly := updatableInboundForTest(t, providerTunnel, "cn")
	sharedOnly.localEnabled = false
	sharedOnly.sharedEnabled = true
	if err = sharedOnly.Update(LC.EBPF{UDPTimeout: 300, BypassRuleSet: []string{"cn"}, Local: LC.EBPFLocal{BypassRuleSet: []string{"missing"}}}); err != nil {
		t.Fatalf("disabled local rule sets affected update: %v", err)
	}
}
