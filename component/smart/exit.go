package smart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	ExitProbeBodyLimit = 2048

	ReasonRegionUnavailable = "region unavailable"

	// A suspicion needs independent nodes of the same key, one answer never condemns a whole
	// region or network.
	suspectThreshold          = 2
	suspectMaxControlExitKeys = 16
	suspectMaxTargets         = 4096

	// exit probes keep their own slots; a slow trace cannot hold back the status probes
	exitProbeMaxInflight = 2
)

// The intervals are variables so a test can shrink them instead of waiting them out.
var (
	suspectConfirmWindow = 10 * time.Minute
	exitRegionTTL        = 6 * time.Hour
	exitProbeRetryGap    = 15 * time.Minute
)

var exitProbeInflight = make(chan struct{}, exitProbeMaxInflight)

// ExitTraceURLs are tried in order, so a blocked endpoint costs a fallback instead of the
// answer; the first answers with `key=value` lines, the others with JSON.
var ExitTraceURLs = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://api.ip.sb/geoip",
	"https://ipwho.is/",
}

type ExitProbeResult struct {
	Region string
	ASN    string
	Key    string
}

// ExitProber reports where a node's traffic lands; the address behind the answer is
// consumed by the probe itself and never handed back.
type ExitProber interface {
	ExitProbe(ctx context.Context, wantASN bool) (*ExitProbeResult, error)
}

type ExitInfo struct {
	Region  string `json:"region,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Key     string `json:"key,omitempty"`
	Updated int64  `json:"updated,omitempty"`
}

type exitRecord struct {
	info   ExitInfo
	failed int64
}

type suspectHalfOpen struct {
	owner   string
	until   int64
	expires int64
}

type ExitState struct {
	mu       sync.RWMutex
	nodes    map[string]*exitRecord
	refusals exitHold
	controls exitHold
}

// exitHold keeps one target per node, dropped once the confirm window passes.
type exitHold map[string]map[string]int64

// SuspectTracker raises a suspicion for one key domain, such as a region or a network:
// the other nodes of that key are only moved behind the rest until the suspicion expires.
// One exit machine counts once, however many nodes run on it.
type SuspectTracker struct {
	mu         sync.RWMutex
	pending    map[string]map[string]map[string]int64
	successes  map[string]map[string]map[string]int64
	suspected  map[string]map[string]int64
	halfOpen   map[string]map[string]suspectHalfOpen
	lastPruned atomic.Int64
	active     atomic.Bool
}

type ExitWatcher struct {
	ExitState

	name       string
	config     string
	store      *Store
	wantASN    func() bool
	beginProbe func() (func(), bool)
	inflight   xsync.Map[string, struct{}]
	seeded     xsync.Map[string, struct{}]
	regions    SuspectTracker
	asns       SuspectTracker
}

type ExitWatcherOptions struct {
	Name    string
	Config  string
	Store   *Store
	WantASN func() bool
	// BeginProbe registers asynchronous work with the owner's shutdown barrier.
	BeginProbe func() (done func(), accepted bool)
}

func (h *exitHold) add(target, node string, at int64) {
	if *h == nil {
		*h = make(exitHold)
	}
	for heldNode, targets := range *h {
		for heldTarget, heldAt := range targets {
			if at-heldAt > int64(suspectConfirmWindow) {
				delete(targets, heldTarget)
			}
		}
		if len(targets) == 0 {
			delete(*h, heldNode)
		}
	}
	if (*h)[node] == nil {
		(*h)[node] = make(map[string]int64)
	}
	(*h)[node][target] = at
}

func (h exitHold) take(node string, at int64) []string {
	targets := h[node]
	delete(h, node)
	if len(targets) == 0 {
		return nil
	}
	released := make([]string, 0, len(targets))
	for target, heldAt := range targets {
		if at-heldAt >= 0 && at-heldAt <= int64(suspectConfirmWindow) {
			released = append(released, target)
		}
	}
	return released
}

func (s *ExitState) Due(node string, ttl, retry time.Duration, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.nodes[node]
	if !ok {
		return true
	}
	if rec.info.Updated != 0 && now.Unix()-rec.info.Updated < int64(ttl.Seconds()) {
		return false
	}
	return rec.failed == 0 || now.Unix()-rec.failed >= int64(retry.Seconds())
}

func (s *ExitState) NoteFailure(node string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.record(node)
	rec.failed = now.Unix()
}

func (s *ExitState) Store(node string, info ExitInfo, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info.Updated = now.Unix()
	rec := s.record(node)
	rec.info = info
	rec.failed = 0
}

// Seed restores an earlier answer; a fresher in-memory answer always wins.
func (s *ExitState) Seed(node string, info ExitInfo) {
	if info.Updated == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.nodes[node]; ok && rec.info.Updated >= info.Updated {
		return
	}
	s.record(node).info = info
}

func (s *ExitState) Info(node string) ExitInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rec, ok := s.nodes[node]; ok {
		return rec.info
	}
	return ExitInfo{}
}

// Withhold holds a refusal until its node's exit answer arrives; Release completes it.
func (s *ExitState) Withhold(target, node string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusals.add(target, node, time.Now().UnixNano())
}

// WithholdSuccess holds a 2xx control until its node's exit answer arrives, so the answer can
// still corroborate the refusal of another key; ReleaseSuccess replays it.
func (s *ExitState) WithholdSuccess(target, node string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controls.add(target, node, time.Now().UnixNano())
}

func (s *ExitState) Release(node string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refusals.take(node, time.Now().UnixNano())
}

func (s *ExitState) ReleaseSuccess(node string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.controls.take(node, time.Now().UnixNano())
}

func (s *ExitState) record(node string) *exitRecord {
	if s.nodes == nil {
		s.nodes = make(map[string]*exitRecord)
	}
	rec, ok := s.nodes[node]
	if !ok {
		rec = &exitRecord{}
		s.nodes[node] = rec
	}
	return rec
}

func (t *SuspectTracker) Note(target, key, identity string, now time.Time) (raised bool) {
	if target == "" || key == "" || identity == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneIfDueLocked(now)

	if until, ok := t.suspected[target][key]; ok && until > now.UnixNano() {
		// a fresh refusal is more evidence, it carries the suspicion forward
		t.suspected[target][key] = now.Add(probeRegionalBlockTTL).UnixNano()
		delete(t.halfOpen[target], key)
		return false
	}
	if _, pending := t.pending[target]; !pending {
		if _, suspected := t.suspected[target]; !suspected && len(t.pending)+len(t.suspected) >= suspectMaxTargets {
			return false
		}
	}

	if t.pending == nil {
		t.pending = make(map[string]map[string]map[string]int64)
	}
	keys := t.pending[target]
	if keys == nil {
		keys = make(map[string]map[string]int64)
		t.pending[target] = keys
	}
	seen := keys[key]
	if seen == nil {
		seen = make(map[string]int64)
		keys[key] = seen
	}
	seen[identity] = now.UnixNano()
	if len(seen) < suspectThreshold || !t.hasControlSuccess(target, key, seen) {
		return false
	}

	if t.suspected == nil {
		t.suspected = make(map[string]map[string]int64)
	}
	suspicions := t.suspected[target]
	if suspicions == nil {
		suspicions = make(map[string]int64)
		t.suspected[target] = suspicions
	}
	suspicions[key] = now.Add(probeRegionalBlockTTL).UnixNano()
	delete(t.halfOpen[target], key)
	delete(keys, key)
	if len(keys) == 0 {
		delete(t.pending, target)
	}
	t.active.Store(true)
	return true
}

func (t *SuspectTracker) NoteSuccess(target, key, identity string, now time.Time) []string {
	if target == "" || key == "" || identity == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneIfDueLocked(now)
	failures := t.pending[target]
	for failedKey, identities := range failures {
		for failedIdentity, at := range identities {
			if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
				delete(identities, failedIdentity)
			}
		}
		if len(identities) == 0 {
			delete(failures, failedKey)
		}
	}
	if len(failures) == 0 {
		delete(t.pending, target)
	}
	controlSuccesses := t.successes[target]
	for successKey, identities := range controlSuccesses {
		for successIdentity, at := range identities {
			if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
				delete(identities, successIdentity)
			}
		}
		if len(identities) == 0 {
			delete(controlSuccesses, successKey)
		}
	}
	if len(controlSuccesses) == 0 {
		delete(t.successes, target)
	}
	if t.successes == nil {
		t.successes = make(map[string]map[string]map[string]int64)
	}
	keys := t.successes[target]
	if keys == nil {
		if len(t.successes) >= probeMaxEntries {
			return nil
		}
		keys = make(map[string]map[string]int64)
		t.successes[target] = keys
	}
	seen := keys[key]
	if _, exists := seen[identity]; !exists {
		controlCount := 0
		for _, identities := range keys {
			controlCount += len(identities)
		}
		if controlCount >= suspectMaxControlExitKeys {
			return nil
		}
	}
	if seen == nil {
		seen = make(map[string]int64)
		keys[key] = seen
	}
	seen[identity] = now.UnixNano()

	var raised []string
	for failedKey, identities := range t.pending[target] {
		if len(identities) < suspectThreshold || !t.hasControlSuccess(target, failedKey, identities) {
			continue
		}
		if t.suspected == nil {
			t.suspected = make(map[string]map[string]int64)
		}
		suspicions := t.suspected[target]
		if suspicions == nil {
			suspicions = make(map[string]int64)
			t.suspected[target] = suspicions
		}
		suspicions[failedKey] = now.Add(probeRegionalBlockTTL).UnixNano()
		delete(t.halfOpen[target], failedKey)
		delete(failures, failedKey)
		raised = append(raised, failedKey)
	}
	if len(failures) == 0 {
		delete(t.pending, target)
	}
	if len(raised) > 0 {
		t.active.Store(true)
	}
	return raised
}

func (t *SuspectTracker) hasControlSuccess(target, failedKey string, failures map[string]int64) bool {
	for successKey, identities := range t.successes[target] {
		if successKey == failedKey {
			continue
		}
		for identity := range identities {
			if _, sameExit := failures[identity]; !sameExit {
				return true
			}
		}
	}
	return false
}

func (t *SuspectTracker) Suspected(target, key string, now time.Time) bool {
	if !t.active.Load() || target == "" || key == "" {
		return false
	}
	// the cleanup mutates the maps, the lookup itself only reads them
	t.pruneIfDue(now)
	t.mu.RLock()
	defer t.mu.RUnlock()
	if until, ok := t.suspected[target][key]; ok {
		if until > now.UnixNano() {
			return true
		}
	}
	state, ok := t.halfOpen[target][key]
	return ok && state.owner != "" && state.until > now.UnixNano()
}

func (t *SuspectTracker) Active() bool {
	return t.active.Load()
}

func (t *SuspectTracker) Defer(target, key, owner string, now time.Time, lease time.Duration) bool {
	if !t.active.Load() || target == "" || key == "" || owner == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	nowNano := now.UnixNano()
	t.pruneIfDueLocked(now)
	until, suspected := t.suspected[target][key]
	if suspected && until > nowNano {
		return true
	}
	state, leased := t.halfOpen[target][key]
	if !suspected && !leased {
		return false
	}
	if suspected {
		delete(t.suspected[target], key)
		if len(t.suspected[target]) == 0 {
			delete(t.suspected, target)
		}
	}
	if leased && state.expires <= nowNano {
		delete(t.halfOpen[target], key)
		leased = false
	}
	if leased && state.owner != "" && state.until > nowNano {
		return true
	}
	if t.halfOpen == nil {
		t.halfOpen = make(map[string]map[string]suspectHalfOpen)
	}
	keys := t.halfOpen[target]
	if keys == nil {
		keys = make(map[string]suspectHalfOpen)
		t.halfOpen[target] = keys
	}
	state.owner = owner
	state.until = now.Add(lease).UnixNano()
	if state.expires == 0 {
		state.expires = now.Add(exitRegionTTL).UnixNano()
	}
	keys[key] = state
	t.active.Store(true)
	return true
}

func (t *SuspectTracker) ReleaseHalfOpen(target, key, owner string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state, ok := t.halfOpen[target][key]; ok && state.owner == owner {
		state.owner = ""
		state.until = 0
		t.halfOpen[target][key] = state
	}
}

func (t *SuspectTracker) TryHalfOpen(target, key, owner string, now time.Time, lease time.Duration) bool {
	if target == "" || key == "" || owner == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	nowNano := now.UnixNano()
	until := t.suspected[target][key]
	state, leased := t.halfOpen[target][key]
	if leased && state.owner != "" && state.until > nowNano {
		return state.owner == owner
	}
	if until <= nowNano && (!leased || state.expires <= nowNano) {
		return false
	}
	if t.halfOpen == nil {
		t.halfOpen = make(map[string]map[string]suspectHalfOpen)
	}
	keys := t.halfOpen[target]
	if keys == nil {
		keys = make(map[string]suspectHalfOpen)
		t.halfOpen[target] = keys
	}
	if until <= nowNano {
		until = state.expires
	}
	keys[key] = suspectHalfOpen{owner: owner, until: now.Add(lease).UnixNano(), expires: until}
	t.active.Store(true)
	return true
}

// Clear drops a suspicion that a later answer has disproved.
func (t *SuspectTracker) Clear(target, key string) {
	if target == "" || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if keys := t.pending[target]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(t.pending, target)
		}
	}
	if keys := t.suspected[target]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(t.suspected, target)
		}
	}
	if keys := t.halfOpen[target]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(t.halfOpen, target)
		}
	}
	t.active.Store(len(t.suspected) > 0 || len(t.halfOpen) > 0)
}

func (t *SuspectTracker) prune(now time.Time) {
	nowNano := now.UnixNano()
	for target, keys := range t.pending {
		for key, seen := range keys {
			for identity, at := range seen {
				if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
					delete(seen, identity)
				}
			}
			if len(seen) == 0 {
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.pending, target)
		}
	}
	for target, keys := range t.suspected {
		for key, until := range keys {
			if until <= nowNano {
				if t.halfOpen == nil {
					t.halfOpen = make(map[string]map[string]suspectHalfOpen)
				}
				halfOpen := t.halfOpen[target]
				if halfOpen == nil {
					halfOpen = make(map[string]suspectHalfOpen)
					t.halfOpen[target] = halfOpen
				}
				if _, exists := halfOpen[key]; !exists {
					halfOpen[key] = suspectHalfOpen{expires: now.Add(exitRegionTTL).UnixNano()}
				}
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.suspected, target)
		}
	}
	for target, keys := range t.halfOpen {
		for key, state := range keys {
			if state.owner != "" && state.until <= nowNano {
				state.owner = ""
				state.until = 0
				keys[key] = state
			}
			if state.expires <= nowNano {
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.halfOpen, target)
		}
	}
	for target, keys := range t.successes {
		for key, seen := range keys {
			for identity, at := range seen {
				if now.Sub(time.Unix(0, at)) > suspectConfirmWindow {
					delete(seen, identity)
				}
			}
			if len(seen) == 0 {
				delete(keys, key)
			}
		}
		if len(keys) == 0 {
			delete(t.successes, target)
		}
	}
	t.lastPruned.Store(nowNano)
	t.active.Store(len(t.suspected) > 0 || len(t.halfOpen) > 0)
}

// pruneDue reports whether the periodic cleanup is due; the caller decides which lock to take.
func (t *SuspectTracker) pruneDue(now time.Time) bool {
	interval := suspectConfirmWindow
	if interval > time.Minute {
		interval = time.Minute
	}
	return now.UnixNano()-t.lastPruned.Load() >= int64(interval)
}

// pruneIfDue runs the cleanup for a read path, it takes the write lock itself.
func (t *SuspectTracker) pruneIfDue(now time.Time) {
	if !t.pruneDue(now) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// another reader may have pruned while this one waited for the lock
	if !t.pruneDue(now) {
		return
	}
	t.prune(now)
}

// pruneIfDueLocked runs the cleanup for a caller that already holds the write lock.
func (t *SuspectTracker) pruneIfDueLocked(now time.Time) {
	if !t.pruneDue(now) {
		return
	}
	t.prune(now)
}

func NewExitWatcher(options ExitWatcherOptions) *ExitWatcher {
	return &ExitWatcher{name: options.Name, config: options.Config, store: options.Store, wantASN: options.WantASN, beginProbe: options.BeginProbe}
}

// TryStartExitProbe takes one exit probe slot; the returned function releases it.
func TryStartExitProbe() (func(), bool) {
	select {
	case exitProbeInflight <- struct{}{}:
		return func() { <-exitProbeInflight }, true
	default:
		return nil, false
	}
}

// MaybeProbe learns where a node's traffic lands, at most once per exitRegionTTL.
func (w *ExitWatcher) MaybeProbe(parent context.Context, proxy C.Proxy) {
	prober, ok := proxy.(ExitProber)
	if !ok {
		return
	}
	node := proxy.Name()
	now := time.Now()
	w.EnsureLoaded(node)
	if !w.Due(node, exitRegionTTL, exitProbeRetryGap, now) {
		return
	}
	if _, loaded := w.inflight.LoadOrStore(node, struct{}{}); loaded {
		return
	}
	var finish func()
	if w.beginProbe != nil {
		var accepted bool
		finish, accepted = w.beginProbe()
		if !accepted {
			w.inflight.Delete(node)
			return
		}
	}

	go func() {
		if finish != nil {
			defer finish()
		}
		defer w.inflight.Delete(node)

		done, ok := TryStartExitProbe()
		if !ok {
			return
		}
		defer done()
		if !AllowGlobalProbe(time.Now()) {
			return
		}

		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
		defer cancel()

		wantASN := w.wantASN != nil && w.wantASN()
		result, err := prober.ExitProbe(ctx, wantASN)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return
			}
			failedAt := time.Now()
			w.NoteFailure(node, failedAt)
			w.storeExitFailure(node, failedAt)
			log.Debugln("[Smart] Exit probe [%s] node [%s] failed: %s", w.name, node, err.Error())
			return
		}

		w.Store(node, ExitInfo{Region: result.Region, ASN: result.ASN, Key: result.Key}, time.Now())
		if result.ASN != "" {
			log.Debugln("[Smart] Exit probe [%s] node [%s] -> region [%s] asn [%s]", w.name, node, result.Region, result.ASN)
		} else {
			log.Debugln("[Smart] Exit probe [%s] node [%s] -> region [%s]", w.name, node, result.Region)
		}
		w.storeExitState(node, w.Info(node))
		for _, target := range w.Release(node) {
			log.Debugln("[Smart] Exit refusal released [%s] target [%s] node [%s] after its exit answer", w.name, target, node)
			w.confirm(target, node)
		}
		for _, target := range w.ReleaseSuccess(node) {
			log.Debugln("[Smart] Exit control released [%s] target [%s] node [%s] after its exit answer", w.name, target, node)
			w.NoteSuccess(target, node)
		}
	}()
}

// EnsureLoaded reads the stored answer of a node once per run, so a connection arriving
// before any probe already reports what an earlier run learned; a failed probe keeps its
// retry gap. A connection racing the first load may still see the node as unknown.
func (w *ExitWatcher) EnsureLoaded(node string) {
	if _, loaded := w.seeded.LoadOrStore(node, struct{}{}); loaded {
		return
	}
	info, failed, ok := w.loadExitState(node)
	if !ok {
		return
	}
	if info.Updated != 0 {
		w.Seed(node, info)
	}
	if failed != 0 {
		w.NoteFailure(node, time.Unix(failed, 0))
	}
}

// storeExitState keeps the learned exit on the node state, where later runs can read it;
// an answer without an ASN keeps the one learned earlier.
func (w *ExitWatcher) storeExitState(node string, info ExitInfo) {
	if w.store == nil {
		return
	}
	w.store.UpdateNodeState(w.name, w.config, node, func(state *NodeState) {
		state.ExitRegion = info.Region
		if info.ASN != "" {
			state.ExitASN = info.ASN
		}
		state.ExitKey = info.Key
		state.ExitUpdated = info.Updated
		state.ExitFailed = 0
	})
}

// storeExitFailure persists the failed attempt, so a restart waits the retry gap again.
func (w *ExitWatcher) storeExitFailure(node string, at time.Time) {
	if w.store == nil {
		return
	}
	w.store.UpdateNodeState(w.name, w.config, node, func(state *NodeState) {
		state.ExitFailed = at.Unix()
	})
}

// loadExitState lets a restart reuse an answer that is still fresh.
func (w *ExitWatcher) loadExitState(node string) (ExitInfo, int64, bool) {
	if w.store == nil {
		return ExitInfo{}, 0, false
	}
	raw, ok := w.store.NodeStateBytes(w.name, w.config, node)
	if !ok {
		return ExitInfo{}, 0, false
	}
	var state NodeState
	if json.Unmarshal(raw, &state) != nil {
		return ExitInfo{}, 0, false
	}
	info := ExitInfo{Region: state.ExitRegion, ASN: state.ExitASN, Key: state.ExitKey, Updated: state.ExitUpdated}
	return info, state.ExitFailed, true
}

// Note blames a refusal on the node's own answer; while that answer is unknown the
// suspicion waits for it instead of being dropped. It reports whether a suspicion was raised.
func (w *ExitWatcher) Note(target, node string) bool {
	if w.Info(node).Region == "" && w.asnOf(node) == "" {
		w.Withhold(target, node)
		log.Debugln("[Smart] Exit refusal [%s] target [%s] node [%s] held until its exit answer arrives", w.name, target, node)
		return false
	}
	return w.confirm(target, node)
}

// NoteSuccess records a 2xx control answer of the target and reports whether it raised a
// suspicion for another key; an answer that arrives before the node's exit is held and later
// replayed by ReleaseSuccess.
func (w *ExitWatcher) NoteSuccess(target, node string) bool {
	info := w.Info(node)
	asn := w.asnOf(node)
	if info.Region == "" && asn == "" {
		w.WithholdSuccess(target, node)
		log.Debugln("[Smart] Exit control [%s] target [%s] node [%s] held until its exit answer arrives", w.name, target, node)
		return false
	}
	identity := w.identity(node)
	now := time.Now()
	raised := false
	if info.Region != "" {
		for _, failedRegion := range w.regions.NoteSuccess(target, info.Region, identity, now) {
			raised = true
			log.Debugln("[Smart] Exit suspect [%s] target [%s] region [%s] raised after a successful control from [%s]",
				w.name, target, failedRegion, node)
		}
	}
	if asn != "" {
		for _, failedASN := range w.asns.NoteSuccess(target, asn, identity, now) {
			raised = true
			log.Debugln("[Smart] Exit suspect [%s] target [%s] asn [%s] raised after a successful control from [%s]",
				w.name, target, failedASN, node)
		}
	}
	if raised {
		w.dropUnwrapResult(target)
	}
	return raised
}

func (w *ExitWatcher) confirm(target, node string) bool {
	now := time.Now()
	identity := w.identity(node)
	raised := false
	if region := w.Info(node).Region; region != "" {
		if w.regions.Note(target, region, identity, now) {
			raised = true
			log.Debugln("[Smart] Exit suspect [%s] target [%s] region [%s] raised by node [%s]",
				w.name, target, region, node)
		}
	}
	if asn := w.asnOf(node); asn != "" {
		if w.asns.Note(target, asn, identity, now) {
			raised = true
			log.Debugln("[Smart] Exit suspect [%s] target [%s] asn [%s] raised by node [%s]",
				w.name, target, asn, node)
		}
	}
	if raised {
		w.dropUnwrapResult(target)
	}
	return raised
}

// A target pinned to a node of the suspected key would keep dialing that node, so the pin is
// dropped and the next selection ranks the nodes again.
func (w *ExitWatcher) dropUnwrapResult(target string) {
	if w.store == nil {
		return
	}
	w.store.DeleteUnwrapResult(w.name, w.config, target)
	log.Debugln("[Smart] Exit suspect [%s] target [%s] unwrap pin cleared", w.name, target)
}

// identity tells the exit machines of two nodes apart, falling back to the node name.
func (w *ExitWatcher) identity(node string) string {
	if key := w.Info(node).Key; key != "" {
		return key
	}
	return node
}

// asnOf reports the network of a node only while the group works with networks.
func (w *ExitWatcher) asnOf(node string) string {
	if w.wantASN == nil || !w.wantASN() {
		return ""
	}
	return w.Info(node).ASN
}

// Suspected reports whether the region the node lands in, or the network it runs on, is
// under suspicion for the target; a suspicion only reorders candidates, callers must
// never drop one.
func (w *ExitWatcher) Suspected(target, node string) bool {
	if !w.regions.Active() && !w.asns.Active() {
		return false
	}
	now := time.Now()
	info := w.Info(node)
	if info.Region != "" && w.regions.Suspected(target, info.Region, now) {
		return true
	}
	if w.wantASN != nil && w.wantASN() && info.ASN != "" && w.asns.Suspected(target, info.ASN, now) {
		return true
	}
	return false
}

func (w *ExitWatcher) Defer(target, node string, now time.Time, lease time.Duration) bool {
	if !w.regions.Active() && !w.asns.Active() {
		return false
	}
	info := w.Info(node)
	if w.wantASN != nil && w.wantASN() && info.ASN != "" && w.asns.Defer(target, info.ASN, node, now, lease) {
		return true
	}
	if info.Region == "" {
		return false
	}
	return w.regions.Defer(target, info.Region, node, now, lease)
}

func (w *ExitWatcher) AllowFallback(target, node string, now time.Time, lease time.Duration) bool {
	info := w.Info(node)
	regionSuspected := info.Region != "" && w.regions.Suspected(target, info.Region, now)
	asnSuspected := w.wantASN != nil && w.wantASN() && info.ASN != "" && w.asns.Suspected(target, info.ASN, now)
	if !regionSuspected && !asnSuspected {
		return true
	}
	claimedASN := false
	if asnSuspected {
		if !w.asns.TryHalfOpen(target, info.ASN, node, now, lease) {
			return false
		}
		claimedASN = true
	}
	if regionSuspected && !w.regions.TryHalfOpen(target, info.Region, node, now, lease) {
		if claimedASN {
			w.asns.ReleaseHalfOpen(target, info.ASN, node)
		}
		return false
	}
	return true
}

// Clear drops the suspicions an answered node has disproved.
func (w *ExitWatcher) Clear(target, node string) {
	if region := w.Info(node).Region; region != "" {
		w.regions.Clear(target, region)
	}
	if asn := w.asnOf(node); asn != "" {
		w.asns.Clear(target, asn)
	}
}

// ParseExitAnswer reads the region and address out of any of the exit endpoints; the
// address is only for the caller's own lookup and must not be stored.
func ParseExitAnswer(body []byte) (region string, ip netip.Addr) {
	if region, ip = ParseExitTrace(body); region != "" {
		return region, ip
	}
	var answer struct {
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		IP          string `json:"ip"`
	}
	if json.Unmarshal(body, &answer) != nil {
		return "", netip.Addr{}
	}
	code := answer.CountryCode
	if code == "" && len(answer.Country) == 2 {
		code = answer.Country
	}
	if code = strings.ToLower(strings.TrimSpace(code)); len(code) != 2 {
		return "", netip.Addr{}
	}
	if parsed, err := netip.ParseAddr(strings.TrimSpace(answer.IP)); err == nil {
		ip = parsed
	}
	return code, ip
}

func ParseExitTrace(body []byte) (region string, ip netip.Addr) {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "loc":
			if v := strings.ToLower(strings.TrimSpace(value)); len(v) == 2 {
				region = v
			}
		case "ip":
			if v, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
				ip = v
			}
		}
	}
	return region, ip
}

// IsRegionUnavailableLocation tells a page that blames the region from an ordinary
// relocation: only the former may record a block for the whole region. A region word next
// to a refusal word counts as one; either word alone is an ordinary page.
func IsRegionUnavailableLocation(location string) bool {
	if location == "" {
		return false
	}
	location = strings.ToLower(location)
	for _, pattern := range []string{
		"app-unavailable-in-region",
		"/welcome/unavailable",
		"unavailable-in-region",
		"region-unavailable",
		"not-available-in-your-region",
		"unsupported-region",
	} {
		if strings.Contains(location, pattern) {
			return true
		}
	}
	region := false
	for _, word := range []string{"region", "country", "location", "geo-block", "geoblock", "geo-restrict", "georestrict"} {
		if strings.Contains(location, word) {
			region = true
			break
		}
	}
	if !region {
		return false
	}
	for _, word := range []string{"unavailable", "not-available", "notavailable", "unsupported", "blocked", "restricted", "denied"} {
		if strings.Contains(location, word) {
			return true
		}
	}
	return false
}

// IsRegionUnavailableText recognizes a refusal that is only stated in the page body.
func IsRegionUnavailableText(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	text := strings.ReplaceAll(strings.ToLower(string(body)), "_", " ")
	for _, phrase := range []string{
		"not available in your region",
		"not available in your country",
		"not available in your area",
		"not available in your location",
		"not available in your territory",
		"unavailable in your region",
		"unavailable in your country",
		"not available in this region",
		"not available in this country",
		"not available in the region",
		"unsupported country",
		"unsupported region",
		"region is not supported",
		"country is not supported",
		"not supported in your country",
		"not supported in your region",
		"blocked in your region",
		"blocked in your country",
		"geo-blocked",
		"geoblocked",
		"geo-restricted",
		"georestricted",
		"地区不可用",
		"所在地区不可用",
		"不支持您所在的",
		"您所在的地区",
		"お住まいの地域",
		"お住まいの国",
		"地域ではご利用",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

// ExitKey derives a pseudonymous identity of an exit address: nodes behind the same
// machine share it, and the address itself is never kept.
func ExitKey(ip netip.Addr) string {
	sum := sha256.Sum256(ip.AsSlice())
	return hex.EncodeToString(sum[:6])
}
