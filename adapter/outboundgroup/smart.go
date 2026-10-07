package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/smart"
	"github.com/metacubex/mihomo/component/smart/lightgbm"
	"github.com/metacubex/mihomo/component/smart/tcpstats"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/samber/lo"
)

const (
	cleanupInterval          = 120 * time.Minute
	cacheParamAdjustInterval = 5 * time.Minute
	recoveryCheckInterval    = 10 * time.Minute
	hostStatusCheckInterval  = 30 * time.Minute
	checkInterval            = 10 * time.Minute
	prefetchInterval         = 15 * time.Minute
	claimInterval            = 2 * time.Minute
	flushQueueInterval       = 5 * time.Minute
	rankingInterval          = 5 * time.Minute

	maxRetries  = 5
	maxSelected = 10

	deterministicDialPrefix = 3
	parallelDials           = 5
	connectThreshold        = 5.0

	floodWindow    = 2 * time.Second
	floodThreshold = 50

	// How long a connection on a degraded node may wait for an answer to what
	// it sent before closeStalledConnections treats it as stuck.
	stalledReplyAfter = 10 * time.Second
	// How often the global sweep looks for connections stuck on a member that
	// new dials already avoid. One task for every group, so the cadence costs
	// one wake-up rather than one per group.
	stalledSweepInterval = 15 * time.Second

	// Blocking a (host, node) pair is a hard exclusion at dial time, not a
	// ranking penalty, and the store drops the pair on its own only after
	// HostFailureNodeTTL (24h). Recovery probing therefore has to get all the
	// way round the blocked set well inside that window: at 64 per tick a group
	// with 400 blocked pairs is fully swept in ~3h.
	hostRecoveryProbeBudget = 64
	// Must be at least one tick, otherwise a group used in short regular bursts
	// can land in the "wrong" half of every cycle and deterministically never
	// probe - the scheduler's jitter is computed once at start, so its phase is
	// fixed for the process lifetime.
	hostRecoveryActiveWindow = 2 * hostStatusCheckInterval
	hostRecoveryBackoffBase  = 2 * hostStatusCheckInterval
	// This is now the only thing spacing repeat probes of the same pair. The
	// store's own gate only withholds a pair for the first hostStatusRetryAfter
	// of its block: it was implemented by a failed probe resetting the deadline
	// to now+TTL, and a re-block no longer moves the deadline, precisely so a
	// host that fails every probe cannot stay blocked for good. Backing off
	// past a few hours only delays recovery, and this map is lost on restart --
	// after which the 64-per-tick budget is what bounds the catch-up.
	hostRecoveryBackoffMax = 4 * time.Hour

	siteKeyCacheLimit = 4096 // sites remembered as site keys, relearned after eviction
)

type SmartOption struct {
	PolicyPriority string  `group:"policy-priority,omitempty"`
	UseLightGBM    bool    `group:"uselightgbm,omitempty"`
	CollectData    bool    `group:"collectdata,omitempty"`
	SampleRate     float64 `group:"sample-rate,omitempty"`
	PreferASN      bool    `group:"prefer-asn,omitempty"`
	Tolerance      uint16  `group:"tolerance,omitempty"`
}

type Smart struct {
	*GroupBase
	store *smart.Store

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	close  sync.Once
	global *smartGlobalTaskRun

	configName     string
	selected       string
	testUrl        string
	expectedStatus string
	disableUDP     bool

	weightModel    *lightgbm.WeightModel
	policyPriority []priorityRule
	priorityCache  xsync.Map[string, float64]
	sampleRate     float64
	useLightGBM    bool
	collectData    bool
	preferASN      bool
	hostFailLimit  atomic.Int32
	tolerance      uint16

	freshNodesGroup singleflight.Group[nodeResult]

	ruleCountCache xsync.Map[string, int]
	asnDiversity   xsync.Map[string, *xsync.Map[string, bool]]
	asnRule        xsync.Map[string, string]
	siteKeyCache   xsync.Map[string, bool]

	suppressStats atomic.Bool
	suppressCount atomic.Int64
	suppressLast  atomic.Int64

	workMu      sync.Mutex
	workWG      sync.WaitGroup
	workClosing bool

	lastTrafficActivity atomic.Int64
	recoveryCursor      atomic.Uint64
	recoveryMu          sync.Mutex
	recoveryBackoff     map[string]hostRecoveryState

	probeThrottle smart.ProbeThrottle

	exitWatch *smart.ExitWatcher
}

type dialResult struct {
	proxyIndex  int
	conn        C.Conn
	connectTime int64
	error       error
}

type priorityRule struct {
	pattern string
	regex   *regexp2.Regexp
	factor  float64
	isRegex bool
}

type nodeResult struct {
	names   []string
	weights []float64
}

// targetState is the store side of the judgement of one finished connection, read once by
// the caller.
type targetState struct {
	failNodes map[string]smart.BlockCode
	blocked   bool
	suspected bool
}

// connQuality is the connection side of the judgement of one finished connection.
type connQuality struct {
	err         error
	address     string // display string of the connection, only used by the debug lines
	weight      float64
	oldWeight   float64
	duration    int64
	uploadMB    float64
	downloadMB  float64
	lossRate    float64
	emaLossRate float64
}

func NewSmart(option GroupCommonOption, smartOption SmartOption, emptyFallback C.Proxy, providers []provider.ProxyProvider) (*Smart, error) {
	if option.URL == "" {
		option.URL = C.DefaultTestURL
	}

	configFile := C.Path.Config()
	configName := strings.TrimSuffix(filepath.Base(configFile), filepath.Ext(configFile))

	s := &Smart{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:             option.Name,
			Type:             C.Smart,
			Hidden:           option.Hidden,
			Icon:             option.Icon,
			Filter:           option.Filter,
			ExcludeFilter:    option.ExcludeFilter,
			ExcludeType:      option.ExcludeType,
			TestTimeout:      option.TestTimeout,
			MaxFailedTimes:   option.MaxFailedTimes,
			EmptyFallback:    emptyFallback,
			PreferUDP:        option.PreferUDP,
			PenalizeUnstable: option.PenalizeUnstable,
			PreferIPv6:       option.PreferIPv6,
			Providers:        providers,
		}),
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		configName:     configName,
		disableUDP:     option.DisableUDP,
		policyPriority: make([]priorityRule, 0),
		sampleRate:     1,
		useLightGBM:    smartOption.UseLightGBM,
		collectData:    smartOption.CollectData,
		preferASN:      smartOption.PreferASN,
		tolerance:      smartOption.Tolerance,
	}

	s.hostFailLimit.Store(int32(s.maxFailedTimes))

	if smartOption.SampleRate > 0 && smartOption.SampleRate <= 1 {
		s.sampleRate = smartOption.SampleRate
	}

	if smartOption.PolicyPriority != "" {
		s.applyPolicyPriority(smartOption.PolicyPriority)
	}

	s.InitSmart()

	return s, nil
}

func (s *Smart) GetConfigFilename() string {
	return s.configName
}

func (s *Smart) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	s.markTrafficActivity()

	getBatch := func(proxies []C.Proxy, i int, pinned bool) ([]C.Proxy, time.Duration) {
		begin, end := smartDialBatchBounds(len(proxies), i, pinned)
		if begin == end {
			return nil, 0
		}

		batch := proxies[begin:end]
		var timeout time.Duration
		for _, p := range batch {
			if t := s.dialTimeout(metadata, p, C.DefaultTCPTimeout); t > timeout {
				timeout = t
			}
		}

		return batch, timeout
	}

	tryDial := func(proxies []C.Proxy, pinned bool) (C.Conn, error) {
		var finalErr error
		for i := 0; i < maxRetries; i++ {
			batch, timeout := getBatch(proxies, i, pinned)
			if len(batch) == 0 {
				break
			}

			ctxDial, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			p, c, connectTime, err := s.ParallelDialContext(ctxDial, batch, metadata, start, s.singleDialContext)
			cancel()

			if err != nil {
				if tunnel.ShouldStopRetry(err) {
					return nil, err
				}
				finalErr = err
			} else {
				s.adoptUnwrapWinner(metadata, p)
				s.onDialSuccess()
				return s.WrapConnWithMetric(c, p, metadata, connectTime), nil
			}
		}

		s.store.DeleteUnwrapResult(s.Name(), s.configName, metadata.SmartTarget)

		s.groupDialFailed(proxies, finalErr)

		return nil, finalErr
	}

	proxies, pinned := s.selectProxies(metadata, s.GetProxies(true))

	return tryDial(proxies, pinned)
}

func (s *Smart) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	s.markTrafficActivity()

	var finalErr error

	proxies, _ := s.selectProxies(metadata, s.GetProxies(true))

	limit := len(proxies)
	if limit > maxSelected {
		limit = maxSelected
	}

	singleProxyRetry := (len(proxies) == 1)

	for i := 0; i < limit; i++ {
		proxy := proxies[i]
		attempts := 1
		if singleProxyRetry {
			attempts = maxRetries
		}

		for a := 0; a < attempts; a++ {
			timeout := s.dialTimeout(metadata, proxy, C.DefaultUDPTimeout)
			ctxDial, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			pc, err = proxy.ListenPacketContext(ctxDial, metadata)
			cancel()
			connectTime := time.Since(start).Milliseconds()

			if err != nil {
				if tunnel.ShouldStopRetry(err) {
					return nil, err
				}
				finalErr = err
				s.submitConnectionStats(metadata.Clone(), proxy, connectTime, 0, 0, 0, 0, 0, 0, nil, err, false)
				continue
			}

			s.adoptUnwrapWinner(metadata, proxy)
			s.onDialSuccess()
			return s.WrapPacketConnWithMetric(pc, proxy, metadata, connectTime), nil
		}

		if singleProxyRetry {
			break
		}
	}

	s.store.DeleteUnwrapResult(s.Name(), s.configName, metadata.SmartTarget)

	s.groupDialFailed(proxies, finalErr)

	return nil, finalErr
}

// ref: component/dialer/dialer.go parallelDialContext
func (s *Smart) ParallelDialContext(ctx context.Context, proxies []C.Proxy, metadata *C.Metadata, start time.Time, singleDialFunc func(context.Context, C.Proxy, *C.Metadata, time.Time) (C.Conn, int64, error)) (C.Proxy, C.Conn, int64, error) {
	if len(proxies) == 1 {
		conn, connectTime, err := singleDialFunc(ctx, proxies[0], metadata, start)
		return proxies[0], conn, connectTime, err
	}

	n := len(proxies)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, n)

	for i := 0; i < n; i++ {
		go func(proxyIndex int) {
			conn, connectTime, err := singleDialFunc(childCtx, proxies[proxyIndex], metadata, start)
			results <- dialResult{
				proxyIndex:  proxyIndex,
				conn:        conn,
				connectTime: connectTime,
				error:       err,
			}
		}(i)
	}

	drainRemaining := func(pending int) {
		go func() {
			for i := 0; i < pending; i++ {
				if r := <-results; r.conn != nil && r.error == nil {
					_ = r.conn.Close()
				}
			}
		}()
	}

	errs := make([]error, 0, n)
	for received := 0; received < n; received++ {
		select {
		case res := <-results:
			if res.error == nil {
				cancel()
				drainRemaining(n - received - 1)
				return proxies[res.proxyIndex], res.conn, res.connectTime, nil
			}
			errs = append(errs, res.error)

		case <-ctx.Done():
			drainRemaining(n - received)
			return nil, nil, 0, ctx.Err()
		}
	}

	if len(errs) > 0 {
		return nil, nil, 0, errors.Join(errs...)
	}
	return nil, nil, 0, os.ErrDeadlineExceeded
}

func (s *Smart) singleDialContext(ctx context.Context, proxy C.Proxy, metadata *C.Metadata, start time.Time) (c C.Conn, connectTime int64, err error) {
	c, err = proxy.DialContext(ctx, metadata)
	connectTime = time.Since(start).Milliseconds()

	if err != nil {
		// err if ShouldStopRetry should not record as failed in node stats and stop retry
		if tunnel.ShouldStopRetry(err) {
			return nil, connectTime, err
		}
		if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
			// metadata may be re-written by a later retry's selectProxies.
			s.submitConnectionStats(metadata.Clone(), proxy, connectTime, 0, 0, 0, 0, 0, 0, nil, err, false)
		}
		return nil, connectTime, err
	}

	return c, connectTime, nil
}

// dialTimeout converts the remembered connect time into a deadline: a node that was slow
// before fails fast instead of holding the whole batch until the default timeout.
func (s *Smart) dialTimeout(metadata *C.Metadata, proxy C.Proxy, max time.Duration) time.Duration {
	historyConnectTime := s.getHistoryConnectStats(metadata, proxy)
	if historyConnectTime <= 0 {
		return max
	}
	timeout := time.Duration(float64(historyConnectTime)*connectThreshold) * time.Millisecond
	if timeout > max {
		return max
	}
	return timeout
}

func (s *Smart) groupDialFailed(proxies []C.Proxy, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	for _, p := range proxies {
		t := p.Type()
		if t == C.Direct || t == C.Compatible || t == C.Reject || t == C.Pass || t == C.RejectDrop {
			continue
		}
		s.onDialFailed(t, err, s.healthCheck)
		return
	}
}

// smartDialBatchBounds returns the dial batch of one iteration, a pinned target is
// dialed one node at a time so it cannot end up on a second exit.
func smartDialBatchBounds(total, iteration int, pinned bool) (begin, end int) {
	if total <= 0 {
		return 0, 0
	}
	if pinned {
		if iteration >= total {
			return 0, 0
		}
		return iteration, iteration + 1
	}
	if total == 1 {
		return 0, 1
	}
	if iteration < deterministicDialPrefix {
		if iteration >= total {
			return 0, 0
		}
		return iteration, iteration + 1
	}
	begin = deterministicDialPrefix + (iteration-deterministicDialPrefix)*parallelDials
	if begin >= total {
		return 0, 0
	}
	end = begin + parallelDials
	if end > total {
		end = total
	}
	return begin, end
}

func (s *Smart) adoptUnwrapWinner(metadata *C.Metadata, p C.Proxy) {
	target := metadata.SmartTarget
	existing, _ := s.store.GetUnwrapResult(s.Name(), s.configName, target)

	// A new winner steers the dials that come after it, and nothing else. This
	// used to also close every connection in the bucket that was not on the
	// winner, and the bucket is keyed by the matched rule while the node a dial
	// lands on depends on per-destination blocks. Two destinations in one rule
	// that each exclude the other's node therefore closed each other's working
	// connections on every dial, for as long as the client kept reconnecting --
	// a Telegram DC set split across two nodes looped every few seconds
	// (liuran001/mihomo#2). A winner change says nothing against the node the
	// existing connections are on; the degrade path is what handles a node
	// that has actually stopped carrying traffic.
	switch {
	case len(existing) == 0:
		s.store.StoreUnwrapResult(s.Name(), s.configName, target, []C.Proxy{p})
	case existing[0] == p.Name():
		// Unchanged: nothing to record.
	default:
		s.store.DeleteUnwrapResult(s.Name(), s.configName, target)
		s.store.StoreUnwrapResult(s.Name(), s.configName, target, []C.Proxy{p})
	}
}

func (s *Smart) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := s.GetProxies(touch)

	if metadata == nil {
		return proxies[0]
	}

	if s.selected != "" {
		for _, p := range proxies {
			if p.Name() == s.selected {
				return p
			}
		}
	}

	proxies, _ = s.selectProxies(metadata, proxies)

	return proxies[0]
}

func (s *Smart) IsL3Protocol(metadata *C.Metadata) bool {
	return s.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func (s *Smart) SupportUDP() bool {
	return !s.disableUDP
}

func (s *Smart) WrapConnWithMetric(c C.Conn, proxy C.Proxy, metadata *C.Metadata, connectTime int64) C.Conn {
	s.exitWatch.EnsureLoaded(proxy.Name())
	if info := s.exitWatch.Info(proxy.Name()); info.Region != "" || info.ASN != "" {
		metadata.ExitGeoIP = info.Region
		if s.preferASN {
			metadata.ExitIPASN = info.ASN
		}
	}
	c.AppendToChains(s)

	start := time.Now()

	var firstReadErr atomic.TypedValue[error]
	var firstReadLatency atomic.Int64
	var observedReadErr atomic.TypedValue[error]
	var observedWriteErr atomic.TypedValue[error]

	needHandshake := N.NeedHandshake(c)
	// a raw relay must keep its splice fast path: the copy engine peels wrappers
	// down to the socket, so the observer would disable it; skip those chains
	stop := N.UnwrapWriter(c)
	if _, isRawRelay := stop.(syscall.Conn); !isRawRelay {
		if u, ok := stop.(interface{ Upstream() any }); !ok || u.Upstream() != nil {
			c = callback.NewErrorCallBackConn(c, &observedReadErr, &observedWriteErr)
		}
	}

	if needHandshake {
		c = callback.NewFirstWriteCallBackConn(c, nil)
	}

	c = callback.NewFirstReadCallBackConn(c, func(err error) {
		firstReadLatency.Store(time.Since(start).Milliseconds())
		if err != nil {
			firstReadErr.Store(err)
		}
	})

	return s.registerClosureMetricsCallback(
		c, proxy, metadata, connectTime,
		&firstReadLatency, &firstReadErr,
		&observedReadErr, &observedWriteErr,
	)
}

func (s *Smart) WrapPacketConnWithMetric(pc C.PacketConn, proxy C.Proxy, metadata *C.Metadata, connectTime int64) C.PacketConn {
	s.exitWatch.EnsureLoaded(proxy.Name())
	if info := s.exitWatch.Info(proxy.Name()); info.Region != "" || info.ASN != "" {
		metadata.ExitGeoIP = info.Region
		if s.preferASN {
			metadata.ExitIPASN = info.ASN
		}
	}
	pc.AppendToChains(s)

	var udpLatency atomic.Int64
	var observedReadErr atomic.TypedValue[error]
	var observedWriteErr atomic.TypedValue[error]

	pc = callback.NewErrorCallBackPacketConn(pc, &observedReadErr, &observedWriteErr)
	pc = callback.NewFirstReadCallBackPacketConn(pc, func(latency int64) {
		udpLatency.Store(latency)
	})

	return s.registerPacketClosureMetricsCallback(pc, proxy, metadata, connectTime, &udpLatency, &observedReadErr, &observedWriteErr)
}

func (s *Smart) Set(name string) error {
	var p C.Proxy
	for _, proxy := range s.GetProxies(false) {
		if proxy.Name() == name {
			p = proxy
			break
		}
	}

	if p == nil {
		return errors.New("proxy not exist")
	}

	s.ForceSet(name)

	return nil
}

func (s *Smart) ForceSet(name string) {
	s.selected = name
}

func (s *Smart) Now() string {
	if s.selected != "" {
		for _, p := range s.GetProxies(false) {
			if p.Name() == s.selected {
				return p.Name()
			}
		}
		s.selected = ""
	}

	return "Smart - Select"
}

func (s *Smart) MarshalJSON() ([]byte, error) {
	proxies := s.GetProxies(false)
	all := make([]string, len(proxies))
	for i, proxy := range proxies {
		all[i] = proxy.Name()
	}

	var policyPriorityBuf strings.Builder
	for i, rule := range s.policyPriority {
		if i > 0 {
			policyPriorityBuf.WriteByte(';')
		}
		fmt.Fprintf(&policyPriorityBuf, "%s:%.2f", rule.pattern, rule.factor)
	}

	return json.Marshal(map[string]any{
		"type":            s.Type().String(),
		"now":             s.Now(),
		"all":             all,
		"testUrl":         s.testUrl,
		"expectedStatus":  s.expectedStatus,
		"fixed":           s.selected,
		"hidden":          s.Hidden(),
		"icon":            s.Icon(),
		"emptyFallback":   s.EmptyFallback().Name(),
		"policy-priority": policyPriorityBuf.String(),
		"useLightGBM":     s.useLightGBM,
		"collectData":     s.collectData,
		"sampleRate":      s.sampleRate,
		"preferASN":       s.preferASN,
		"tolerance":       s.tolerance,
	})
}

func (s *Smart) Providers() []provider.ProxyProvider {
	return s.providers
}

func (s *Smart) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

func (s *Smart) filterProxies(metadata *C.Metadata, wildcardTarget string, names []string, weights []float64, all []C.Proxy, minCount int, isUDP bool) []C.Proxy {
	blockedNodes := s.store.GetBlockedNodes(s.Name(), s.configName)
	wtFailNodes, _, _, wtBlocked := s.store.GetHostStatus(s.Name(), s.configName, wildcardTarget, int(s.hostFailLimit.Load()), metadata.SmartTarget)
	now := time.Now()

	var proxyByName map[string]C.Proxy
	if len(names) > 0 {
		proxyByName = s.proxyIndexFor(all)
	}

	checkNodeUsed := make(map[string]bool, len(names))

	selected := make([]C.Proxy, 0, minCount+1)

	for i, name := range names {
		proxy := proxyByName[name]
		if proxy == nil || blockedNodes[name] || !proxy.AliveForTestUrl(s.testUrl) || (isUDP && !proxy.SupportUDP()) {
			continue
		}
		checkNodeUsed[adapter.ProxyIdentity(proxy)] = true
		w := 0.0
		if weights != nil && i < len(weights) {
			w = weights[i]
		}
		if weights != nil && w < smart.AllowedWeight {
			continue
		}
		if excludedForHost(wtFailNodes, wtBlocked, name) {
			continue
		}
		if s.exitWatch.Defer(wildcardTarget, name, now, smart.ProbeTimeout) {
			continue
		}
		selected = append(selected, proxy)
	}
	// a pinned candidate list is used as is, it is not padded from the rest
	if weights == nil && len(selected) > 0 {
		return selected
	}

	if len(selected) >= len(all) {
		return selected
	}

	if len(selected) >= minCount {
		return selected[:minCount]
	}

	hasPriority := len(s.policyPriority) > 0

	type sortKey struct {
		delay     uint16
		suspected bool
		factor    float64
		index     int
	}
	type keyedProxy struct {
		proxy C.Proxy
		key   sortKey
	}

	ranked := make([]keyedProxy, len(all))
	for i, p := range all {
		key := sortKey{
			delay:     adapter.AddCapabilityPenalty(p.LastDelayForTestUrl(s.testUrl), p, s.preferUDP, s.preferIPv6),
			index:     i,
			suspected: s.exitWatch.Suspected(wildcardTarget, p.Name()),
		}
		if hasPriority {
			key.factor = s.getPriorityFactor(p.Name())
		}
		ranked[i] = keyedProxy{proxy: p, key: key}
	}

	// delays within the tolerance count as equal, so a jittering delay does not reorder the list
	less := func(a, b sortKey) bool {
		if a.suspected != b.suspected {
			return !a.suspected
		}
		if hasPriority && a.factor != b.factor {
			return a.factor > b.factor
		}
		if s.tolerance > 0 {
			var diff uint16
			if a.delay > b.delay {
				diff = a.delay - b.delay
			} else {
				diff = b.delay - a.delay
			}
			if diff <= s.tolerance {
				return a.index < b.index
			}
		}
		if a.delay != b.delay {
			return a.delay < b.delay
		}
		return a.index < b.index
	}

	filtered := make([]keyedProxy, 0, len(all))
	for _, kp := range ranked {
		name := kp.proxy.Name()
		if checkNodeUsed[adapter.ProxyIdentity(kp.proxy)] {
			continue
		}
		if excludedForHost(wtFailNodes, wtBlocked, name) {
			continue
		}
		if blockedNodes[name] {
			continue
		}
		if s.exitWatch.Defer(wildcardTarget, name, now, smart.ProbeTimeout) {
			continue
		}
		if !kp.proxy.AliveForTestUrl(s.testUrl) || (isUDP && !kp.proxy.SupportUDP()) {
			continue
		}
		filtered = append(filtered, kp)
	}

	sort.SliceStable(filtered, func(i, j int) bool { return less(filtered[i].key, filtered[j].key) })

	for _, kp := range filtered {
		selected = append(selected, kp.proxy)
		if len(selected) >= minCount {
			break
		}
	}

	rankedSorted := false
	sortFallback := func() {
		if !rankedSorted {
			sort.SliceStable(ranked, func(i, j int) bool { return less(ranked[i].key, ranked[j].key) })
			rankedSorted = true
		}
	}

	if len(selected) == 0 {
		sortFallback()
		for _, kp := range ranked {
			p := kp.proxy
			if !s.exitWatch.Defer(wildcardTarget, p.Name(), now, smart.ProbeTimeout) &&
				!excludedForHost(wtFailNodes, wtBlocked, p.Name()) &&
				p.AliveForTestUrl(s.testUrl) && (!isUDP || p.SupportUDP()) {
				selected = append(selected, p)
			}
			if len(selected) >= minCount {
				break
			}
		}

		if len(selected) == 0 {
			for _, kp := range ranked {
				p := kp.proxy
				if !s.exitWatch.Defer(wildcardTarget, p.Name(), now, smart.ProbeTimeout) && p.AliveForTestUrl(s.testUrl) {
					selected = append(selected, p)
				}
				if len(selected) >= minCount {
					break
				}
			}
		}

		if len(selected) == 0 {
			for _, kp := range ranked {
				p := kp.proxy
				if s.exitWatch.Defer(wildcardTarget, p.Name(), now, smart.ProbeTimeout) || wtFailNodes[p.Name()] == 1 {
					continue
				}
				selected = append(selected, p)
				if len(selected) >= minCount {
					break
				}
			}
		}
	}

	if len(selected) < minCount {
		sortFallback()
		for _, kp := range ranked {
			p := kp.proxy
			if !p.AliveForTestUrl(s.testUrl) || (isUDP && !p.SupportUDP()) {
				continue
			}
			if s.exitWatch.Defer(wildcardTarget, p.Name(), now, smart.ProbeTimeout) &&
				s.exitWatch.AllowFallback(wildcardTarget, p.Name(), now, smart.ProbeTimeout) {
				selected = append(selected, p)
				break
			}
		}
	}
	return selected
}

// selectProxies returns the nodes to dial and whether the target is already pinned to
// one node: a pinned target is dialed node by node, an unpinned one may race on its
// first dial, which is the only moment a key can show more than one exit.
func (s *Smart) selectProxies(metadata *C.Metadata, proxies []C.Proxy) ([]C.Proxy, bool) {
	asnNumber := s.getASNCode(metadata)
	dstIP := ""
	if metadata.Host == "" {
		dstIP = metadata.DstIP.String()
	}
	wildcardTarget := smart.GetEffectiveTarget(metadata.Host, dstIP)
	metadata.WildcardTarget = wildcardTarget
	if metadata.SmartTarget == "" {
		metadata.SmartTarget = wildcardTarget
	}
	needsASNKey := s.preferASN && s.needsASNKey(metadata.SmartTarget, asnNumber)
	if claimedRule, ok := s.claimedRule(asnNumber, needsASNKey); ok {
		metadata.SmartTarget = claimedRule
	} else {
		// a shared or unknown network cannot identify the site, so the site is kept as its key
		site := ""
		if needsASNKey && metadata.Host != "" {
			if asnNumber == "" || smart.SharedASNs[asnNumber] {
				s.recordSiteKey(metadata, wildcardTarget)
			} else if _, recorded := s.siteKeyCache.Load(wildcardTarget); recorded {
				site = wildcardTarget
			}
		}
		metadata.SmartTarget = smart.SmartTargetKey(s.preferASN, asnNumber, metadata.SmartTarget, wildcardTarget, site, needsASNKey)
	}

	if s.selected != "" {
		for _, p := range proxies {
			if p.Name() == s.selected {
				return []C.Proxy{p}, true
			}
		}
	}

	computeFreshNodes := func(isUDP bool) ([]string, []float64) {
		if proxiesName, weights := s.store.GetPrefetchResult(s.Name(), s.configName, metadata.SmartTarget, isUDP); len(proxiesName) > 0 {
			return proxiesName, weights
		}
		if proxiesName, weights, err := s.store.GetBestProxyForTarget(s.Name(), s.configName, metadata.SmartTarget, isUDP); err == nil && len(proxiesName) > 0 {
			return proxiesName, weights
		}
		return nil, nil
	}

	computeFreshSingleFlight := func(isUDP bool) ([]string, []float64) {
		sfKey := metadata.SmartTarget + "|t"
		if isUDP {
			sfKey = metadata.SmartTarget + "|u"
		}
		res, _, _ := s.freshNodesGroup.Do(sfKey, func() (nodeResult, error) {
			names, weights := computeFreshNodes(isUDP)
			return nodeResult{names: names, weights: weights}, nil
		})
		return res.names, res.weights
	}

	// asynchronously update expired cache (stale-while-revalidate)
	refreshUnwrapCache := func(isUDP bool) {
		names, _ := computeFreshSingleFlight(isUDP)
		if len(names) == 0 {
			return
		}
		_, proxyByName := s.GetProxiesByName(true)
		resultProxies := make([]C.Proxy, 0, len(names))
		for _, name := range names {
			if p, ok := proxyByName[name]; ok {
				resultProxies = append(resultProxies, p)
			}
		}
		if len(resultProxies) > 0 {
			s.store.StoreUnwrapResult(s.Name(), s.configName, metadata.SmartTarget, resultProxies)
		}
	}

	trySelector := func(isUDP bool) ([]string, []float64, bool) {
		if proxiesName, expired := s.store.GetUnwrapResult(s.Name(), s.configName, metadata.SmartTarget); len(proxiesName) > 0 {
			if expired && s.beginBackgroundWork() {
				go func() {
					defer s.finishBackgroundWork()
					refreshUnwrapCache(isUDP)
				}()
			}
			return proxiesName, nil, true
		}
		names, weights := computeFreshSingleFlight(isUDP)
		return names, weights, false
	}

	isUDP := metadata.NetWork == C.UDP
	resultNames, resultWeights, pinned := trySelector(isUDP)

	// a pin that cannot serve this network leaves it to the other one, so the candidates are
	// taken per network instead; the winner of this dial still replaces the pin
	if pinned && isUDP && len(resultNames) > 0 && lo.ContainsBy(proxies, func(p C.Proxy) bool {
		return p.Name() == resultNames[0] && !p.SupportUDP()
	}) {
		resultNames, resultWeights = computeFreshSingleFlight(isUDP)
		pinned = false
	}

	return s.filterProxies(metadata, wildcardTarget, resultNames, resultWeights, proxies, maxSelected, isUDP), pinned
}

func (s *Smart) getPriorityFactor(proxyName string) float64 {
	if len(s.policyPriority) == 0 {
		return 1.0
	}
	if v, ok := s.priorityCache.Load(proxyName); ok {
		return v
	}
	factor := 1.0
	for _, rule := range s.policyPriority {
		if rule.isRegex && rule.regex != nil {
			if matched, _ := rule.regex.MatchString(proxyName); matched {
				factor = rule.factor
				break
			}
		} else if strings.Contains(proxyName, rule.pattern) {
			factor = rule.factor
			break
		}
	}
	s.priorityCache.Store(proxyName, factor)
	return factor
}

func (s *Smart) applyHostFailLimit() {
	if proxyCount := len(s.GetProxies(true)); proxyCount > 0 {
		hostFailLimit := proxyCount / 3
		if hostFailLimit < 2 {
			hostFailLimit = 2
		}
		s.hostFailLimit.Store(int32(hostFailLimit))
	}
}

func (s *Smart) applyPolicyPriority(policyPriority string) {
	lastUnescapedColon := func(str string) int {
		for i := len(str) - 1; i >= 0; i-- {
			if str[i] == ':' {
				bs := 0
				j := i - 1
				for j >= 0 && str[j] == '\\' {
					bs++
					j--
				}
				if bs%2 == 0 {
					return i
				}
			}
		}
		return -1
	}

	unescapePattern := func(p string) string {
		var b strings.Builder
		for i := 0; i < len(p); i++ {
			if p[i] == '\\' && i+1 < len(p) {
				b.WriteByte(p[i+1])
				i++
			} else {
				b.WriteByte(p[i])
			}
		}
		return b.String()
	}

	pairs := strings.Split(policyPriority, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		idx := lastUnescapedColon(pair)
		if idx <= 0 || idx == len(pair)-1 {
			log.Warnln("[Smart] Invalid policy-priority rule: [%s], must be in 'pattern:factor' format and factor is required", pair)
			continue
		}

		patternRaw := strings.TrimSpace(pair[:idx])
		factorStr := strings.TrimSpace(pair[idx+1:])

		factor, err := strconv.ParseFloat(factorStr, 64)
		if err != nil {
			log.Warnln("[Smart] Invalid priority factor format for pattern [%s:%v]", patternRaw, err)
			continue
		}
		if factor <= 0 {
			log.Warnln("[Smart] Invalid priority factor [%.2f] for pattern [%s], factor must be positive", factor, patternRaw)
			continue
		}

		rule := priorityRule{
			pattern: unescapePattern(patternRaw),
			factor:  factor,
		}

		if re, err := regexp2.Compile(rule.pattern, regexp2.None); err == nil {
			rule.regex = re
			rule.isRegex = true
		}

		s.policyPriority = append(s.policyPriority, rule)
	}
}

func (s *Smart) getASNCode(metadata *C.Metadata) string {
	if metadata.DstIPASN == "unknown" {
		return ""
	}

	if metadata.DstIPASN == "" {
		if !s.preferASN {
			return ""
		}
		var ip netip.Addr
		if metadata.Host != "" && !metadata.Resolved() {
			ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
			defer cancel()
			var err error
			ip, err = resolver.ResolveIP(ctx, metadata.Host)
			if err != nil {
				log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				metadata.DstIPASN = "unknown"
				return ""
			} else {
				log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
				if !ip.IsValid() {
					metadata.DstIPASN = "unknown"
					return ""
				}
			}
		} else {
			ip = metadata.DstIP
		}

		asn, aso := mmdb.ASNInstance().LookupASN(ip.AsSlice())
		if asn == "" {
			metadata.DstIPASN = "unknown"
		} else {
			metadata.DstIPASN = asn + " " + aso
		}
		return asn
	}

	if idx := strings.IndexByte(metadata.DstIPASN, ' '); idx >= 0 {
		return metadata.DstIPASN[:idx]
	}
	return metadata.DstIPASN
}

// recordSiteKey marks a site as keyed by itself, so its later dials key by the
// site rather than by the network they happened to resolve to.
//
// Upstream also closed the site's open connections that still keyed by a
// network, to converge the service on one exit at once. That is the sweep this
// fork removed from adoptUnwrapWinner (liuran001/mihomo#2): a key change steers
// the dials after it and says nothing against the node a working connection is
// on, so the existing connections are left to finish on their own.
func (s *Smart) recordSiteKey(metadata *C.Metadata, site string) {
	if site == "" {
		return
	}
	if _, recorded := s.siteKeyCache.Load(site); recorded {
		return
	}
	if s.siteKeyCache.Size() >= siteKeyCacheLimit {
		return
	}
	s.siteKeyCache.LoadOrStore(site, true)
}

func (s *Smart) needsASNKey(target, asn string) bool {
	ruleCount := 0
	if payload, ok := smart.RuleSetPayload(target); ok {
		if cached, loaded := s.ruleCountCache.Load(payload); loaded {
			ruleCount = cached
		} else if rp, ok := tunnel.RuleProviders()[payload]; ok && rp != nil {
			if ruleCount = rp.Count(); ruleCount > 0 {
				s.ruleCountCache.Store(payload, ruleCount)
			}
		}
	}
	// Only a provider-defined rule name is judged by its diversity; every other
	// kind is decided by its name alone. Counting for all of them kept a set per
	// domain in asnDiversity for the life of the group, which nothing reads.
	diversity := 0
	if smart.ClassifyTargetName(target) == smart.TargetKindRuleName {
		diversity = s.asnDiversityOf(target, asn)
	}
	return smart.NeedsASNKey(target, ruleCount, diversity)
}

// asnDiversityOf counts the unrelated networks a target was seen on, which is how a
// rule set with a provider defined name is told apart from a collection.
func (s *Smart) asnDiversityOf(target, asn string) int {
	if asn == "" || smart.SharedASNs[asn] {
		return 0
	}
	set, _ := s.asnDiversity.LoadOrStoreFn(target, func() *xsync.Map[string, bool] {
		return xsync.NewMap[string, bool]()
	})
	if _, loaded := set.Load(asn); !loaded && set.Size() < smart.BroadASNDiversity {
		set.Store(asn, true)
	}
	return set.Size()
}

// claimedRule returns the service rule that owns this network, so that a host of the
// same service which matched a broad rule keeps the exit of the service.
func (s *Smart) claimedRule(asn string, needsASNKey bool) (string, bool) {
	if !s.preferASN || !needsASNKey || asn == "" {
		return "", false
	}
	rule, ok := s.asnRule.Load(asn)
	if !ok || rule == "" || rule == smart.ASNClaimAmbiguous {
		return "", false
	}
	return rule, true
}

// claimASNEvidence rebuilds the network to service rule claims from the evidence
// collected per target (see TargetASNEvidence), it runs on its own timer.
func (s *Smart) claimASNEvidence() {
	// claimedRule consults the claims only under prefer-asn, and building them
	// decodes every stats record of the group.
	if !s.preferASN {
		return
	}
	// An empty result still has to go through: it is what clears the claims
	// whose evidence has aged out.
	claims := smart.ClaimedASNRules(s.store.TargetASNEvidence(s.Name(), s.configName))

	s.asnRule.Range(func(asn, _ string) bool {
		if _, ok := claims[asn]; !ok {
			s.asnRule.Delete(asn)
		}
		return true
	})

	ambiguous := 0
	for asn, rule := range claims {
		if rule == smart.ASNClaimAmbiguous {
			ambiguous++
		}
		s.asnRule.Store(asn, rule)
	}

	log.Debugln("[Smart] Group: [%s] - network claims updated: [%d] networks, [%d] ambiguous", s.Name(), len(claims), ambiguous)
}

func (s *Smart) getHistoryConnectStats(metadata *C.Metadata, proxy C.Proxy) int64 {
	target := metadata.SmartTarget
	proxyName := proxy.Name()
	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, s.configName, s.Name(), target, proxyName)
	atomicRecord := s.store.GetOrCreateAtomicRecord(cacheKey, s.Name(), s.configName, target, proxyName)
	return atomicRecord.ConnectTime()
}

func (s *Smart) updateConnectionDuration(record *smart.AtomicStatsRecord, connectionDuration int64) {
	durationMinutes := float64(connectionDuration) / 60000.0
	if currentDuration := record.Duration(); currentDuration > 0 {
		record.SetDuration((currentDuration + durationMinutes) / 2.0)
	} else {
		record.SetDuration(durationMinutes)
	}
}

func (s *Smart) saveStatsRecord(target string, proxy C.Proxy, record *smart.StatsRecord) {
	if data, err := json.Marshal(record); err == nil {
		s.store.AppendToGlobalQueue(smart.StoreOperation{
			Type:   smart.OpSaveStats,
			Group:  s.Name(),
			Config: s.configName,
			Target: target,
			Node:   proxy.Name(),
			Data:   data,
		})
	}
}

func formatTrafficUnit(val float64, isSpeed bool) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	base := 1024.0
	i := 0
	for val >= base && i < len(units)-1 {
		val /= base
		i++
	}
	if isSpeed {
		return fmt.Sprintf("%.2f %s/s", val, units[i])
	}
	return fmt.Sprintf("%.2f %s", val, units[i])
}

func formatTimeUnit(val float64) string {
	units := []string{"ms", "s", "min", "h"}
	thresholds := []float64{1000.0, 60.0, 60.0}
	i := 0
	for i < len(units)-1 && val >= thresholds[i] {
		val /= thresholds[i]
		i++
	}
	return fmt.Sprintf("%.2f %s", val, units[i])
}

func (s *Smart) logConnectionStats(err error, record *smart.StatsRecord, metadata *C.Metadata, baseWeight, priorityFactor float64,
	addressDisplay, proxyName string, connectTime int64, latency int64, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate float64,
	connectionDuration int64, ModelPredicted bool, lossRate, cumulLossRate float64,
) {
	weightSource := "Traditional"
	if ModelPredicted {
		weightSource = "LightGBM"
	}

	statusStr := "closed"
	if err != nil {
		statusStr = "failed"
	}

	log.Debugln("[Smart] Connection status: [%s], Updated weights: (Model: [%s], TCP: [%.4f], UDP: [%.4f], Base: [%.4f], Priority: [%.2f]) "+
		"For (Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s]) "+
		"- Current: (Connect: [%s], Latency: [%s], LossRate: [%.2f%%], Up: [%s], Down: [%s], Max Up Speed: [%s], Max Down Speed: [%s], Duration: [%s]) "+
		"- History: (Success: [%d], Failure: [%d], EMA Connect: [%s], EMA Latency: [%s], Cumul LossRate: [%.2f%%], Total Up: [%s], Total Down: [%s], Max Up Speed: [%s], Max Down Speed: [%s], Avg Duration: [%s])",
		statusStr, weightSource, record.Weights[smart.WeightTypeTCP], record.Weights[smart.WeightTypeUDP], baseWeight, priorityFactor,
		s.Name(), proxyName, metadata.NetWork.String(), addressDisplay,
		formatTimeUnit(float64(connectTime)),
		formatTimeUnit(float64(latency)),
		lossRate*100,
		formatTrafficUnit(uploadTotal*1024*1024, false),
		formatTrafficUnit(downloadTotal*1024*1024, false),
		formatTrafficUnit(maxUploadRate*1024, true),
		formatTrafficUnit(maxDownloadRate*1024, true),
		formatTimeUnit(float64(connectionDuration)),
		record.Success, record.Failure,
		formatTimeUnit(float64(record.ConnectTime)),
		formatTimeUnit(float64(record.Latency)),
		cumulLossRate*100,
		formatTrafficUnit(record.UploadTotal*1024*1024, false),
		formatTrafficUnit(record.DownloadTotal*1024*1024, false),
		formatTrafficUnit(record.MaxUploadRate*1024, true),
		formatTrafficUnit(record.MaxDownloadRate*1024, true),
		formatTimeUnit(record.ConnectionDuration*60000),
	)
}

func (s *Smart) collectConnectionData(input *smart.ModelInput, metadata *C.Metadata,
	baseWeight float64, proxyName string, ModelPredicted bool,
) {
	if s.sampleRate < 1.0 && rand.Float64() > s.sampleRate {
		return
	}

	input.GroupName = s.Name()
	input.NodeName = proxyName
	weightSource := "Traditional"

	if ModelPredicted {
		weightSource = "LightGBM"
	}

	lightgbm.GetCollector().AddSample(input, metadata, baseWeight, weightSource)
}

func updateEMA[T int64 | float64](oldValue, newValue T) T {
	if oldValue > 0 {
		return (oldValue*2 + newValue*4) / 6
	}
	return newValue
}

func (s *Smart) recordConnectionStats(metadata *C.Metadata, proxy C.Proxy,
	connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate,
	connectionDuration int64, tcpStats *tcpstats.Stats, err error,
) {
	if proxy.Type() == C.Compatible || proxy.Type() == C.Reject || proxy.Type() == C.Pass || proxy.Type() == C.RejectDrop {
		return
	}

	// failure flood suppression: short-circuit heavy work when recent failures reach the threshold to avoid a disconnect storm (including Direct nodes)
	now := time.Now().Unix()
	proceed, tripped := s.admitConnectionStats(metadata, err, now)
	if tripped {
		s.store.ClearFloodRecordsByGroup(s.Name(), s.configName)
	}
	if !proceed {
		return
	}
	s.exitWatch.MaybeProbe(s.ctx, proxy)

	var lossRate float64
	var cumulLossRate float64
	var calculatedWeight float64
	var ModelPredicted bool

	proxyName := proxy.Name()
	isUDP := metadata.NetWork == C.UDP

	target := metadata.SmartTarget
	wildcardTarget := metadata.WildcardTarget
	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, s.configName, s.Name(), target, proxyName)
	asnNumber := s.getASNCode(metadata)
	priorityFactor := s.getPriorityFactor(proxyName)

	debugEnabled := log.DebugEnabled()
	var addressDisplay string
	if debugEnabled {
		asnDisplay := "unknown"
		if asnNumber != "" {
			asnDisplay = asnNumber
		}
		exitDisplay := "unknown"
		if metadata.ExitGeoIP != "" {
			exitDisplay = metadata.ExitGeoIP
			if metadata.ExitIPASN != "" {
				exitDisplay += " AS" + metadata.ExitIPASN
			}
		}
		if metadata.Host != "" {
			addressDisplay = fmt.Sprintf("Host: [%s] - Target: [%s] - WildcardTarget: [%s] - ASN: [%s] - ExitGeoIP: [%s]", metadata.Host, target, wildcardTarget, asnDisplay, exitDisplay)
		} else {
			addressDisplay = fmt.Sprintf("IP: [%s] - Target: [%s] - ASN: [%s] - ExitGeoIP: [%s]", metadata.DstIP.String(), target, asnDisplay, exitDisplay)
		}

	}

	weightType := smart.WeightTypeTCP
	if isUDP {
		weightType = smart.WeightTypeUDP
	}

	lock := smart.GetTargetNodeLock(target, s.Name(), proxyName)
	lock.Lock()
	locked := true
	defer func() {
		if locked {
			lock.Unlock()
		}
	}()

	atomicRecord := s.store.GetOrCreateAtomicRecord(cacheKey, s.Name(), s.configName, target, proxyName)

	switch {
	case err != nil:
		atomicRecord.AddFailure(1)
	default:
		atomicRecord.AddSuccess(1)
		if asnNumber != "" && !smart.SharedASNs[asnNumber] {
			if kind := smart.ClassifyTargetName(target); kind == smart.TargetKindRuleName || kind == smart.TargetKindService {
				atomicRecord.AddASNEvidence(asnNumber)
				s.store.RecordASNEvidence(s.Name(), s.configName, target, asnNumber)
			}
		}
	}

	if connectTime > 0 {
		atomicRecord.SetConnectTime(updateEMA(atomicRecord.ConnectTime(), connectTime))
	}

	if latency > 0 {
		atomicRecord.SetLatency(updateEMA(atomicRecord.Latency(), latency))
	}

	if connectionDuration > 0 {
		s.updateConnectionDuration(atomicRecord, connectionDuration)
	}

	if tcpStats != nil {
		atomicRecord.AddCumulSent(int64(tcpStats.TotalSent()))
		atomicRecord.AddCumulRetrans(int64(tcpStats.TotalRetrans()))
		lossRate = tcpStats.LossRate()
	}

	if sent := atomicRecord.CumulSent(); sent > 0 {
		cumulLossRate = float64(atomicRecord.CumulRetrans()) / float64(sent)
		if cumulLossRate > 1 {
			cumulLossRate = 1
		}
	}

	emaLossRate := updateEMA(atomicRecord.LossRate(), lossRate)
	atomicRecord.SetLossRate(emaLossRate)

	oldWeight := atomicRecord.GetWeight(weightType)
	uploadTotalMB := float64(uploadTotal) / (1024.0 * 1024.0)
	downloadTotalMB := float64(downloadTotal) / (1024.0 * 1024.0)
	maxUploadRateKB := float64(maxUploadRate) / 1024.0
	maxDownloadRateKB := float64(maxDownloadRate) / 1024.0

	atomicRecord.AddUploadTotal(uploadTotalMB)
	atomicRecord.AddDownloadTotal(downloadTotalMB)

	if maxUploadRateKB > atomicRecord.MaxUploadRate() {
		atomicRecord.SetMaxUploadRate(maxUploadRateKB)
	}

	if maxDownloadRateKB > atomicRecord.MaxDownloadRate() {
		atomicRecord.SetMaxDownloadRate(maxDownloadRateKB)
	}

	input := lightgbm.CreateModelInputFromStatsRecord(
		atomicRecord, metadata,
		uploadTotalMB, downloadTotalMB, maxUploadRateKB, maxDownloadRateKB, float64(connectionDuration)/60000.0, wildcardTarget,
		lossRate, cumulLossRate,
	)
	input.ConnectionFailed = err != nil

	if s.useLightGBM && s.weightModel != nil {
		calculatedWeight, ModelPredicted = s.weightModel.PredictWeight(input, priorityFactor)
	} else {
		calculatedWeight, ModelPredicted = smart.CalculateWeight(input, priorityFactor)
	}

	// a pinned group and a force-closed connection never reach the host checks, so their
	// snapshot is not read at all
	var state targetState
	if s.selected == "" && metadata.SmartBlock != "blocked" && metadata.SmartBlock != "degraded" {
		state = s.readTargetState(metadata, proxyName)
	}
	adjWeight, isDegraded, checked, blockCode := s.checkNodeQuality(state, metadata, proxy, connQuality{
		err:         err,
		address:     addressDisplay,
		weight:      calculatedWeight,
		oldWeight:   oldWeight,
		duration:    connectionDuration,
		uploadMB:    uploadTotalMB,
		downloadMB:  downloadTotalMB,
		lossRate:    lossRate,
		emaLossRate: emaLossRate,
	})

	// block node for the specific domain/IP (wildcardTarget + SmartTarget two-level records)
	failedBlock := s.markNodeFailure(metadata, proxyName, isDegraded, checked, blockCode, 0)

	newWeight := updateEMA(oldWeight, adjWeight)
	atomicRecord.SetLastUsed(time.Now().Unix())
	atomicRecord.SetWeight(weightType, newWeight)
	statsSnapshot := atomicRecord.CreateStatsSnapshot(cacheKey)

	s.saveStatsRecord(target, proxy, statsSnapshot)

	lock.Unlock()
	locked = false

	if isDegraded || failedBlock {
		s.closeStalledConnections(metadata, proxyName, target)
		s.store.DeleteUnwrapResult(s.Name(), s.configName, target)
	}

	if s.collectData {
		collectedWeight := adjWeight / priorityFactor
		if isDegraded || failedBlock {
			// forcefully adjust for abnormal connections so the model can recognize them during training
			if collectedWeight >= smart.AllowedWeight {
				collectedWeight = collectedWeight * 0.1
			} else {
				if collectedWeight == 0 {
					collectedWeight = smart.AllowedWeight * rand.Float64()
				}
			}
		}
		s.collectConnectionData(input, metadata, collectedWeight, proxyName, ModelPredicted)
	}

	// the event must always be published: an API log subscriber filters by its own level,
	// so a console level above debug does not mean the line is unwanted
	if debugEnabled {
		s.logConnectionStats(err, statsSnapshot, metadata, calculatedWeight/priorityFactor, priorityFactor, addressDisplay, proxyName,
			connectTime, latency, uploadTotalMB, downloadTotalMB, maxUploadRateKB, maxDownloadRateKB, connectionDuration, ModelPredicted, lossRate, cumulLossRate)
	}
}

func (s *Smart) registerClosureMetricsCallback(c C.Conn, proxy C.Proxy, metadata *C.Metadata, connectTime int64, firstReadLatency *atomic.Int64, firstReadErr *atomic.TypedValue[error], observedReadErr *atomic.TypedValue[error], observedWriteErr *atomic.TypedValue[error]) C.Conn {
	return callback.NewCloseCallbackConn(c, func() {
		tracker := statistic.DefaultManager.Get(metadata.UUID)
		if tracker != nil {
			info := tracker.Info()
			uploadTotal := info.UploadTotal.Load()
			downloadTotal := info.DownloadTotal.Load()
			connectionDuration := time.Since(info.Start).Milliseconds()
			maxUploadRate := info.MaxUploadRate.Load()
			maxDownloadRate := info.MaxDownloadRate.Load()

			latency := firstReadLatency.Load()
			readErr := firstReadErr.Load()
			// the observer covers mid-transfer errors the one-shot callbacks miss
			if err := observedReadErr.Load(); err != nil {
				readErr = err
			}
			writeErr := observedWriteErr.Load()

			var tcpStats *tcpstats.Stats
			if trackerConn, ok := tracker.(net.Conn); ok {
				tcpStats = tcpstats.GetTCPStats(trackerConn)
			}

			var closeErr error
			if readErr != nil {
				if readErr == io.EOF {
					if writeErr != nil && writeErr != io.EOF {
						closeErr = writeErr
					}
				} else {
					closeErr = readErr
				}
			} else if writeErr != nil && writeErr != io.EOF {
				closeErr = writeErr
			}

			// a connection the group closed on purpose is not a transfer failure
			if metadata.SmartBlock == "degraded" {
				closeErr = nil
			}

			s.submitConnectionStats(metadata, proxy, connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate, connectionDuration, tcpStats, closeErr, true)
			return
		}
	})
}

func (s *Smart) registerPacketClosureMetricsCallback(pc C.PacketConn, proxy C.Proxy, metadata *C.Metadata, connectTime int64, udpLatency *atomic.Int64, observedReadErr *atomic.TypedValue[error], observedWriteErr *atomic.TypedValue[error]) C.PacketConn {
	return callback.NewCloseCallbackPacketConn(pc, func() {
		tracker := statistic.DefaultManager.Get(metadata.UUID)
		if tracker != nil {
			info := tracker.Info()
			uploadTotal := info.UploadTotal.Load()
			downloadTotal := info.DownloadTotal.Load()
			connectionDuration := time.Since(info.Start).Milliseconds()
			maxUploadRate := info.MaxUploadRate.Load()
			maxDownloadRate := info.MaxDownloadRate.Load()

			closeErr := observedReadErr.Load()
			if closeErr == nil {
				closeErr = observedWriteErr.Load()
			}
			// a connection the group closed on purpose is not a transfer failure
			if metadata.SmartBlock == "degraded" {
				closeErr = nil
			}

			s.submitConnectionStats(metadata, proxy, connectTime, udpLatency.Load(),
				uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate, connectionDuration, nil, closeErr, false)
			return
		}
	})
}

func (s *Smart) calcMADMetrics(delays []float64) (currentAnomaly bool, unstable bool, threshold float64, grade int) {
	calcGrade := func(t float64) int {
		if t <= 500 {
			return 1
		} else if t <= 1000 {
			return 2
		} else if t <= 2000 {
			return 3
		}
		return 4
	}

	n := len(delays)
	if n == 0 {
		return false, false, 0, 0
	}

	var median float64
	var mad float64
	var robustCV float64

	const scale = 1.4826
	const defaultK = 2.5
	const smallK = 3.5
	const cvThreshold = 0.6
	const minSamples = 3
	const SentinelThreshold = 0.5
	const sentinel = float64(0xffff)

	recentCount := minSamples
	if n < recentCount {
		recentCount = n
	}
	recentStart := n - recentCount
	recentSentinels := 0

	filtered := make([]float64, 0, n)
	for i, v := range delays {
		if v >= sentinel {
			if i >= recentStart {
				recentSentinels++
			}
			continue
		}
		filtered = append(filtered, v)
	}

	m := len(filtered)
	if m == 0 {
		return true, true, 0, 0
	}

	if float64(recentSentinels)/float64(recentCount) > SentinelThreshold {
		unstable = true
	}

	if m < minSamples {
		last := delays[n-1]
		currentAnomaly = last >= sentinel
		return currentAnomaly, unstable, 0, 0
	}

	sort.Float64s(filtered)

	if m%2 == 1 {
		median = filtered[m/2]
	} else {
		median = (filtered[m/2-1] + filtered[m/2]) / 2
	}

	devs := make([]float64, 0, m)
	for _, v := range filtered {
		devs = append(devs, math.Abs(v-median))
	}
	sort.Float64s(devs)

	if m%2 == 1 {
		mad = devs[m/2]
	} else {
		mad = (devs[m/2-1] + devs[m/2]) / 2
	}

	if mad == 0 {
		mean := 0.0
		for _, v := range filtered {
			mean += v
		}
		mean /= float64(m)
		varSum := 0.0
		for _, v := range filtered {
			d := v - mean
			varSum += d * d
		}
		std := math.Sqrt(varSum / float64(m))
		threshold = mean + 2*std
		last := delays[n-1]
		if last >= sentinel {
			currentAnomaly = true
		} else {
			currentAnomaly = last > threshold && delays[n-2] > threshold
		}

		return currentAnomaly, unstable, threshold, calcGrade(threshold)
	}

	k := defaultK
	if m < maxSelected {
		k = smallK
	}

	threshold = median + k*scale*mad

	if median > 0 {
		robustCV = scale * mad / median
	} else {
		robustCV = 0
	}

	last := delays[n-1]
	if last >= sentinel {
		currentAnomaly = true
	} else {
		currentAnomaly = last > threshold && delays[n-2] > threshold
	}

	if !unstable {
		unstable = robustCV >= cvThreshold
	}

	return currentAnomaly, unstable, threshold, calcGrade(threshold)
}

func (s *Smart) checkNodesStable() {
	if s.suppressStats.Load() {
		return
	}

	proxies := s.GetProxies(true)
	nodesToBlock := make(map[string]*smart.NodeState, len(proxies))
	now := time.Now().Unix()
	blockedUntil := time.Now().Add(checkInterval + 2*time.Minute).Unix()

	for _, p := range proxies {
		if !p.AliveForTestUrl(s.testUrl) {
			continue
		}

		histories := p.DelayHistoryForTestUrl(s.testUrl)
		if len(histories) == 0 {
			continue
		}

		delays := make([]float64, 0, len(histories))
		for _, h := range histories {
			if h.Delay == 0 {
				h.Delay = 0xffff
			}
			delays = append(delays, float64(h.Delay))
		}

		currentAnomaly, unstable, _, newGrade := s.calcMADMetrics(delays)

		proxyName := p.Name()
		var blockCopy *smart.NodeState
		s.store.UpdateNodeState(s.Name(), s.configName, proxyName, func(state *smart.NodeState) {
			prevGrade := state.ThresholdGrade
			state.LastChecked = now
			if newGrade > 0 {
				state.ThresholdGrade = newGrade
			}

			gradeWorsened := (prevGrade > 0 && newGrade > prevGrade) || (prevGrade <= 2 && newGrade > 2)
			if currentAnomaly || unstable || gradeWorsened {
				state.BlockedUntil = blockedUntil
				copied := *state
				blockCopy = &copied
			}
		})
		if blockCopy != nil {
			nodesToBlock[proxyName] = blockCopy
		}
	}

	if len(nodesToBlock) > 0 {
		s.store.UpdateBlockedNodesCache(s.Name(), s.configName, nodesToBlock)
	}
}

func (s *Smart) checkBlockedNodes() {
	stateData, err := s.store.GetNodeStates(s.Name(), s.configName)
	if err != nil {
		return
	}

	nodesToUpdate := make(map[string]*smart.NodeState)

	for nodeName, data := range stateData {
		var state smart.NodeState
		err := json.Unmarshal(data, &state)
		if err != nil {
			continue
		}

		if state.BlockedUntil > 0 && state.BlockedUntil <= time.Now().Unix() {
			s.store.UpdateNodeState(s.Name(), s.configName, nodeName, func(state *smart.NodeState) {
				state.BlockedUntil = 0
			})
			nodesToUpdate[nodeName] = &smart.NodeState{}
			log.Debugln("[Smart] Node [%s] block period expired, unblocking", nodeName)
		}
	}

	if len(nodesToUpdate) > 0 {
		s.store.UpdateBlockedNodesCache(s.Name(), s.configName, nodesToUpdate)
	}
}

// readTargetState reads one snapshot for the judgement of a finished connection: the host
// failure view of the target and the exit suspicion of the node.
func (s *Smart) readTargetState(metadata *C.Metadata, proxyName string) targetState {
	failNodes, _, _, blocked := s.store.GetHostStatus(s.Name(), s.configName, metadata.WildcardTarget, int(s.hostFailLimit.Load()), metadata.SmartTarget)
	return targetState{
		failNodes: failNodes,
		blocked:   blocked,
		suspected: s.exitWatch.Suspected(metadata.WildcardTarget, proxyName),
	}
}

// checkNodeQuality turns one finished connection into its weight adjustment and the host
// record to write; the store and the exit trackers are read by the caller, so this only
// decides.
func (s *Smart) checkNodeQuality(state targetState, metadata *C.Metadata, proxy C.Proxy, q connQuality) (float64, bool, bool, smart.BlockCode) {
	if s.selected != "" {
		return q.weight, false, false, 0
	}

	proxyName := proxy.Name()

	// user manual block
	if metadata.SmartBlock == "blocked" {
		log.Debugln("[Smart] Connection Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s] detected manual block...",
			s.Name(), proxyName, metadata.NetWork.String(), q.address)
		return q.weight, true, true, smart.BlockManual
	}

	// force-closed connection, skip quality check to avoid erroneous downgrade
	if metadata.SmartBlock == "degraded" {
		return q.oldWeight, false, false, 0
	}

	if state.blocked {
		return q.weight, false, q.err == nil && state.failNodes[proxyName] != smart.BlockNone, smart.BlockNone
	}

	if q.weight > 0 && q.weight < smart.AllowedWeight {
		return q.weight, true, true, smart.BlockLowWeight
	}

	if q.err != nil {
		return q.weight, false, true, smart.BlockDialFailure
	}

	if state.failNodes[proxyName] != 0 {
		return q.weight, false, true, smart.BlockNone
	}

	// zero-traffic connection
	if q.duration > 100 && q.downloadMB == 0 && q.uploadMB > 0 && metadata.DstPort == 443 && metadata.NetWork != C.UDP {
		log.Debugln("[Smart] Connection Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s] detected no response to a sent request...",
			s.Name(), proxyName, metadata.NetWork.String(), q.address)
		return q.weight, true, true, smart.BlockNoResponse
	}

	// a suspected exit re-checks the suspicion: it carries traffic only when the rest failed;
	// a connection that downloaded almost nothing may have been answered by an error page
	if state.suspected || smart.ResponseProbeEligible(metadata, q.downloadMB, metadata.NetWork == C.UDP) {
		s.probeAfterClose(metadata, proxy)
		return q.weight, false, false, 0
	}

	// a strike needs current loss too, the decaying ema alone must not confirm it
	if q.lossRate >= 0.1 || (q.lossRate >= 0.05 && q.emaLossRate >= 0.05) {
		log.Debugln("[Smart] Connection Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s] detected high packet loss [current: %.2f%%, history EMA: %.2f%%]...",
			s.Name(), proxyName, metadata.NetWork.String(), q.address, q.lossRate*100, q.emaLossRate*100)
		return q.weight, true, true, smart.BlockPacketLoss
	}

	return q.weight, false, false, 0
}

// markNodeFailure records a node failure for the host and for the target, otherwise every
// host of a rule set picks its own fallback node. ttl, when set, bounds how long the
// block lasts; see UpdateHostStatus.
func (s *Smart) markNodeFailure(metadata *C.Metadata, proxyName string, isDegraded bool, checked bool, blockCode smart.BlockCode, ttl time.Duration) bool {
	wildcardTarget := metadata.WildcardTarget
	target := metadata.SmartTarget

	failedBlock := s.store.UpdateHostStatus(s.Name(), s.configName, wildcardTarget, metadata, proxyName, s.maxFailedTimes, int(s.hostFailLimit.Load()), isDegraded, checked, blockCode, ttl)

	if hostStatusAppliesToEveryScope(isDegraded, failedBlock, checked, blockCode) {
		if target != "" && target != wildcardTarget {
			if s.store.UpdateHostStatus(s.Name(), s.configName, target, metadata, proxyName, s.maxFailedTimes, int(s.hostFailLimit.Load()), isDegraded, checked, blockCode, ttl) {
				failedBlock = true
			}
		}
	}

	return failedBlock
}

// applyNodeAnswer writes the host record of one node's answer and feeds the exit evidence: a
// reachable answer clears the host failure and any exit suspicion of that node, a refusal
// records the host and pools per region. It reports whether a suspicion was cleared.
func (s *Smart) applyNodeAnswer(metadata *C.Metadata, target, node string, verdict smart.Verdict) (cleared bool) {
	switch verdict.Action {
	case smart.VerdictReachable:
		s.markNodeFailure(metadata, node, false, true, 0, 0)
		s.noteExitSuccess(target, node, verdict)
		cleared = s.exitWatch.Suspected(target, node)
		s.exitWatch.Clear(target, node)
	case smart.VerdictRecord:
		s.markNodeFailure(metadata, node, true, true, smart.BlockAbnormalStatus, verdict.TTL)
		s.noteExitEvidence(target, node, verdict.Reason)
	}
	return cleared
}

func (s *Smart) checkHostStatus() {
	now := time.Now()
	if !s.trafficRecentlyActive(now) {
		return
	}

	proxies := s.GetProxies(false)
	proxyMap := uniqueProxiesByName(proxies)

	toCheck, err := s.store.CheckHostStatus(s.Name(), s.configName, int(s.hostFailLimit.Load()))
	if err != nil {
		return
	}

	toProbe := s.selectHostRecoveryItems(toCheck, proxyMap, now)
	if len(toProbe) == 0 {
		return
	}

	jobs := make(chan hostRecoveryItem)
	var wg sync.WaitGroup
	for i := 0; i < parallelDials; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				select {
				case <-s.ctx.Done():
					return
				default:
				}
				p, ok := proxyMap[it.nodeName]
				if !ok {
					continue
				}
				metadata := &C.Metadata{Host: it.host, WildcardTarget: it.wildcardTarget}
				verdict := s.probeVerdict(p, it.host)
				s.recordHostRecoveryResult(it.key, verdict.Action == smart.VerdictReachable, time.Now())
				s.applyNodeAnswer(metadata, it.wildcardTarget, it.nodeName, verdict)
				switch verdict.Action {
				case smart.VerdictReachable:
					log.Debugln("[Smart] Recheck Group: [%s] - Node: [%s] - Host: [%s] recovered [%s]", s.Name(), it.nodeName, it.host, verdict.Reason)
				case smart.VerdictRecord:
					log.Debugln("[Smart] Recheck Group: [%s] - Node: [%s] - Host: [%s] avoided for [%s]: [%s]", s.Name(), it.nodeName, it.host, verdict.TTL, verdict.Reason)
				default:
					log.Debugln("[Smart] Recheck Group: [%s] - Node: [%s] - Host: [%s] left unchanged [%s]", s.Name(), it.nodeName, it.host, verdict.Reason)
				}
			}
		}()
	}

sendLoop:
	for _, it := range toProbe {
		select {
		case jobs <- it:
		case <-s.ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
}

// The verdict lands after its connection is gone, outside the (target, node) stats lock, so the pin,
// the membership and the stop-loss have to be re-checked before anything is written.
func (s *Smart) probeAfterClose(metadata *C.Metadata, proxy C.Proxy) {
	now := time.Now()
	if !s.probeThrottle.AllowNode(metadata.WildcardTarget, proxy.Name(), now) {
		return
	}
	// a blind host is not probed until its window passes, then one probe decides its state
	if s.probeThrottle.Blind(metadata.Host, now) {
		return
	}
	if !smart.AllowGlobalProbe(now) {
		return
	}
	done, ok := smart.TryStartProbe()
	if !ok {
		return
	}

	if !s.beginBackgroundWork() {
		done()
		return
	}

	clone := metadata.Clone()
	nodeName := proxy.Name()
	go func() {
		defer s.finishBackgroundWork()
		defer done()

		verdict := s.probeVerdict(proxy, clone.Host)
		if verdict.Action == smart.VerdictIgnore {
			log.Debugln("[Smart] Probe Group: [%s] - Node: [%s] - Host: [%s] ignored answer [%s]", s.Name(), nodeName, clone.Host, verdict.Reason)
			return
		}
		if !s.probeThrottle.AllowHostRecord(clone.Host, verdict, time.Now()) {
			log.Debugln("[Smart] Probe Group: [%s] - Node: [%s] - Host: [%s] kept, no node reaches the host [%s]", s.Name(), nodeName, clone.Host, verdict.Reason)
			return
		}
		if s.selected != "" || !lo.ContainsBy(s.GetProxies(false), func(p C.Proxy) bool { return p.Name() == nodeName }) {
			return
		}
		if _, _, _, wtBlocked := s.store.GetHostStatus(s.Name(), s.configName, clone.WildcardTarget, int(s.hostFailLimit.Load()), clone.SmartTarget); wtBlocked {
			return
		}

		if verdict.Action == smart.VerdictReachable {
			if cleared := s.applyNodeAnswer(clone, clone.WildcardTarget, nodeName, verdict); cleared {
				log.Debugln("[Smart] Exit suspicion [%s] target [%s] cleared by node [%s]", s.Name(), clone.WildcardTarget, nodeName)
			}
			log.Debugln("[Smart] Probe Group: [%s] - Node: [%s] - Host: [%s] recovered [%s]", s.Name(), nodeName, clone.Host, verdict.Reason)
			return
		}

		s.probeThrottle.NoteFailure(clone.WildcardTarget, nodeName, time.Now())
		s.applyNodeAnswer(clone, clone.WildcardTarget, nodeName, verdict)
		s.closeStalledConnections(clone, nodeName, clone.SmartTarget)
		s.store.DeleteUnwrapResult(s.Name(), s.configName, clone.SmartTarget)
		log.Debugln("[Smart] Probe Group: [%s] - Node: [%s] - Host: [%s] avoided for [%s]: [%s]", s.Name(), nodeName, clone.Host, verdict.TTL, verdict.Reason)
	}()
}

func (s *Smart) noteExitEvidence(target, node, reason string) {
	if smart.RegionEvidence(reason) {
		s.exitWatch.Note(target, node)
	}
}

func (s *Smart) noteExitSuccess(target, node string, verdict smart.Verdict) {
	if verdict.ControlSuccess {
		s.exitWatch.NoteSuccess(target, node)
	}
}

func (s *Smart) probeVerdict(proxy C.Proxy, host string) smart.Verdict {
	prober, ok := proxy.(smart.StatusProber)
	if !ok {
		return smart.Verdict{Action: smart.VerdictIgnore, Reason: "no probe support"}
	}

	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, smart.ProbeTimeout)
	defer cancel()

	result, err := prober.StatusProbe(ctx, smart.ProbeURL(host))
	if err != nil {
		return smart.ClassifyProbeError(err)
	}
	return smart.ClassifyResponse(result.StatusCode, result.Header, result.Body, time.Now())
}

func (s *Smart) InitSmart() {
	s.store = cachefile.GetSmartStore()

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.lastTrafficActivity.Store(time.Now().UnixNano())
	s.recoveryBackoff = make(map[string]hostRecoveryState)

	s.exitWatch = smart.NewExitWatcher(smart.ExitWatcherOptions{
		Name:    s.Name(),
		Config:  s.configName,
		Store:   s.store,
		WantASN: func() bool { return s.preferASN },
		BeginProbe: func() (func(), bool) {
			if !s.beginBackgroundWork() {
				return nil, false
			}
			return s.finishBackgroundWork, true
		},
	})

	if s.preferASN {
		initASNDatabase()
	}

	s.global = globalSmartTasks.acquire(s)
	s.startGroupTasks()
	if s.useLightGBM {
		s.weightModel = lightgbm.GetModel()
	}
}

func (s *Smart) runPrefetch() {
	proxies := s.GetProxies(true)
	proxyMap := make(map[string]bool, len(proxies))
	for _, proxy := range proxies {
		proxyMap[proxy.Name()] = true
	}
	s.store.RunPrefetch(s.Name(), s.configName, proxyMap)
}

func (s *Smart) updateNodeRanking() {
	proxies := s.GetProxies(true)
	rankingWrapper, _ := s.store.GetNodeWeightRankingCache(s.Name(), s.configName)

	if len(rankingWrapper.Result) > 0 {
		now := time.Now().Unix()
		lastUpdated := rankingWrapper.LastUpdated
		cacheAge := time.Duration(now-lastUpdated) * time.Second

		if cacheAge < 30*time.Minute {
			rankedNodes := make(map[string]bool, len(rankingWrapper.Result))
			for _, r := range rankingWrapper.Result {
				rankedNodes[r.Name] = true
			}
			hasUnrankedProxy := false
			for _, p := range proxies {
				if !rankedNodes[p.Name()] {
					hasUnrankedProxy = true
					break
				}
			}

			if !hasUnrankedProxy {
				if cacheAge <= 10*time.Minute {
					return
				}
				proxyMap := make(map[string]C.Proxy, len(proxies))
				for _, p := range proxies {
					proxyMap[p.Name()] = p
				}
				hasDeadRankedNode := false
				for _, r := range rankingWrapper.Result {
					if r.Rank != smart.RankRarelyUsed {
						if p, exists := proxyMap[r.Name]; exists {
							if !p.AliveForTestUrl(s.testUrl) {
								hasDeadRankedNode = true
								break
							}
						}
					}
				}
				if !hasDeadRankedNode {
					return
				}
			}
		}
	}

	log.Debugln("[Smart] Starting node ranking update for policy group [%s]", s.Name())

	rankingWrapper, err := s.store.GetNodeWeightRanking(s.Name(), s.configName, s.testUrl, proxies)
	if err != nil {
		log.Warnln("[Smart] Failed to update node ranking: %v", err)
		return
	}
	if len(rankingWrapper.Result) == 0 {
		log.Debugln("[Smart] Policy group [%s] doesn't have enough data to generate node ranking", s.Name())
		return
	}
	categoryCounts := make(map[string]int)
	for _, rank := range rankingWrapper.Result {
		categoryCounts[rank.Rank]++
	}

	log.Debugln("[Smart] Policy group [%s] node ranking update completed: %d nodes total (%s: %d, %s: %d, %s: %d)",
		s.Name(), len(rankingWrapper.Result),
		smart.RankMostUsed, categoryCounts[smart.RankMostUsed],
		smart.RankOccasional, categoryCounts[smart.RankOccasional],
		smart.RankRarelyUsed, categoryCounts[smart.RankRarelyUsed])
}

func (s *Smart) cleanupOrphanedGroups() {
	allProxies := tunnel.Proxies()
	existingSmartGroups := make(map[string]bool)

	for name, proxy := range allProxies {
		if proxy.Type() == C.Smart {
			existingSmartGroups[name] = true
		}
	}

	cachedGroups, err := s.store.GetAllGroupsForConfig(s.configName)
	if err != nil {
		return
	}

	var orphanedGroups []string
	for _, groupName := range cachedGroups {
		if !existingSmartGroups[groupName] {
			orphanedGroups = append(orphanedGroups, groupName)
		}
	}

	if len(orphanedGroups) > 0 {
		for _, group := range orphanedGroups {
			log.Debugln("[Smart] Cleaning up cache data for non-existent policy group [%s]", group)
			err := s.store.FlushByGroup(group, s.configName)
			if err != nil {
				log.Warnln("[Smart] Failed to clean up policy group [%s] cache: %v", group, err)
			}
		}
	}
}

func (s *Smart) cleanupOrphanedNodeCache() {
	proxies := s.GetProxies(true)
	proxyMap := make(map[string]bool, len(proxies))
	for _, proxy := range proxies {
		proxyMap[proxy.Name()] = true
	}

	cachedNodes, err := s.store.GetAllNodesForGroup(s.Name(), s.configName)
	if err != nil {
		return
	}

	var orphanedNodes []string
	for _, nodeName := range cachedNodes {
		if !proxyMap[nodeName] {
			orphanedNodes = append(orphanedNodes, nodeName)
		}
	}

	if len(orphanedNodes) > 0 {
		for _, node := range orphanedNodes {
			log.Debugln("[Smart] Cleaning up cache data for non-existent node [%s]", node)
		}

		err := s.store.RemoveNodesData(s.Name(), s.configName, int(s.hostFailLimit.Load()), orphanedNodes)
		if err != nil {
			log.Warnln("[Smart] Failed to clean up non-existent node caches: %v", err)
		}
	}
}

func (s *Smart) Close() error {
	s.close.Do(func() {
		s.disableBackgroundWork()
		if s.cancel != nil {
			s.cancel()
		}
		s.wg.Wait()
		s.waitBackgroundWork()
		globalSmartTasks.release(s, s.global)
		s.global = nil
	})
	return nil
}

// A failed attempt downloads ASN.mmdb with a 90s timeout, and InitSmart runs
// inline on the config-parse path, so retries have to be spaced out: without
// this every smart group in the config would pay that timeout again on every
// reload.
const asnInitRetryAfter = 5 * time.Minute

var asnInitAccess sync.Mutex

var asnInitDone bool

var asnInitLastTried time.Time

// initASNDatabase loads the ASN database once, but only latches on success. The
// usual failure is that the download could not run yet - no connectivity at
// boot is routine on mobile - and a later config reload has to be able to retry
// it. Latching on failure left prefer-asn silently degraded, with getASNCode
// returning "" for the rest of the process lifetime.
func initASNDatabase() {
	asnInitAccess.Lock()
	defer asnInitAccess.Unlock()
	if asnInitDone {
		return
	}
	if now := time.Now(); asnInitLastTried.IsZero() || now.Sub(asnInitLastTried) >= asnInitRetryAfter {
		asnInitLastTried = now
	} else {
		return
	}
	if err := geodata.InitASN(); err != nil {
		log.Warnln("[Smart] Failed to load ASN database: %v", err)
		return
	}
	asnInitDone = true
}

type hostRecoveryState struct {
	failures uint8
	next     time.Time
}

type hostRecoveryItem struct {
	wildcardTarget string
	nodeName       string
	host           string
	key            string
}

// uniqueProxiesByName returns only names that identify one current proxy.
// Smart's persistent store predates provider-aware identities and stores names
// for compatibility, so an ambiguous cached name must be ignored rather than
// silently mapped to whichever provider happened to be iterated last.
func uniqueProxiesByName(proxies []C.Proxy) map[string]C.Proxy {
	byName := make(map[string]C.Proxy, len(proxies))
	ambiguous := make(map[string]struct{})
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		name := proxy.Name()
		if _, duplicate := ambiguous[name]; duplicate {
			continue
		}
		if _, exists := byName[name]; exists {
			delete(byName, name)
			ambiguous[name] = struct{}{}
			continue
		}
		byName[name] = proxy
	}
	return byName
}

// proxyIndexFor returns the cached name index when all is the group's own
// current proxy list, which is what every caller on the connection path passes.
// A caller holding some other slice gets a freshly derived index.
func (s *Smart) proxyIndexFor(all []C.Proxy) map[string]C.Proxy {
	s.getProxiesMutex.Lock()
	cached := len(all) == len(s.providerProxies) &&
		(len(all) == 0 || &all[0] == &s.providerProxies[0])
	if cached && s.proxiesByName == nil {
		s.proxiesByName = uniqueProxiesByName(all)
	}
	byName := s.proxiesByName
	s.getProxiesMutex.Unlock()
	if !cached {
		return uniqueProxiesByName(all)
	}
	return byName
}

// admitConnectionStats is failure-flood suppression: once recent failures reach
// the threshold, the heavy per-connection work is skipped so a burst of dead
// connections cannot turn into a disconnect storm of its own. It reports
// whether to go on, and whether this call is the one that armed the suppressor
// (the caller owns the store write that follows).
//
// A connection the group closed itself is evidence of nothing and must not
// clear the suppressor. It reports no read or write error -- closeErr is
// derived from those alone -- so it used to arrive indistinguishable from a
// healthy close and reset the counter to zero. Every victim of a sweep did
// that, which meant the one mechanism written to stop a disconnect storm was
// held open by the storm it was meant to stop.
func (s *Smart) admitConnectionStats(metadata *C.Metadata, err error, now int64) (proceed bool, tripped bool) {
	// Neither direction: a connection this group closed says nothing about the
	// network, so it must not clear the suppressor and must not count toward
	// arming it either. A victim usually reports no error, but one whose first
	// read had already failed before the sweep reached it arrives here with
	// both an error and the marker -- and arming is not the safe direction it
	// looks like, because tripping runs ClearFloodRecordsByGroup, which
	// discards the group's queued stat and host-status writes.
	if metadata.SmartBlock == "degraded" {
		return true, false
	}
	if err == nil {
		s.suppressStats.Store(false)
		s.suppressCount.Store(0)
		return true, false
	}
	if now-s.suppressLast.Load() > int64(floodWindow.Seconds()) {
		s.suppressCount.Store(0)
	}
	s.suppressLast.Store(now)
	if s.suppressCount.Add(1) >= floodThreshold {
		tripped = s.suppressStats.CompareAndSwap(false, true)
	}
	return !s.suppressStats.Load(), tripped
}

func (s *Smart) submitConnectionStats(metadata *C.Metadata, proxy C.Proxy,
	connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate,
	connectionDuration int64, tcpStats *tcpstats.Stats, err error, markCloseFailure bool,
) bool {
	if !s.beginBackgroundWork() {
		return false
	}

	go func() {
		defer s.finishBackgroundWork()
		// The degraded marker means this group closed the connection itself, so
		// nothing about the close is the node's doing. checkNodeQuality honours
		// it; this path did not, and a connection whose first read had already
		// failed before the sweep reached it was blamed with code 3 anyway.
		if markCloseFailure && err != nil && metadata.SmartBlock != "degraded" {
			s.markNodeFailure(metadata, proxy.Name(), true, true, smart.BlockDialFailure, 0)
		}
		s.recordConnectionStats(metadata, proxy, connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate, connectionDuration, tcpStats, err)
	}()
	return true
}

func (s *Smart) beginBackgroundWork() bool {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.workClosing {
		return false
	}
	s.workWG.Add(1)
	return true
}

func (s *Smart) finishBackgroundWork() {
	s.workWG.Done()
}

func (s *Smart) disableBackgroundWork() {
	s.workMu.Lock()
	s.workClosing = true
	s.workMu.Unlock()
}

func (s *Smart) waitBackgroundWork() {
	s.workWG.Wait()
}

// hostStatusAppliesToEveryScope reports whether a host-status update changes a
// block, and so has to reach the SmartTarget records as well as the wildcard
// ones. GetHostStatus unions the two scopes, so a block written to both and
// lifted from one still excludes the node at dial time -- which is what used to
// happen, because only the blocking verdicts propagated.
func hostStatusAppliesToEveryScope(isDegraded, failedBlock, checked bool, blockCode smart.BlockCode) bool {
	if isDegraded || failedBlock {
		return true
	}
	// A clear. UpdateHostStatus drops the node from every code set but the
	// manual one when it is told the connection succeeded, and does nothing at
	// all when the verdict was never checked.
	return checked && blockCode == smart.BlockNone
}

// closeStalledConnections answers a degrade of proxyName on target by closing
// the connections it left stuck: those in the bucket on that node that sent
// something and have heard nothing back for stalledReplyAfter. Through a dead
// relay they would otherwise hang until the client or a keep-alive gave up, and
// closing them is what lets the client redial onto another node now.
//
// Anything else is left alone. This used to close every connection in the
// bucket on every node, so one degraded connection to one destination killed
// all the rule's working traffic and the reconnect storm fed the next degrade.
// A connection that is on another node, idle, or still getting answers is not
// stuck, whatever happened to its neighbour.
func (s *Smart) closeStalledConnections(metadata *C.Metadata, proxyName, target string) {
	if proxyName == "" {
		return
	}
	now := time.Now()
	statistic.DefaultManager.RangeSmartTarget(target, func(id string) bool {
		if id == metadata.UUID {
			return true
		}
		tracker := statistic.DefaultManager.Get(id)
		if tracker == nil {
			return true
		}
		// Cheapest rejections first: the ASN comparison below can memoise an
		// ASN lookup into the tracker's metadata, which is wasted on a tracker
		// that is not a candidate for closing in the first place.
		chains := tracker.Chains()
		if !lo.Contains(chains, s.Name()) || !lo.Contains(chains, proxyName) {
			return true
		}
		if !tracker.Info().AwaitingReply(now, stalledReplyAfter) {
			return true
		}
		closeStalled(tracker)
		return true
	})
}

// closeStalled closes a connection this group judged stuck, marked as the
// group's own doing. checkNodeQuality reads the marker to skip a connection the
// group killed itself: a connection it closed says nothing about the node that
// carried it, and without the marker its close was read as the node's own
// failure and answered with a block, which fed the next degrade.
//
// The write reaches the reader that matters without synchronisation:
// closeCallbackConn.Close runs its callback synchronously in this goroutine, so
// the stats goroutine it spawns is created after this write. It does race with
// GET /connections marshalling the same field for display, which predates this
// and costs at most a garbled string in one dashboard row -- torn reads here
// can only produce a value matching none of the three constants, which every
// comparison treats as "not ours". Closing it properly means making Metadata
// non-copyable, and it is copied by value in three places including TUIC's UoT
// path.
func closeStalled(tracker statistic.Tracker) {
	tracker.Info().Metadata.SmartBlock = "degraded"
	_ = tracker.Close()
}

// excludedForHost reports whether host-status verdicts keep name off new dials
// to that host. Past the safety valve -- hostBlocked, too many nodes failing
// the host at once -- only a manual block still excludes.
func excludedForHost(failNodes map[string]smart.BlockCode, hostBlocked bool, name string) bool {
	code := failNodes[name]
	return code != smart.BlockNone && (!hostBlocked || code == smart.BlockManual)
}

// groupMemberIn returns the member of group that carries a connection, which is
// the hop just inside the group's own entry: a chain runs from the leaf outward.
func groupMemberIn(chains C.Chain, group string) (string, bool) {
	for hop := 1; hop < len(chains); hop++ {
		if chains[hop] == group {
			return chains[hop-1], true
		}
	}
	return "", false
}

// avoidsMember reports whether new dials through s currently stay off member
// for a connection with metadata -- blocked, failing its health check, or
// blocked for that connection's own target, the verdicts filterProxies applies.
// proxyByName and blockedNodes are the group's, read once per sweep.
func (s *Smart) avoidsMember(member string, metadata *C.Metadata, proxyByName map[string]C.Proxy, blockedNodes map[string]bool) bool {
	proxy := proxyByName[member]
	if proxy == nil {
		// Not a member any more, so not this group's call.
		return false
	}
	if blockedNodes[member] || !proxy.AliveForTestUrl(s.testUrl) {
		return true
	}
	if metadata == nil || metadata.WildcardTarget == "" {
		return false
	}
	failNodes, _, _, hostBlocked := s.store.GetHostStatus(s.Name(), s.configName, metadata.WildcardTarget, int(s.hostFailLimit.Load()), metadata.SmartTarget)
	return excludedForHost(failNodes, hostBlocked, member)
}

func hostRecoveryKey(wildcardTarget, nodeName, host string) string {
	return wildcardTarget + "\x00" + nodeName + "\x00" + host
}

func (s *Smart) markTrafficActivity() {
	s.lastTrafficActivity.Store(time.Now().UnixNano())
}

func (s *Smart) trafficRecentlyActive(now time.Time) bool {
	last := s.lastTrafficActivity.Load()
	return last != 0 && now.Sub(time.Unix(0, last)) <= hostRecoveryActiveWindow
}

func hostRecoveryDelay(failures uint8) time.Duration {
	if failures == 0 {
		return 0
	}
	delay := hostRecoveryBackoffBase
	for i := uint8(1); i < failures && delay < hostRecoveryBackoffMax; i++ {
		delay *= 2
		if delay >= hostRecoveryBackoffMax {
			return hostRecoveryBackoffMax
		}
	}
	return delay
}

func (s *Smart) selectHostRecoveryItems(toCheck map[string]map[string]string, available map[string]C.Proxy, now time.Time) []hostRecoveryItem {
	if !s.trafficRecentlyActive(now) {
		return nil
	}

	all := make([]hostRecoveryItem, 0)
	activeKeys := make(map[string]struct{})
	for wildcardTarget, nodeMap := range toCheck {
		for nodeName, host := range nodeMap {
			if available != nil {
				if _, exists := available[nodeName]; !exists {
					continue
				}
			}
			key := hostRecoveryKey(wildcardTarget, nodeName, host)
			activeKeys[key] = struct{}{}
			all = append(all, hostRecoveryItem{wildcardTarget, nodeName, host, key})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].key < all[j].key })

	s.recoveryMu.Lock()
	eligible := all[:0]
	for _, item := range all {
		state, exists := s.recoveryBackoff[item.key]
		if !exists || !state.next.After(now) {
			eligible = append(eligible, item)
		}
	}
	for key := range s.recoveryBackoff {
		if _, exists := activeKeys[key]; !exists {
			delete(s.recoveryBackoff, key)
		}
	}
	s.recoveryMu.Unlock()

	if len(eligible) <= hostRecoveryProbeBudget {
		return eligible
	}

	start := int(s.recoveryCursor.Add(hostRecoveryProbeBudget)-hostRecoveryProbeBudget) % len(eligible)
	result := make([]hostRecoveryItem, 0, hostRecoveryProbeBudget)
	for i := 0; i < hostRecoveryProbeBudget; i++ {
		result = append(result, eligible[(start+i)%len(eligible)])
	}
	return result
}

func (s *Smart) recordHostRecoveryResult(key string, success bool, now time.Time) {
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	if s.recoveryBackoff == nil {
		s.recoveryBackoff = make(map[string]hostRecoveryState)
	}
	if success {
		delete(s.recoveryBackoff, key)
		return
	}
	state := s.recoveryBackoff[key]
	if state.failures < ^uint8(0) {
		state.failures++
	}
	state.next = now.Add(hostRecoveryDelay(state.failures))
	s.recoveryBackoff[key] = state
}
