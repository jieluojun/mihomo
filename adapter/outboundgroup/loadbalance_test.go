package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/smart"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

var capabilityTestSequence atomic.Uint64

type strategyTestProxy struct {
	C.Proxy
	name     string
	alive    bool
	addr     string
	provider string
}

func (p strategyTestProxy) Name() string                { return p.name }
func (p strategyTestProxy) AliveForTestUrl(string) bool { return p.alive }
func (p strategyTestProxy) Addr() string                { return p.addr }
func (p strategyTestProxy) Type() C.AdapterType         { return C.Http }
func (p strategyTestProxy) ProxyInfo() C.ProxyInfo      { return C.ProxyInfo{ProviderName: p.provider} }

// StatusTest 必须存在：strategyTestProxy 内嵌的是 nil 的 C.Proxy，一旦某个策略
// 触发能力探测，探测 goroutine 就会在这个 nil 接口上空指针解引用，直接带走整个
// 测试进程（而不是让某个测试失败）。
func (p strategyTestProxy) StatusTest(context.Context, string) (uint16, bool, error) {
	return 0, false, errors.New("capability probe unavailable in tests")
}

func strategyProxies(names ...string) []C.Proxy {
	proxies := make([]C.Proxy, len(names))
	for i, name := range names {
		proxies[i] = strategyTestProxy{name: name, alive: true}
	}
	return proxies
}

func TestConsistentHashingStableAcrossCandidateReorder(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyConsistentHashing("test", getKey, false, false)
	first := strategy(strategyProxies("a", "b", "c"), metadata, false)
	second := strategy(strategyProxies("c", "a", "b"), metadata, false)
	if first.Name() != second.Name() {
		t.Fatalf("candidate reorder migrated consistent hash from %q to %q", first.Name(), second.Name())
	}
}

func TestStickySessionsStableAcrossCandidateReorder(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyStickySessions("test", getKeyWithSrcAndDst, false, false)
	first := strategy(strategyProxies("a", "b", "c"), metadata, false)
	second := strategy(strategyProxies("c", "a", "b"), metadata, false)
	if first.Name() != second.Name() {
		t.Fatalf("candidate reorder migrated sticky session from %q to %q", first.Name(), second.Name())
	}
}

func TestStickySessionsDistinguishesDuplicateNames(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyStickySessions("test", getKeyWithSrcAndDst, false, false)
	first := strategy([]C.Proxy{
		strategyTestProxy{name: "same", addr: "one", provider: "p1", alive: true},
		strategyTestProxy{name: "same", addr: "two", provider: "p2", alive: true},
	}, metadata, false)
	second := strategy([]C.Proxy{
		strategyTestProxy{name: "same", addr: "two", provider: "p2", alive: true},
		strategyTestProxy{name: "same", addr: "one", provider: "p1", alive: true},
	}, metadata, false)
	if first.Addr() != second.Addr() {
		t.Fatalf("duplicate proxy names migrated sticky session from %q to %q", first.Addr(), second.Addr())
	}
}

func TestUniqueProxiesByNameOmitsProviderCollisions(t *testing.T) {
	first := strategyTestProxy{name: "same", addr: "one", provider: "p1", alive: true}
	second := strategyTestProxy{name: "same", addr: "two", provider: "p2", alive: true}
	unique := strategyTestProxy{name: "unique", addr: "three", provider: "p3", alive: true}

	byName := uniqueProxiesByName([]C.Proxy{first, second, unique})
	if _, ok := byName["same"]; ok {
		t.Fatal("ambiguous provider name was retained in cache lookup")
	}
	if got := byName["unique"]; got != unique {
		t.Fatalf("unique proxy lookup = %v, want %v", got, unique)
	}
}

func TestStickySessionsSeparatesDelimiterCollisions(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyStickySessions("test", getKeyWithSrcAndDst, false, false)
	a := strategyTestProxy{name: "same", provider: "provider|segment", addr: "endpoint", alive: true}
	b := strategyTestProxy{name: "same", provider: "provider", addr: "segment|endpoint", alive: true}

	first := strategy([]C.Proxy{a, b}, metadata, false)
	second := strategy([]C.Proxy{b, a}, metadata, false)
	if first.ProxyInfo().ProviderName != second.ProxyInfo().ProviderName || first.Addr() != second.Addr() {
		t.Fatalf(
			"delimiter collision migrated sticky session from provider=%q addr=%q to provider=%q addr=%q",
			first.ProxyInfo().ProviderName, first.Addr(), second.ProxyInfo().ProviderName, second.Addr(),
		)
	}
}

func TestConsistentHashingSeparatesDelimiterCollisions(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	strategy := strategyConsistentHashing("test", getKey, false, false)
	a := strategyTestProxy{name: "same", provider: "provider|segment", addr: "endpoint", alive: true}
	b := strategyTestProxy{name: "same", provider: "provider", addr: "segment|endpoint", alive: true}

	first := strategy([]C.Proxy{a, b}, metadata, false)
	second := strategy([]C.Proxy{b, a}, metadata, false)
	if first.ProxyInfo().ProviderName != second.ProxyInfo().ProviderName || first.Addr() != second.Addr() {
		t.Fatalf(
			"delimiter collision migrated consistent hash from provider=%q addr=%q to provider=%q addr=%q",
			first.ProxyInfo().ProviderName, first.Addr(), second.ProxyInfo().ProviderName, second.Addr(),
		)
	}
}

func TestStickySessionKeySeparatesSourceAndDestinationLengths(t *testing.T) {
	a := stickySessionKey("ab", "c")
	b := stickySessionKey("a", "bc")
	if a == b {
		t.Fatalf("sticky keys unexpectedly collide: %q", a)
	}
}

func TestDelayExceedsToleranceDoesNotWrap(t *testing.T) {
	if delayExceedsTolerance(0xFFFF, 0xFFFF, 100) {
		t.Fatal("maximal candidate plus tolerance must not wrap and trigger a switch")
	}
	if !delayExceedsTolerance(0xFFFF, 0xFF00, 100) {
		t.Fatal("a materially faster candidate should exceed the tolerance")
	}
	if delayExceedsTolerance(100, 0xFFFF, 100) {
		t.Fatal("a low current delay should not exceed a maximal candidate")
	}
}

// capabilityDemotedProxy 的能力探测始终失败，所以只要开启了偏好，它就一定带有
// 非零的 capability 惩罚。用它来守住核心语义：偏好只改变节点的排序，不能把节点
// 从候选池里拿掉 —— 早先的实现会直接截断候选，导致连 DIRECT 都被踢出组。
type capabilityDemotedProxy struct {
	strategyTestProxy
}

func (p capabilityDemotedProxy) StatusTest(context.Context, string) (uint16, bool, error) {
	return 0, false, errors.New("capability unavailable")
}

func demotedProxies(names ...string) []C.Proxy {
	proxies := make([]C.Proxy, len(names))
	for i, name := range names {
		proxies[i] = capabilityDemotedProxy{
			strategyTestProxy{name: name, alive: true, addr: name, provider: "p"},
		}
	}
	return proxies
}

// awaitDemoted blocks until every proxy reports demoted.
//
// CapabilityDemoted dispatches its probe asynchronously and reports capUnknown
// until the result lands, so a rotation measured while the probes are still in
// flight is measuring the transition, not the steady state. Observed as a real
// CI failure: proxy a settled first and was skipped by the preferred pass on
// every subsequent call while b was still unknown and kept winning it, giving
// a=1 b=3 out of four calls.
func awaitDemoted(t *testing.T, proxies []C.Proxy) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		settled := true
		for _, proxy := range proxies {
			if !adapter.CapabilityDemoted(proxy, false, true) {
				settled = false
				break
			}
		}
		if settled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("capability probes did not settle; the rotation below would be timing-dependent")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRoundRobinKeepsDemotedProxiesInRotation(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	proxies := demotedProxies("a", "b")
	awaitDemoted(t, proxies)

	// Build the strategy only once the verdicts are stable, so idx starts at a
	// known position and every call takes the same branch.
	strategy := strategyRoundRobin("test", false, true)
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		seen[strategy(proxies, metadata, true).Name()]++
	}
	if len(seen) != len(proxies) {
		t.Fatalf("全部节点被降权时轮换仍应覆盖所有节点，实际只用到 %v", seen)
	}
	for name, hits := range seen {
		if hits != 2 {
			t.Errorf("轮换应保持均匀，节点 %s 命中 %d 次", name, hits)
		}
	}
}

func TestConsistentHashingKeepsDemotedProxiesSelectable(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	proxies := demotedProxies("a", "b", "c")
	strategy := strategyConsistentHashing("test", getKey, false, true)

	// 全部降权时仍必须选出一个存活节点，且映射保持稳定。
	first := strategy(proxies, metadata, false)
	if first == nil {
		t.Fatal("全部节点被降权时不应选不出节点")
	}
	second := strategy(proxies, metadata, false)
	if first.Name() != second.Name() {
		t.Fatalf("一致性哈希应稳定，得到 %q 与 %q", first.Name(), second.Name())
	}
}

// 亲和性策略的映射必须与 capability 判定完全无关。判定会随探测从 unknown 变成
// confirmed，若它参与排序，探测落地就会把活跃会话迁到别的节点上 —— 这正是
// TestConsistentHashingKeepsDemotedProxiesSelectable 在 -count=2 下偶发失败的原因。
func TestAffinityStrategiesIgnoreCapabilityVerdicts(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com"}
	// 混合节点：demoted 的探测必定失败，普通的保持 unknown。
	mixed := []C.Proxy{
		capabilityDemotedProxy{strategyTestProxy{name: "a", alive: true, addr: "a", provider: "p"}},
		strategyTestProxy{name: "b", alive: true, addr: "b", provider: "p"},
		capabilityDemotedProxy{strategyTestProxy{name: "c", alive: true, addr: "c", provider: "p"}},
	}
	// 同一批节点，同样的身份，但不开启任何能力偏好 —— 这是纯哈希的基准答案。
	plain := []C.Proxy{
		strategyTestProxy{name: "a", alive: true, addr: "a", provider: "p"},
		strategyTestProxy{name: "b", alive: true, addr: "b", provider: "p"},
		strategyTestProxy{name: "c", alive: true, addr: "c", provider: "p"},
	}

	for _, testCase := range []struct {
		name  string
		build func(preferIPv6 bool) strategyFn
	}{
		{name: "consistent-hashing", build: func(preferIPv6 bool) strategyFn {
			return strategyConsistentHashing("test", getKey, false, preferIPv6)
		}},
		{name: "sticky-sessions", build: func(preferIPv6 bool) strategyFn {
			return strategyStickySessions("test", getKeyWithSrcAndDst, false, preferIPv6)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			want := testCase.build(false)(plain, metadata, false).Name()
			withPreference := testCase.build(true)
			// 反复调用：任何一次探测在调用之间落地都不得改变结果。
			for i := 0; i < 8; i++ {
				if got := withPreference(mixed, metadata, false).Name(); got != want {
					t.Fatalf("第 %d 次调用被能力判定改写了映射：得到 %q，纯哈希应为 %q", i+1, got, want)
				}
			}
		})
	}
}

// 未完成的探测不是降权：把 unknown 当成已确认失败，会让刚加载的大机场里每个
// 节点都被判定为降权，首轮轮换直接跳过全部节点。
func TestCapabilityDemotedIgnoresUnfinishedProbe(t *testing.T) {
	// 能力缓存是进程级全局的，判定一旦落地就会留在里面。用唯一身份保证每次调用
	// 看到的都是「探测尚未出结果」这个状态，否则 -count>1 时第二轮读到的是上一轮
	// 的结果。
	unique := fmt.Sprintf("%s-%d", t.Name(), capabilityTestSequence.Add(1))
	fresh := strategyTestProxy{name: unique, alive: true, addr: unique, provider: unique}
	if adapter.CapabilityDemoted(fresh, false, true) {
		t.Fatal("尚未出结果的探测不应被当作确认失败")
	}
	if adapter.CapabilityDemoted(nil, false, true) {
		t.Fatal("nil 节点不应被判定为降权")
	}
	if adapter.CapabilityDemoted(fresh, false, false) {
		t.Fatal("未开启任何偏好时不应有降权")
	}
}

// Smart 的持久化 store 以节点名为键，早于 provider 感知的身份而存在。同名不同
// provider 的节点因此共享同一份持久化数据，而缓存里的名字无法判断指向哪一个。
// uniqueProxiesByName 的契约是：宁可当作没有这条记录，也不能随手解析成迭代顺序
// 里恰好最后出现的那个节点 —— 后者会把流量按另一个机场的历史数据来选路。
func TestUniqueProxiesByNameDropsAmbiguousNames(t *testing.T) {
	duplicateA := strategyTestProxy{name: "same", alive: true, addr: "endpoint-a", provider: "provider-a"}
	duplicateB := strategyTestProxy{name: "same", alive: true, addr: "endpoint-b", provider: "provider-b"}
	unique := strategyTestProxy{name: "unique", alive: true, addr: "endpoint-c", provider: "provider-a"}

	byName := uniqueProxiesByName([]C.Proxy{duplicateA, duplicateB, unique})

	if _, resolved := byName["same"]; resolved {
		t.Fatal("有歧义的名字必须被丢弃，不能解析到任意一个节点")
	}
	got, resolved := byName["unique"]
	if !resolved {
		t.Fatal("无歧义的名字应当仍可解析")
	}
	if got.Addr() != unique.Addr() {
		t.Fatalf("解析到了错误的节点：%q", got.Addr())
	}

	// 顺序不能影响结果：歧义与迭代顺序无关。
	reordered := uniqueProxiesByName([]C.Proxy{unique, duplicateB, duplicateA})
	if _, resolved := reordered["same"]; resolved {
		t.Fatal("调换顺序后歧义名字又被解析出来了")
	}

	// 出现三次以上同样要丢弃，且不能因为后续重复而“复活”。
	triple := uniqueProxiesByName([]C.Proxy{duplicateA, duplicateB, duplicateA, unique})
	if _, resolved := triple["same"]; resolved {
		t.Fatal("重复出现三次的名字仍被解析")
	}
	if _, resolved := triple["unique"]; !resolved {
		t.Fatal("歧义名字不应影响其它名字的解析")
	}

	if len(uniqueProxiesByName([]C.Proxy{nil, unique})) != 1 {
		t.Fatal("nil 节点应被跳过而不是引发 panic")
	}
}

// The name index changes only when the proxies do, so it is cached with them.
// Both the selection path and the filter need it on every connection and were
// each rebuilding two maps over the whole pool.
//
// Invalidation is not covered here: it is a single statement beside the
// assignment it pairs with in GetProxies, and reaching it from a test needs a
// provider whose version moves, which this package has no fixture for. Faking
// the clear would only assert the test's own stub.
func TestProxyNameIndexIsCachedWithTheProxies(t *testing.T) {
	gb := &GroupBase{}
	gb.providerProxies = strategyProxies("node-a", "node-b")
	gb.providerVersions = []uint32{}

	proxies, first := gb.GetProxiesByName(false)
	if len(proxies) != 2 || first["node-a"] == nil {
		t.Fatalf("index = %v over %d proxies", first, len(proxies))
	}
	_, second := gb.GetProxiesByName(false)
	if reflect.ValueOf(first).Pointer() != reflect.ValueOf(second).Pointer() {
		t.Fatal("the index was rebuilt for an unchanged proxy list")
	}

}

// A caller holding a slice that is not the group's own gets an index over what
// it actually passed, not the cached one.
func TestProxyIndexForAForeignSliceIsNotTheCachedOne(t *testing.T) {
	s := &Smart{GroupBase: &GroupBase{}}
	s.providerProxies = strategyProxies("node-a")
	s.proxiesByName = uniqueProxiesByName(s.providerProxies)

	foreign := strategyProxies("node-z")
	got := s.proxyIndexFor(foreign)
	if got["node-z"] == nil || got["node-a"] != nil {
		t.Fatalf("index = %v, want it to describe the slice that was passed", got)
	}
}

const testUrl = "https://www.gstatic.com/generate_204"

// Upstream builds these from identical DIRECT adapters and tells them apart by
// position. The hashing strategies here rank by adapter.ProxyIdentity, so
// identical adapters would all tie and every key would land on the first one;
// the members need distinct identities for the spread to be observable.
func balancedProxies(count int) []C.Proxy {
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("node-%d", i)
	}
	return strategyProxies(names...)
}

func indexOf(t *testing.T, proxies []C.Proxy, selected C.Proxy) int {
	t.Helper()
	for i, proxy := range proxies {
		if proxy == selected {
			return i
		}
	}
	require.Fail(t, "selected proxy is not a member of the group")
	return -1
}

func request(user, host string) *C.Metadata {
	return &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstPort: 443,
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		InUser:  user,
	}
}

// One unit of work walking several destinations is the case both address-derived
// keys get wrong: the group is meant to hold that work on one egress, and the
// default key changes as soon as the host changes.
func TestLoadBalanceHashKeyInUserSurvivesADestinationChange(t *testing.T) {
	proxies := balancedProxies(8)
	hosts := distinctKeys("www.site-%02d.com", 16)

	byUser := strategyConsistentHashing(testUrl, getKeyWithInUser(getKey), false, false)
	pinned := indexOf(t, proxies, byUser(proxies, request("job-1", hosts[0]), false))
	for _, host := range hosts {
		selected := byUser(proxies, request("job-1", host), false)
		require.Equal(t, pinned, indexOf(t, proxies, selected),
			"hash-key: user must ignore the destination")
	}

	// Distinct keys may legally select the same bucket; assert the key contract.
	seenKeys := map[string]struct{}{}
	for _, host := range hosts {
		seenKeys[getKey(request("job-1", host))] = struct{}{}
	}
	require.Len(t, seenKeys, len(hosts), "the default key must change with the destination")
}

// distinctKeys returns count distinct keys; for hosts, vary the registrable
// domain, since getKey hashes the eTLD+1.
func distinctKeys(format string, count int) []string {
	keys := make([]string, count)
	for i := range keys {
		keys[i] = fmt.Sprintf(format, i)
	}
	return keys
}

// Pinning must preserve distinct inbound identities before hashing.
func TestLoadBalanceHashKeyInUserKeepsUsersDistinct(t *testing.T) {
	keyed := getKeyWithInUser(getKey)
	users := distinctKeys("job-%02d", 16)
	seenKeys := map[string]struct{}{}
	for _, user := range users {
		seenKeys[keyed(request(user, "a.example.com"))] = struct{}{}
	}
	require.Len(t, seenKeys, len(users))
}

// Sticky sessions keys on source and destination; a client behind one source
// address cannot separate its own concurrent jobs without a supplied identity.
func TestLoadBalanceHashKeyInUserSeparatesJobsSharingASourceAddress(t *testing.T) {
	proxies := balancedProxies(8)
	strategy := strategyStickySessions(testUrl, getKeyWithInUser(getKeyWithSrcAndDst), false, false)

	first := indexOf(t, proxies, strategy(proxies, request("job-1", "a.example.com"), false))
	require.Equal(t, first,
		indexOf(t, proxies, strategy(proxies, request("job-1", "b.example.org"), false)))

	shared := strategyStickySessions(testUrl, getKeyWithSrcAndDst, false, false)
	require.Equal(t,
		indexOf(t, proxies, shared(proxies, request("job-1", "a.example.com"), false)),
		indexOf(t, proxies, shared(proxies, request("job-2", "a.example.com"), false)),
		"without a supplied key the two jobs are one session")
}

// An unauthenticated request keeps the strategy's own key. Returning a constant
// instead would herd every anonymous request onto one member.
func TestLoadBalanceHashKeyInUserFallsBackWhenUnauthenticated(t *testing.T) {
	keyed := getKeyWithInUser(getKey)
	require.Equal(t, "example.com", keyed(request("", "a.example.com")))
	require.Equal(t, "job-1", keyed(request("job-1", "a.example.com")))
	require.Equal(t, getKey(nil), keyed(nil))
}

// The option name is the contract with the config file, and nothing else here
// exercises it: every other test reaches the decorator directly, so renaming
// the case would leave them all green while `hash-key: in-user` stopped working.
func TestLoadBalanceHashKeyResolvesTheOptionName(t *testing.T) {
	withInUser, err := hashKey("in-user")
	require.NoError(t, err)
	require.Equal(t, "job-1", withInUser(getKey)(request("job-1", "a.example.com")))

	identity, err := hashKey("")
	require.NoError(t, err)
	require.Equal(t, getKey(request("job-1", "a.example.com")),
		identity(getKey)(request("job-1", "a.example.com")))
}

func TestLoadBalanceHashKeyRejectsUnusableConfigs(t *testing.T) {
	_, err := hashKey("session")
	require.ErrorIs(t, err, errHashKey)

	// `user` was the name this option carried before review. Rejecting it keeps
	// the rename honest: without this the case above could still read `user`
	// and every test here would stay green.
	_, err = hashKey("user")
	require.ErrorIs(t, err, errHashKey)

	_, err = NewLoadBalance(GroupCommonOption{Name: "lb"},
		LoadBalanceOption{Strategy: "round-robin", HashKey: "in-user"}, nil, nil)
	require.ErrorIs(t, err, errHashKey)

	_, err = NewLoadBalance(GroupCommonOption{Name: "lb"},
		LoadBalanceOption{Strategy: "consistent-hashing", HashKey: "nonsense"}, nil, nil)
	require.ErrorIs(t, err, errHashKey)
}

type filterOrderProxy struct {
	C.Proxy
	name string
}

func (p *filterOrderProxy) Name() string { return p.name }

func (p *filterOrderProxy) AliveForTestUrl(string) bool { return true }

func TestFilterProxiesPutsSuspectedBehindUnrankedCandidates(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/smart.db", 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := smart.NewStore(db)
	watcher := smart.NewExitWatcher(smart.ExitWatcherOptions{Name: "exit-order-test", Config: "test"})
	now := time.Now()
	all := make([]C.Proxy, 0, 12)
	names := make([]string, 0, 10)
	weights := make([]float64, 0, 10)
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("node-%02d", i)
		proxy := &filterOrderProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), name: name}
		all = append(all, proxy)
		if i >= 10 {
			continue
		}
		names = append(names, name)
		weights = append(weights, 1)
		watcher.Store(name, smart.ExitInfo{Region: "hk", Key: name}, now)
		watcher.Note("*.example.test", name)
		if i == 0 {
			watcher.Store("control", smart.ExitInfo{Region: "us", Key: "control-exit"}, now)
			watcher.NoteSuccess("*.example.test", "control")
		}
	}

	s := &Smart{
		GroupBase:  NewGroupBase(GroupBaseOption{Name: "exit-order-test"}),
		store:      store,
		exitWatch:  watcher,
		testUrl:    testUrl,
		configName: "test",
	}
	selected := s.filterProxies(request("user", "example.test"), "*.example.test", names, weights, all, 10, false)
	if len(selected) != 3 {
		t.Fatalf("selected %d candidates, want 2 healthy alternatives and 1 half-open fallback", len(selected))
	}
	if selected[0].Name() != "node-10" || selected[1].Name() != "node-11" {
		t.Fatalf("unranked candidates must precede suspected exits, got %q, %q", selected[0].Name(), selected[1].Name())
	}
	if watcher.Suspected("*.example.test", selected[2].Name()) == false {
		t.Fatalf("last candidate %q must be the half-open fallback", selected[2].Name())
	}
}

func TestFilterProxiesDefersCachedSuspectedNodes(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/smart.db", 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := smart.NewStore(db)
	watcher := smart.NewExitWatcher(smart.ExitWatcherOptions{Name: "cached-exit-order-test", Config: "test"})
	now := time.Now()
	target := "*.onejav.com"
	for _, node := range []string{"jp-suspected", "jp-second"} {
		watcher.Store(node, smart.ExitInfo{Region: "jp", Key: node}, now)
		watcher.Note(target, node)
	}
	watcher.Store("hk-control", smart.ExitInfo{Region: "hk", Key: "hk-control"}, now)
	watcher.NoteSuccess(target, "hk-control")

	all := []C.Proxy{
		&filterOrderProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), name: "jp-suspected"},
		&filterOrderProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), name: "hk-cached"},
		&filterOrderProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), name: "hk-fallback-1"},
		&filterOrderProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), name: "hk-fallback-2"},
	}
	group := &Smart{
		GroupBase:  NewGroupBase(GroupBaseOption{Name: "cached-exit-order-test"}),
		store:      store,
		exitWatch:  watcher,
		testUrl:    testUrl,
		configName: "test",
	}
	selected := group.filterProxies(request("user", "onejav.com"), target,
		[]string{"jp-suspected", "hk-cached"}, nil, all, 3, false)
	if len(selected) != 1 || selected[0].Name() != "hk-cached" {
		t.Fatalf("cached selection should keep only its healthy entry, got %v", selected)
	}
	for _, proxy := range selected {
		if proxy.Name() == "jp-suspected" {
			t.Fatalf("a cached suspected candidate must stay behind available alternatives: %+v", selected)
		}
	}
}

func TestFilterProxiesFailsOpenWhenAllCandidatesSuspected(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/smart.db", 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := smart.NewStore(db)
	watcher := smart.NewExitWatcher(smart.ExitWatcherOptions{Name: "exit-fail-open-test", Config: "test"})
	now := time.Now()
	for _, node := range []string{"jp-01", "jp-02"} {
		watcher.Store(node, smart.ExitInfo{Region: "jp", Key: node}, now)
		watcher.Note("*.onejav.com", node)
	}
	watcher.Store("hk-control", smart.ExitInfo{Region: "hk", Key: "hk-control"}, now)
	watcher.NoteSuccess("*.onejav.com", "hk-control")
	proxies := []C.Proxy{
		&filterOrderProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), name: "jp-01"},
		&filterOrderProxy{Proxy: adapter.NewProxy(outbound.NewDirect()), name: "jp-02"},
	}
	group := &Smart{
		GroupBase:  NewGroupBase(GroupBaseOption{Name: "exit-fail-open-test"}),
		store:      store,
		exitWatch:  watcher,
		testUrl:    testUrl,
		configName: "test",
	}
	selected := group.filterProxies(request("user", "onejav.com"), "*.onejav.com", []string{"jp-01", "jp-02"}, []float64{1, 1}, proxies, 2, false)
	if len(selected) != 1 || selected[0].Name() != "jp-01" {
		t.Fatalf("all-suspected target should allow only one half-open node, got %v", selected)
	}
}

func TestPeriodicOriginRefusalsRaiseExitSuspicion(t *testing.T) {
	watcher := smart.NewExitWatcher(smart.ExitWatcherOptions{Name: "exit-evidence-test"})
	now := time.Now()
	watcher.Store("jp-01", smart.ExitInfo{Region: "jp", Key: "exit-jp-01"}, now)
	watcher.Store("jp-02", smart.ExitInfo{Region: "jp", Key: "exit-jp-02"}, now)
	group := &Smart{exitWatch: watcher}
	target := "*.onejav.com"

	group.noteExitEvidence(target, "jp-01", smart.ReasonOriginError)
	if watcher.Suspected(target, "jp-01") {
		t.Fatal("one JP exit must not raise a suspicion")
	}
	watcher.Store("hk-control", smart.ExitInfo{Region: "hk", Key: "exit-hk"}, now)
	group.noteExitSuccess(target, "hk-control", smart.ClassifyResponse(http.StatusOK, nil, nil, now))
	group.noteExitEvidence(target, "jp-02", smart.ReasonOriginError)
	if !watcher.Suspected(target, "jp-01") {
		t.Fatal("independent JP origin refusals must raise a suspicion")
	}
}
