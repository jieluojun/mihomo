//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"time"
	"unsafe"
)

func TestBypassExcludeCompileIndependentOfFakeIP(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.1.2/106"), netip.MustParsePrefix("10.1.2.3/8"), netip.MustParsePrefix("fd7a:115c:a1e0::1/48")}
	p, err := CompilePolicy(PolicyConfig{LocalBypassExclude: prefixes, SharedBypassExclude: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}, FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15")})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.localBypassExclude.ipv4) != 2 || len(p.localBypassExclude.ipv6) != 1 || len(p.sharedBypassExclude.ipv4) != 1 {
		t.Fatalf("scope policies: %+v", p)
	}
	if p.localBypassExclude.ipv4[1] != netip.MustParsePrefix("100.64.0.0/10") {
		t.Fatal("mapped prefix was not normalized")
	}
	prefixes[0] = netip.Prefix{}
	if !p.localBypassExclude.ipv4[1].IsValid() || p.fakeIPIPv4 != netip.MustParsePrefix("198.18.0.0/15") {
		t.Fatal("mutable or shared fake-IP policy")
	}
	for _, bad := range []netip.Prefix{{}, netip.MustParsePrefix("::ffff:0:0/80")} {
		if _, err = CompilePolicy(PolicyConfig{LocalBypassExclude: []netip.Prefix{bad}}); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestRecoveryExpiryAndABI(t *testing.T) {
	if unsafe.Sizeof(UDPReleaseEvent{}) != 16 || unsafe.Sizeof(tcRetiredKey{}) != 56 || unsafe.Offsetof(TCAssignment{}.Generation) != 24 {
		t.Fatal("recovery ABI mismatch")
	}
	e := UDPReleaseEvent{1, 100}
	if recoveryExpired(e, 99, time.Nanosecond) || recoveryExpired(e, 109, 10*time.Nanosecond) || !recoveryExpired(e, 110, 10*time.Nanosecond) {
		t.Fatal("expiry crossed its boundary")
	}
}
