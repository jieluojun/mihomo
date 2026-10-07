//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestCgroupBypassRefreshAndRollbackIntegration(t *testing.T) {
	path, _ := dedicatedHookOwnerCgroup(t, 980)
	b, err := prepareCgroupIntegrationBackend(path, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	b.listenerPort = 41100
	policy := func(prefixes ...string) BypassCIDRPolicy {
		var parsed []netip.Prefix
		for _, prefix := range prefixes {
			parsed = append(parsed, netip.MustParsePrefix(prefix))
		}
		p, err := CompileBypassCIDRPolicy(parsed)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	check := func(want4, want6 bool) {
		t.Helper()
		var control cgroupControl
		key := uint32(0)
		if err := lookupMap(b.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control)); err != nil {
			t.Fatal(err)
		}
		mask := (policyVector{BypassIPv4: true, BypassIPv6: true}).cgroupFlags()
		want := (policyVector{BypassIPv4: want4, BypassIPv6: want6}).cgroupFlags()
		if control.Flags&mask != want || b.runtime.bypass_ipv4_policy != want4 || b.runtime.bypass_ipv6_policy != want6 {
			t.Fatalf("bypass flags kernel=%#x, want %#x", control.Flags&mask, want)
		}
	}
	if _, err = b.UpdateCompiledBypassCIDR(policy()); err != nil {
		t.Fatal(err)
	}
	check(false, false)
	if _, err = b.UpdateCompiledBypassCIDR(policy("203.0.113.0/24", "2001:db8::/32")); err != nil {
		t.Fatal(err)
	}
	check(true, true)
	// A failed control write must put back the previous map contents and flags.
	fd := b.runtime.control_map_fd
	b.runtime.control_map_fd = -1
	_, err = b.UpdateCompiledBypassCIDR(policy())
	b.runtime.control_map_fd = fd
	if err == nil {
		t.Fatal("invalid control FD accepted")
	}
	check(true, true)
	if v4, v6 := b.BypassCIDRCount(); v4 != 1 || v6 != 1 {
		t.Fatalf("rollback lost cached prefixes: %d/%d", v4, v6)
	}
	v4key := ipv4CIDRLPMKey{PrefixLength: 24, Address: [4]byte{203, 0, 113, 0}}
	if value, lookupErr := b.runtime.maps["cgroup_bypass_ipv4"].LookupBytes(&v4key); lookupErr != nil || len(value) == 0 {
		t.Fatalf("rollback lost kernel prefix: value=%v, error=%v", value, lookupErr)
	}
	if _, err = b.UpdateCompiledBypassCIDR(policy("203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	check(true, false)
	if _, err = b.UpdateCompiledBypassCIDR(policy()); err != nil {
		t.Fatal(err)
	}
	check(false, false)
}

func TestCgroupTakeFallbackRetainsRedirectIntegration(t *testing.T) {
	path, _ := dedicatedHookOwnerCgroup(t, 981)
	b, err := prepareCgroupIntegrationBackend(path, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	b.lookupAndDeleteMode.Store(mapLookupAndDeleteUnsupported)
	destination := netip.MustParseAddrPort("203.0.113.1:53")
	address, err := b.ReserveUDPReplyRedirect(destination, 41101)
	if err != nil {
		t.Fatal(err)
	}
	token := netip.AddrPortFrom(address, 41101)
	first, err := b.TakeOriginal(ProtocolUDP, token)
	if err != nil || first.Destination != destination {
		t.Fatalf("take = %+v, %v", first, err)
	}
	remaining, err := b.LookupOriginal(ProtocolUDP, token)
	if err != nil || remaining.Destination != destination {
		t.Fatalf("non-atomic fallback deleted redirect: %+v, %v", remaining, err)
	}
}
