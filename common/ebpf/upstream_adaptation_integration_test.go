//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestBypassExcludeDataplanesIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run independent bypass-exclude policies")
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true, SharedDNSMode: DNSModeOff, SharedBypassPrivate: true,
		SharedBypassPort: []PortRange{{53, 53}}, IncludeSourceMAC: []MACAddress{{2, 0, 0, 0, 0, 99}},
		LocalBypassExclude:  []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		SharedBypassExclude: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
		FakeIPIPv4:          netip.MustParsePrefix("198.18.0.0/15")})
	if err != nil {
		t.Fatal(err)
	}
	tc, err := PrepareTC(TCConfig{ListenerPort: 65531, EnableTCP: true, EnableShared: true, EnableIPv4: true, EnableSharedIPv6: true, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	if err = tc.Enable(); err != nil {
		t.Fatal(err)
	}
	shared, err := PrepareSharedNetwork(nil, SharedNetworkConfig{ListenerPort: 65531, EnableTCP: true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		UDPTimeout: time.Minute, Policy: policy, MapCapacity: SharedNetworkMapCapacities{Proxy: 64, Bypass: 64}})
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if err = shared.Enable(); err != nil {
		t.Fatal(err)
	}
	for _, update := range []bool{false, true} {
		if update {
			if _, err = tc.SetFakeIPRanges(netip.MustParsePrefix("198.20.0.0/16"), netip.Prefix{}); err != nil {
				t.Fatal(err)
			}
			if _, err = shared.SetFakeIPRanges(netip.MustParsePrefix("198.20.0.0/16"), netip.Prefix{}); err != nil {
				t.Fatal(err)
			}
		}
		for _, tt := range []struct {
			src, dst string
			force    bool
		}{
			{"192.0.2.10:53001", "100.64.0.7:53", true},
			{"[2001:db8::10]:53002", "[fd7a:115c:a1e0::7]:53", true},
			{"192.0.2.10:53003", "192.168.1.7:53", false},
			{"192.0.2.10:53004", "127.0.0.1:53", false},
		} {
			packet := sharedRewriteTestPacket(ProtocolTCP, netip.MustParseAddrPort(tt.src), netip.MustParseAddrPort(tt.dst), nil, false)
			action, _ := runTCProgram(t, tc.runtime.programs[tcProgramSharedIngressEthernet], packet)
			want := testTCActUnspec
			if tt.force {
				want = testTCActShot
			} // missing listener proves selection
			if action != want {
				t.Fatalf("TC %s reload=%v: action=%d want=%d", tt.dst, update, action, want)
			}
			action, out := runTCProgram(t, shared.IngressProgram(), packet)
			if tt.force {
				if action != 0 || bytes.Equal(out, packet) {
					t.Fatalf("rewrite did not intercept %s: %d", tt.dst, action)
				}
			} else if action != testTCActUnspec || !bytes.Equal(out, packet) {
				t.Fatalf("rewrite intercepted unrelated %s", tt.dst)
			}
		}
	}
}

func TestCgroupForceAndReleaseEventIntegration(t *testing.T) {
	requireEBPFIntegration(t, "exercise forced DNS and actual socket release events")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 990)
	if !dedicated {
		t.Skip("dedicated cgroup unavailable")
	}
	self, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LRUHash, KeySize: 8, ValueSize: 4, MaxEntries: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	policy, err := CompilePolicy(PolicyConfig{EnableUDP: true, Local: LocalPolicy{DNSMode: DNSModeOff, BypassPrivateAddress: true, ExcludeUID: []UIDRange{{0, 0}}}, LocalBypassPort: []PortRange{{53, 53}}, LocalBypassExclude: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := PrepareCgroup(CgroupConfig{Path: path, EnableUDP: true, RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), UDPTimeout: time.Minute, Policy: policy, SelfBypassMap: self, MapCapacity: CgroupMapCapacity{64, 64, 64, 64, 8}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	l, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err = b.LoadPrograms(uint16(l.LocalAddr().(*net.UDPAddr).Port)); err != nil {
		t.Fatal(err)
	}
	if err = b.Attach(); err != nil {
		t.Fatal(err)
	}
	if _, err = b.SetFakeIPRanges(netip.MustParsePrefix("198.20.0.0/16"), netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestAdaptedUDPHelperProcess$")
	command.Env = append(os.Environ(), "SB_EBPF_ADAPTED_UDP_HELPER=1")
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	l.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	if n, _, err := l.ReadFromUDP(buf); err != nil || string(buf[:n]) != "forced" {
		t.Fatalf("force policy lost to UID/port/DNS/private: %q %v", buf[:n], err)
	}
	d := b.UDPStateDiagnostics()
	if d.UserspaceCleanupMode != "ringbuf" {
		t.Fatalf("ring observer fell back on integration kernel: %+v", d)
	}
	event, err := b.ReadUDPRelease(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var key listenerLookupKey
	var index originalDestinationValue
	iter := b.runtime.maps["cgroup_udp_recovery"].Iterate()
	if !iter.Next(&key, &index) || index.SocketCookie != event.SocketCookie || index.CreatedAtNS != event.ReleasedAtNS {
		t.Fatalf("event/index mismatch: %+v %+v err=%v", event, index, iter.Err())
	}
	listener := netip.AddrPortFrom(netip.AddrFrom4([4]byte(key.TokenAddr[:4])), key.ListenerPort)
	original, err := b.RecoverUDPOriginal(listener)
	if err != nil || original.Destination != netip.MustParseAddrPort("100.64.0.7:53") {
		t.Fatalf("late packet recovery: %+v %v", original, err)
	}
	if err = b.DeleteRedirect(ProtocolUDP, listener); err != nil {
		t.Fatal(err)
	}
	// A delayed event must not remove the newer payload for the same token.
	if err = b.DeleteUDPRecovery(event); err != nil {
		t.Fatal(err)
	}
	if _, err = b.RecoverUDPOriginal(listener); err != nil {
		t.Fatalf("old event deleted new recovery: %v", err)
	}
}

func TestAdaptedUDPHelperProcess(t *testing.T) {
	if os.Getenv("SB_EBPF_ADAPTED_UDP_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	conn, err := net.Dial("udp4", "100.64.0.7:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("forced")); err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTCUDPAssignmentRetirementIntegration(t *testing.T) {
	requireEBPFIntegration(t, "retire a stale TC assignment while its key is reused")
	b := newTestAssignmentBackend(t)
	m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LRUHash, KeySize: 56, ValueSize: 1, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	b.runtime.maps["tc_retired_assignment"] = m
	src, dst := netip.MustParseAddrPort("192.0.2.1:50001"), netip.MustParseAddrPort("203.0.113.1:53")
	old := TCAssignment{Generation: 100, SocketCookie: 7}
	newer := old
	newer.Generation = 101
	writeTestAssignment(t, b, ProtocolUDP, src, dst, 3, newer)
	if err = b.DeleteUDPAssignment(src, dst, 3, old); err != nil {
		t.Fatal(err)
	}
	if got, err := b.LookupAssignment(ProtocolUDP, src, dst, 3, false); err != nil || got != newer {
		t.Fatalf("new assignment lost: %+v %v", got, err)
	}
	if err = b.DeleteUDPAssignment(src, dst, 3, newer); err != nil {
		t.Fatal(err)
	}
	if _, err = b.LookupAssignment(ProtocolUDP, src, dst, 3, false); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("retired assignment still visible: %v", err)
	}
	key, _ := makeTCAssignKey(ProtocolUDP, src, dst, 3)
	var kept TCAssignment
	if err = lookupMap(b.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&kept)); err != nil || kept != newer {
		t.Fatal("retirement mutated the kernel's index")
	}
}

func TestUDPReverseRecoveryAndExpiryIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify reverse index and bounded recovery expiry")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	path, _ := createIntegrationCgroup(t, root, 991)
	b, err := prepareCgroupIntegrationBackend(path, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	// Exercise the same non-ring program selection an older kernel uses.
	if b.runtime.udpReleaseReader != nil {
		b.runtime.udpReleaseReader.Close()
		b.runtime.udpReleaseReader = nil
	}
	b.runtime.udpReleaseFallback = "ringbuf_unsupported"
	if err = b.LoadPrograms(41099); err != nil {
		t.Fatal(err)
	}
	if b.cgroupProgramSection(cgroupProgramSocketRelease) != "cgroup/sock_release_cookie" || b.UDPStateDiagnostics().UserspaceCleanupMode != "deadline" {
		t.Fatal("fallback selected ring program")
	}
	b.runtime.socket_release_supported = false
	listener := netip.MustParseAddrPort("127.128.0.9:41099")
	key, _ := makeListenerLookupKey(ProtocolUDP, listener)
	cookie := uint64(901)
	peer := udpPeerValue{Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: 443}
	copy(peer.Addr[:], netip.MustParseAddr("203.0.113.9").AsSlice())
	put := func(name string, k, v unsafe.Pointer) {
		t.Helper()
		if err := updateMap(b.runtime.maps[name].FD(), k, v); err != nil {
			t.Fatal(err)
		}
	}
	put("cgroup_udp_token", unsafe.Pointer(&cookie), unsafe.Pointer(&key))
	put("cgroup_udp_token_reverse", unsafe.Pointer(&key), unsafe.Pointer(&cookie))
	put("cgroup_udp_peer", unsafe.Pointer(&cookie), unsafe.Pointer(&peer))
	if original, err := b.RecoverConnectedUDPOriginal(listener); err != nil || original.SocketCookie != cookie {
		t.Fatalf("reverse recovery: %+v %v", original, err)
	}
	changed := key
	changed.ListenerPort++
	put("cgroup_udp_token", unsafe.Pointer(&cookie), unsafe.Pointer(&changed))
	if _, err := b.RecoverConnectedUDPOriginal(listener); err == nil {
		t.Fatal("stale reverse entry accepted")
	}
	b.udpTimeoutSeconds = 1
	now := monotonicNowNS()
	old := UDPReleaseEvent{cookie, now - uint64(2*time.Second)}
	current := UDPReleaseEvent{cookie, now}
	value := originalDestinationValue{Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: 443, SocketCookie: cookie}
	copy(value.Addr[:], peer.Addr[:])
	put("cgroup_udp_recovery_value", unsafe.Pointer(&old), unsafe.Pointer(&value))
	put("cgroup_udp_recovery_value", unsafe.Pointer(&current), unsafe.Pointer(&value))
	complete := false
	for n := 0; n < 5 && !complete; n++ {
		complete, err = b.SweepUDPRecovery(1)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !complete {
		t.Fatal("bounded sweep did not finish")
	}
	m := b.runtime.maps["cgroup_udp_recovery_value"]
	if err = lookupMap(m.FD(), unsafe.Pointer(&old), unsafe.Pointer(&value)); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("expired recovery retained: %v", err)
	}
	if err = lookupMap(m.FD(), unsafe.Pointer(&current), unsafe.Pointer(&value)); err != nil {
		t.Fatalf("current recovery removed: %v", err)
	}
}

func TestUDPReleaseReaderStopsOnCancellationIntegration(t *testing.T) {
	requireEBPFIntegration(t, "cancel a blocked UDP release reader")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	path, _ := createIntegrationCgroup(t, root, 992)
	b, err := prepareCgroupIntegrationBackend(path, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.runtime.udpReleaseReader == nil {
		t.Skip("ring buffer unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.RunUDPRecoveryCleanup(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader blocked shutdown")
	}
}
