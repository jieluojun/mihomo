//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func prepareCgroupMaps(runtimeState *cgroupRuntime, capacity CgroupMapCapacity, uidEntries int, selfBypassMap *CiliumEBPF.Map) error {
	udpLayout := cgroupUDPMapConfiguration(
		runtimeState.enable_udp,
		runtimeState.socket_release_supported,
		capacity,
	)
	tcpCapacity := uint32(1)
	udpCapacity := uint32(1)
	if runtimeState.enable_tcp {
		tcpCapacity = capacity.TCPRedirect
	}
	if runtimeState.enable_udp {
		udpCapacity = capacity.UDPRedirect
	}
	recoveryCapacity := min(udpCapacity, uint32(UDPRecoveryMapCapacity))
	uidCapacity := uint32(uidEntries)
	if uidCapacity == 0 {
		uidCapacity = 1
	}
	var err error
	overrides := map[string]mapSpecOverride{
		"cgroup_local_force_ipv4":   {name: "sb_cg_lforce4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassExcludeEntries, flags: bpfFlagNoPrealloc},
		"cgroup_local_force_ipv6":   {name: "sb_cg_lforce6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassExcludeEntries, flags: bpfFlagNoPrealloc},
		"cgroup_control":            {name: "sb_cg_control", mapType: CiliumEBPF.Array, maxEntries: 1},
		"cgroup_tcp_redirect":       {name: "sb_cg_tcp", mapType: CiliumEBPF.LRUHash, maxEntries: tcpCapacity},
		"cgroup_udp_redirect":       {name: "sb_cg_udp", mapType: udpLayout.cleanupType, maxEntries: udpCapacity, flags: udpLayout.cleanupFlags},
		"cgroup_udp_recovery_value": {name: "sb_cg_rec_value", mapType: CiliumEBPF.LRUHash, maxEntries: recoveryCapacity},
		"cgroup_udp_recovery":       {name: "sb_cg_recover", mapType: CiliumEBPF.LRUHash, maxEntries: recoveryCapacity},
		"cgroup_udp_token_reverse":  {name: "sb_cg_token_rev", mapType: udpLayout.cleanupType, maxEntries: udpCapacity, flags: udpLayout.cleanupFlags},
		"cgroup_udp_token":          {name: "sb_cg_token", mapType: udpLayout.cleanupType, maxEntries: udpCapacity, flags: udpLayout.cleanupFlags},
		"cgroup_udp_peer":           {name: "sb_cg_peer", mapType: udpLayout.peerType, maxEntries: udpLayout.peerCapacity, flags: udpLayout.peerFlags},
		"cgroup_udp_flow":           {name: "sb_cg_flow", mapType: CiliumEBPF.LRUHash, maxEntries: udpLayout.flowCapacity},
		"cgroup_socket_bypass":      {name: "sb_cg_sock_byp", mapType: CiliumEBPF.LRUHash, maxEntries: capacity.SocketBypass},
		"cgroup_bypass_port":        {name: "sb_cg_bypass_port", mapType: CiliumEBPF.Hash, maxEntries: tcPortPolicyCapacity},
		"cgroup_uid_policy":         {name: "sb_cg_uid", mapType: CiliumEBPF.LPMTrie, maxEntries: uidCapacity, flags: bpfFlagNoPrealloc},
		"cgroup_bypass_ipv4":        {name: "sb_cg_bypass4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"cgroup_bypass_ipv6":        {name: "sb_cg_bypass6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"cgroup_host_ipv4":          {name: "sb_cg_host4", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries, flags: bpfFlagNoPrealloc},
		"cgroup_host_ipv6":          {name: "sb_cg_host6", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries, flags: bpfFlagNoPrealloc},
	}
	if runtimeState.enable_udp && runtimeState.socket_release_supported {
		runtimeState.udpReleaseFallback = "ringbuf_unsupported"
		if features.HaveMapType(CiliumEBPF.RingBuf) == nil {
			overrides["cgroup_udp_release_events"] = mapSpecOverride{name: "sb_cg_rel_evt", mapType: CiliumEBPF.RingBuf, maxEntries: 65536}
			overrides["cgroup_udp_release_stats"] = mapSpecOverride{name: "sb_cg_rel_stat", mapType: CiliumEBPF.PerCPUArray, maxEntries: 1}
		}
	}
	runtimeState.maps, err = loadObjectMaps(loadCgroup, overrides)
	if err != nil && overrides["cgroup_udp_release_events"].mapType == CiliumEBPF.RingBuf {
		runtimeState.udpReleaseFallback = "ringbuf_map_load_failed"
		delete(overrides, "cgroup_udp_release_events")
		delete(overrides, "cgroup_udp_release_stats")
		runtimeState.maps, err = loadObjectMaps(loadCgroup, overrides)
	}
	if err != nil {
		return err
	}
	if events := runtimeState.maps["cgroup_udp_release_events"]; events != nil {
		reader, readerErr := ringbuf.NewReader(events)
		if readerErr == nil {
			runtimeState.udpReleaseReader = reader
			runtimeState.udpReleaseFallback = ""
		} else {
			runtimeState.udpReleaseFallback = "ringbuf_reader_unavailable"
		}
	}
	if selfBypassMap == nil {
		return E.New("missing eBPF self-bypass map")
	}
	sharedSelfBypassMap, err := selfBypassMap.Clone()
	if err != nil {
		return E.Cause(err, "clone eBPF self-bypass map")
	}
	if closeErr := runtimeState.maps["cgroup_socket_bypass"].Close(); closeErr != nil {
		_ = sharedSelfBypassMap.Close()
		return closeErr
	}
	runtimeState.maps["cgroup_socket_bypass"] = sharedSelfBypassMap
	if err = validateCgroupUDPCleanupMaps(runtimeState); err != nil {
		return err
	}
	runtimeState.control_map_fd = runtimeState.maps["cgroup_control"].FD()
	runtimeState.tcp_redirect_map_fd = runtimeState.maps["cgroup_tcp_redirect"].FD()
	runtimeState.udp_redirect_map_fd = runtimeState.maps["cgroup_udp_redirect"].FD()
	runtimeState.udp_recovery_map_fd = runtimeState.maps["cgroup_udp_recovery"].FD()
	runtimeState.udp_token_map_fd = runtimeState.maps["cgroup_udp_token"].FD()
	runtimeState.udp_peer_map_fd = runtimeState.maps["cgroup_udp_peer"].FD()
	runtimeState.udp_flow_map_fd = runtimeState.maps["cgroup_udp_flow"].FD()
	runtimeState.bypass_socket_cookie_map_fd = runtimeState.maps["cgroup_socket_bypass"].FD()
	runtimeState.uid_policy_map_fd = runtimeState.maps["cgroup_uid_policy"].FD()
	runtimeState.bypass_ipv4_cidr_map_fd = runtimeState.maps["cgroup_bypass_ipv4"].FD()
	runtimeState.bypass_ipv6_cidr_map_fd = runtimeState.maps["cgroup_bypass_ipv6"].FD()
	runtimeState.host_ipv4_map_fd = runtimeState.maps["cgroup_host_ipv4"].FD()
	runtimeState.host_ipv6_map_fd = runtimeState.maps["cgroup_host_ipv6"].FD()
	return nil
}

type cgroupUDPMapLayout struct {
	cleanupType  CiliumEBPF.MapType
	cleanupFlags uint32
	peerType     CiliumEBPF.MapType
	peerFlags    uint32
	peerCapacity uint32
	flowCapacity uint32
}

func cgroupUDPMapConfiguration(
	enableUDP bool,
	socketReleaseSupported bool,
	capacity CgroupMapCapacity,
) cgroupUDPMapLayout {
	layout := cgroupUDPMapLayout{
		cleanupType:  CiliumEBPF.Hash,
		cleanupFlags: bpfFlagNoPrealloc,
		peerType:     CiliumEBPF.Hash,
		peerFlags:    bpfFlagNoPrealloc,
		peerCapacity: 1,
		flowCapacity: 1,
	}
	if !enableUDP {
		return layout
	}
	layout.peerCapacity = capacity.UDPPeer
	layout.flowCapacity = capacity.UDPFlow
	if socketReleaseSupported {
		return layout
	}
	layout.cleanupType = CiliumEBPF.LRUHash
	layout.cleanupFlags = 0
	layout.peerType = CiliumEBPF.LRUHash
	layout.peerFlags = 0
	return layout
}

func validateCgroupUDPCleanupMaps(runtimeState *cgroupRuntime) error {
	if !runtimeState.enable_udp {
		return nil
	}
	expectedType := CiliumEBPF.LRUHash
	if runtimeState.socket_release_supported {
		expectedType = CiliumEBPF.Hash
	}
	for _, name := range []string{"cgroup_udp_redirect", "cgroup_udp_token", "cgroup_udp_token_reverse"} {
		mapInstance := runtimeState.maps[name]
		if mapInstance == nil {
			return E.New("missing UDP cleanup map ", name)
		}
		info, err := mapInstance.Info()
		if err != nil {
			return E.Cause(err, "inspect UDP cleanup map ", name)
		}
		if info.Type != expectedType {
			return E.New("invalid UDP cleanup map type for ", name, ": ", info.Type, ", expected ", expectedType)
		}
	}
	return nil
}

func probeSocketReleaseSupport(cgroupFD int) (bool, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:       "sb_rel_probe",
		Type:       CiliumEBPF.CGroupSock,
		AttachType: CiliumEBPF.AttachCgroupInetSockRelease,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
	})
	if err != nil {
		if socketReleaseProbeUnavailable(err) {
			return false, nil
		}
		return false, err
	}
	// Attach the probe alongside whatever is there, never in place of it. An
	// in-place attach would replace another owner's program on this hook, and
	// the detach below would then leave the hook empty. Where only that would
	// have worked, the refusal is EPERM and the probe reports the hook as
	// unavailable.
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  cgroupFD,
		Program: program,
		Attach:  CiliumEBPF.AttachCgroupInetSockRelease,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	})
	if err != nil {
		closeErr := program.Close()
		if socketReleaseProbeUnavailable(err) {
			return false, closeErr
		}
		return false, E.Errors(err, closeErr)
	}
	detachErr := rawDetachProgram(cgroupFD, program, CiliumEBPF.AttachCgroupInetSockRelease)
	closeErr := program.Close()
	if detachErr != nil {
		return false, E.Errors(detachErr, closeErr)
	}
	if closeErr != nil {
		return false, closeErr
	}
	return true, nil
}

// socketReleaseProbeUnavailable reports whether the probe found the socket-release
// hook unusable. The hook only speeds up UDP cleanup, the LRU maps work without
// it, so a permission refusal counts too: some Android kernels allow the cgroup
// data plane but reject this attach type with EPERM or EACCES (SELinux or a vendor
// policy). Treating that as fatal failed the whole cgroup inbound, TCP included.
// The required cgroup hooks still report permission errors to the caller.
func socketReleaseProbeUnavailable(err error) bool {
	return socketReleaseUnavailable(err) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

func socketReleaseUnavailable(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, linuxErrnoNotSupported)
}
