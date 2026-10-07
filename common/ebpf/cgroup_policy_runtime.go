//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"

	E "github.com/metacubex/sing/common/exceptions"
)

func validateCgroupMapCapacity(capacity CgroupMapCapacity) error {
	for name, value := range map[string]uint32{
		"tcp_redirect":  capacity.TCPRedirect,
		"udp_redirect":  capacity.UDPRedirect,
		"udp_peer":      capacity.UDPPeer,
		"udp_flow":      capacity.UDPFlow,
		"socket_bypass": capacity.SocketBypass,
	} {
		if value == 0 || value > MaxConfigurableMapCapacity {
			return E.New("invalid eBPF ", name, " map capacity: ", value)
		}
	}
	return nil
}

func (b *CgroupBackend) UpdateCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	if len(policy.ipv4) > maxBypassCIDRPolicyEntries || len(policy.ipv6) > maxBypassCIDRPolicyEntries {
		return false, E.New("eBPF cgroup bypass CIDR policy exceeds map capacity")
	}
	if err := checkLPMTriePolicyCompatibility("eBPF cgroup bypass CIDR", len(policy.ipv4)+len(policy.ipv6)); err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return false, err
	}
	previous := dualStackCIDRPrefixes{b.bypassIPv4CIDR, b.bypassIPv6CIDR}
	next := dualStackCIDRPrefixes{policy.ipv4, policy.ipv6}
	previousIPv4, previousIPv6 := b.runtime.bypass_ipv4_policy, b.runtime.bypass_ipv6_policy
	changed, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["cgroup_bypass_ipv4"],
		b.runtime.maps["cgroup_bypass_ipv6"],
		previous,
		next,
		"eBPF cgroup ", "bypass CIDR",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return false, E.Errors(err, b.health.invalidate("cgroup", "bypass CIDR policy"))
		}
		return false, err
	}
	b.bypassIPv4CIDR = slices.Clone(policy.ipv4)
	b.bypassIPv6CIDR = slices.Clone(policy.ipv6)
	b.runtime.bypass_ipv4_policy = len(policy.ipv4) > 0 && b.redirectIPv4.IsValid()
	b.runtime.bypass_ipv6_policy = len(policy.ipv6) > 0 && b.redirectIPv6.IsValid()
	flagsChanged := previousIPv4 != b.runtime.bypass_ipv4_policy || previousIPv6 != b.runtime.bypass_ipv6_policy
	if flagsChanged && b.listenerPort != 0 {
		if err = b.updateCgroupControl(b.listenerPort); err != nil {
			_, rollbackErr := replaceDualStackCIDRPolicy(
				b.runtime.maps["cgroup_bypass_ipv4"], b.runtime.maps["cgroup_bypass_ipv6"],
				next, previous, "eBPF cgroup ", "bypass CIDR rollback",
			)
			b.bypassIPv4CIDR, b.bypassIPv6CIDR = previous.ipv4, previous.ipv6
			b.runtime.bypass_ipv4_policy, b.runtime.bypass_ipv6_policy = previousIPv4, previousIPv6
			if rollbackErr != nil {
				return false, E.Errors(err, rollbackErr, b.health.invalidate("cgroup", "bypass CIDR control"))
			}
			return false, E.Cause(err, "update cgroup bypass CIDR control")
		}
	}
	return changed, nil
}

func (b *CgroupBackend) BypassCIDRCount() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.bypassIPv4CIDR), len(b.bypassIPv6CIDR)
}

func (b *CgroupBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileHostAddresses(addresses)
	if len(ipv4) > maxHostAddressPolicyEntries || len(ipv6) > maxHostAddressPolicyEntries {
		return E.New("eBPF cgroup host address policy exceeds map capacity")
	}
	ipv4Prefixes := make([]netip.Prefix, len(ipv4))
	for index, address := range ipv4 {
		ipv4Prefixes[index] = netip.PrefixFrom(netip.AddrFrom4(address), 32)
	}
	ipv6Prefixes := make([]netip.Prefix, len(ipv6))
	for index, address := range ipv6 {
		ipv6Prefixes[index] = netip.PrefixFrom(netip.AddrFrom16(address), 128)
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	previous := dualStackCIDRPrefixes{b.hostIPv4, b.hostIPv6}
	next := dualStackCIDRPrefixes{ipv4Prefixes, ipv6Prefixes}
	changed, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["cgroup_host_ipv4"],
		b.runtime.maps["cgroup_host_ipv6"],
		previous,
		next,
		"eBPF cgroup ", "host address",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return E.Errors(err, b.health.invalidate("cgroup", "host address policy"))
		}
		return err
	}
	b.hostIPv4 = slices.Clone(ipv4Prefixes)
	b.hostIPv6 = slices.Clone(ipv6Prefixes)
	if changed && b.listenerPort != 0 {
		if err = b.updateCgroupControl(b.listenerPort); err != nil {
			_, rollbackErr := replaceDualStackCIDRPolicy(
				b.runtime.maps["cgroup_host_ipv4"],
				b.runtime.maps["cgroup_host_ipv6"],
				next,
				previous,
				"eBPF cgroup ", "host address rollback",
			)
			b.hostIPv4 = slices.Clone(previous.ipv4)
			b.hostIPv6 = slices.Clone(previous.ipv6)
			if rollbackErr != nil {
				return E.Errors(err, rollbackErr, b.health.invalidate("cgroup", "host address control"))
			}
			return E.Cause(err, "update cgroup host address control")
		}
	}
	return nil
}

// CgroupPolicyCapacity is intentionally fixed for the optional backend. The
// local data-plane selector must not add another user-facing tuning surface.
func cgroupPolicyCapacity() CgroupMapCapacity {
	return DefaultCgroupMapCapacity()
}
