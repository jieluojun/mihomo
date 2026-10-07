//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	E "github.com/metacubex/sing/common/exceptions"
)

const maxBypassExcludeEntries = 4096

// Exclusions use separate immutable LPM tables. DNS can replace its fake-IP
// ranges without overwriting these tables or the ICMP responder's ranges.
func compileBypassExclude(prefixes []netip.Prefix) (dualStackCIDRPrefixes, error) {
	for _, prefix := range prefixes {
		if !prefix.IsValid() || (prefix.Addr().Is4In6() && prefix.Bits() < 96) {
			return dualStackCIDRPrefixes{}, E.New("invalid bypass-exclude prefix: ", prefix)
		}
	}
	ipv4, ipv6, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return dualStackCIDRPrefixes{}, err
	}
	if len(ipv4) > maxBypassExcludeEntries || len(ipv6) > maxBypassExcludeEntries {
		return dualStackCIDRPrefixes{}, E.New("bypass-exclude exceeds map capacity")
	}
	return dualStackCIDRPrefixes{ipv4: ipv4, ipv6: ipv6}, nil
}
