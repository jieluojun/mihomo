//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"

	"go4.org/netipx"
)

// Publication is global to TUN/DNS, so a force-intercept request in either
// enabled scope must win over the union of their bypasses. Kernel bypass maps
// stay scope-specific; their independent force tables decide per packet.
func (i *Inbound) excludeForcedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(i.localBypassExclude) == 0 && len(i.sharedBypassExclude) == 0 {
		return prefixes
	}
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	for _, scope := range []struct {
		enabled  bool
		prefixes []netip.Prefix
	}{
		{i.localEnabled, i.localBypassExclude}, {i.sharedEnabled, i.sharedBypassExclude},
	} {
		if !scope.enabled {
			continue
		}
		for _, prefix := range scope.prefixes {
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			builder.RemovePrefix(prefix.Masked())
		}
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil
	} // Never publish an unsafe direct exception.
	return set.Prefixes()
}
