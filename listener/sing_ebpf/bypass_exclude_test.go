//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"

	"go4.org/netipx"
)

func TestForcedPrefixesLeaveDNSAndTUNBypass(t *testing.T) {
	i := &Inbound{localEnabled: true, sharedEnabled: true, localBypassExclude: []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.0.0/106")}, sharedBypassExclude: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::/48")}}
	input := []netip.Prefix{netip.MustParsePrefix("100.0.0.0/8"), netip.MustParsePrefix("fc00::/7")}
	var builder netipx.IPSetBuilder
	for _, prefix := range i.excludeForcedPrefixes(input) {
		builder.AddPrefix(prefix)
	}
	set, err := builder.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"100.64.0.1", "fd7a:115c:a1e0::1"} {
		if set.Contains(netip.MustParseAddr(ip)) {
			t.Fatalf("forced address %s still bypassed", ip)
		}
	}
	if !set.Contains(netip.MustParseAddr("100.1.1.1")) || !set.Contains(netip.MustParseAddr("fd00::1")) {
		t.Fatal("unrelated bypass lost")
	}
	i.localEnabled = false
	if got := i.excludeForcedPrefixes([]netip.Prefix{input[0]}); len(got) != 1 || got[0] != input[0] {
		t.Fatal("disabled local scope affected publication")
	}
}

func TestDisabledScopeIgnoresInvalidBypassExclude(t *testing.T) {
	for _, mode := range []string{"local", "shared"} {
		options := LC.EBPF{Mode: mode}
		if mode == "local" {
			options.Shared.BypassExclude = []netip.Prefix{{}}
		} else {
			options.Local.BypassExclude = []netip.Prefix{{}}
		}
		got, _, err := applyLegacyOptions(options)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Local.BypassExclude) != 0 || len(got.Shared.BypassExclude) != 0 {
			t.Fatal("disabled exclusions were retained")
		}
	}
}
