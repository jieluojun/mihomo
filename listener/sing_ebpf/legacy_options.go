//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"fmt"
	"time"

	LC "github.com/metacubex/mihomo/listener/config"

	E "github.com/metacubex/sing/common/exceptions"
)

// minimumUDPTimeout bounds udp-timeout from below. The UDP session tables and
// the eBPF flow state derive their sweep cadence from it, so a tiny value would
// evict live sessions before their first packet could refresh them.
const minimumUDPTimeout = 5 * time.Second

// maximumStateCapacity mirrors the cap the eBPF map layout accepts.
const maximumStateCapacity = 1 << 20

// resolveUDPTimeout reads udp-timeout the way every other listener does: as a
// number of seconds.
//
// Reading the value as a raw time.Duration would interpret it as nanoseconds:
// `udp-timeout: 300` became 300ns, which made every sweep tick consider every
// client idle and tear down live UDP sessions (and their eBPF redirects) a few
// seconds after they were established. The floor keeps a hand-written tiny
// value from degenerating the sweeper the same way.
func resolveUDPTimeout(configured int64) time.Duration {
	if configured <= 0 {
		return 5 * time.Minute
	}
	timeout := time.Second * time.Duration(configured)
	if timeout < minimumUDPTimeout {
		return minimumUDPTimeout
	}
	return timeout
}

// applyLegacyOptions folds the pre-rework option surface into the current one
// so a config written against the earlier `type: ebpf` listener keeps working
// unchanged. It reports the adjustments worth telling the user about, and
// rejects values that can no longer mean anything.
//
// The old surface had dns-mode and bypass-private-address at the top level,
// `ipv6-mode: auto|always|off` strings in both sections, `state-capacity` per
// section, and `shared.advanced.tc-priority`. Each is mapped onto its current
// equivalent only when the new key is unset, so a config that already uses the
// new keys is never overridden by a leftover legacy one.
func applyLegacyOptions(options LC.EBPF) (LC.EBPF, []string, error) {
	var notes []string
	options, err := resolveEnableAliases(options)
	if err != nil {
		return options, nil, err
	}
	_, localEnabled, sharedEnabled, err := normalizeModeWithEnabled(options.Mode, options.Local.Enabled, options.Shared.Enabled)
	if err != nil {
		// New reports the mode error itself; there is nothing to fold.
		return options, nil, nil
	}
	// Disabled scopes may still contain a complete configuration template.
	// Keep only the selector before converting or validating legacy settings.
	if !localEnabled {
		options.Local = LC.EBPFLocal{Enabled: options.Local.Enabled}
	}
	if !sharedEnabled {
		options.Shared = LC.EBPFShared{Enabled: options.Shared.Enabled}
	}
	if options.DNSMode != "" {
		if localEnabled && options.Local.DNSMode == "" {
			options.Local.DNSMode = options.DNSMode
		}
		if sharedEnabled && options.Shared.DNSMode == "" {
			options.Shared.DNSMode = options.DNSMode
		}
	}
	if options.BypassPrivateAddress != nil {
		if localEnabled && options.Local.BypassPrivateAddress == nil {
			options.Local.BypassPrivateAddress = options.BypassPrivateAddress
		}
		if sharedEnabled && options.Shared.BypassPrivateAddress == nil {
			options.Shared.BypassPrivateAddress = options.BypassPrivateAddress
		}
	}
	if options.Local.IPv6Mode != "" {
		enabled, note, err := legacyIPv6Mode("local", options.Local.IPv6Mode, true)
		if err != nil {
			return options, nil, err
		}
		if localEnabled && options.Local.IPv6 == nil {
			options.Local.IPv6 = &enabled
			if note != "" {
				notes = append(notes, note)
			}
		}
	}
	if options.Shared.IPv6Mode != "" {
		enabled, note, err := legacyIPv6Mode("shared", options.Shared.IPv6Mode, false)
		if err != nil {
			return options, nil, err
		}
		if sharedEnabled && options.Shared.IPv6 == nil {
			options.Shared.IPv6 = &enabled
			if note != "" {
				notes = append(notes, note)
			}
		}
	}
	if options.Local.StateCapacity > maximumStateCapacity {
		return options, nil, E.New("local.state-capacity exceeds ", maximumStateCapacity)
	}
	if options.Shared.StateCapacity > maximumStateCapacity {
		return options, nil, E.New("shared.state-capacity exceeds ", maximumStateCapacity)
	}
	advanced := options.Shared.Advanced
	if advanced.TCPriority != 0 && options.TCPriority == 0 {
		options.TCPriority = advanced.TCPriority
	}
	if advanced.DataPlane != "" && options.Shared.DataPlane == "" {
		switch advanced.DataPlane {
		case "packet_rewrite", "packet-rewrite", "rewrite":
			options.Shared.DataPlane = sharedDataPlanePacketRewrite
		case "socket_assign", "socket-assign", "assign":
			options.Shared.DataPlane = sharedDataPlaneSocketAssign
		default:
			notes = append(notes, fmt.Sprintf("shared.advanced.data-plane %q is not a known data plane and was ignored; use shared.data-plane: packet_rewrite or socket_assign", advanced.DataPlane))
		}
	}
	if advanced.RoutingMark != 0 || advanced.RoutingTable != 0 {
		notes = append(notes, "shared.advanced.routing-mark and routing-table are ignored: the policy-routing mark and table are now allocated automatically from the unused ones")
	}
	if options.TCPSplice {
		notes = append(notes, "tcp-splice is ignored: the kernel TCP splice fast path was removed with the unified TC data plane")
	}
	return options, notes, nil
}

// legacyIPv6Mode maps the old three-state string onto the current boolean. The
// old `auto` probed the host for IPv6 connectivity before enabling
// interception; the current backend does not probe, so `auto` becomes enabled
// and says so once.
func legacyIPv6Mode(section string, mode string, allowAuto bool) (bool, string, error) {
	switch mode {
	case "off":
		return false, "", nil
	case "always":
		return true, "", nil
	case "auto":
		if !allowAuto {
			break
		}
		return true, section + ".ipv6-mode: auto is no longer probed; IPv6 interception is enabled. Set " + section + ".ipv6: false to turn it off", nil
	}
	return false, "", E.New("unknown ", section, ".ipv6-mode: ", mode)
}

// resolveBypassTUNDirect reads bypass-tun-direct with its default applied. On
// by default: a destination this inbound bypasses is one the user asked to keep
// off the proxy, and letting TUN hand it to the rules instead is what makes a
// bypassed address unreachable.
func resolveBypassTUNDirect(configured *bool) bool {
	return configured == nil || *configured
}
