//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"reflect"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

func boolPtr(v bool) *bool { return &v }

func TestSharedIgnoresDisabledLocalTemplate(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		options := LC.EBPF{Mode: "shared", Local: LC.EBPFLocal{
			DNSMode: "invalid", DataPlane: "invalid", CgroupPath: "relative",
			IPv6Mode: "invalid", StateCapacity: maximumStateCapacity + 1,
			BypassPortRange: []string{"invalid"}, IncludeUIDRange: []string{"invalid"},
			IncludePackage: []string{"android-only"}, BypassRuleSet: []string{"missing"},
		}}
		if explicit {
			options.Mode = ""
			options.Local.Enable = boolPtr(false)
			options.Shared.Enable = boolPtr(true)
		}
		normalized, notes, err := applyLegacyOptions(options)
		if err != nil || len(notes) != 0 {
			t.Fatalf("disabled template validated: %v, %v", err, notes)
		}
		if !reflect.DeepEqual(normalized.Local, LC.EBPFLocal{Enabled: normalized.Local.Enabled}) {
			t.Fatalf("disabled local retained: %+v", normalized.Local)
		}
		selection, err := normalizeDataPlanes(normalized)
		if err != nil || selection.localEnabled || !selection.sharedEnabled {
			t.Fatalf("selection=%+v, %v", selection, err)
		}
	}
	if _, _, err := applyLegacyOptions(LC.EBPF{Mode: "local", Local: LC.EBPFLocal{IPv6Mode: "invalid"}}); err == nil {
		t.Fatal("enabled local scope stopped validating legacy options")
	}
}

func TestEnablementModeLocal(t *testing.T) {
	// mode: local only -> local enabled, shared disabled
	sel, err := normalizeDataPlanes(LC.EBPF{Mode: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.localEnabled || sel.sharedEnabled {
		t.Fatalf("mode=local: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
	if sel.localDataPlane != localDataPlaneCgroup {
		t.Fatalf("mode=local default data plane = %q", sel.localDataPlane)
	}
}

func TestEnablementLocalEnabledField(t *testing.T) {
	// local.enabled: true, no shared -> local only
	sel, err := normalizeDataPlanes(LC.EBPF{
		Local: LC.EBPFLocal{Enabled: boolPtr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.localEnabled || sel.sharedEnabled {
		t.Fatalf("local.enabled=true: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
}

func TestEnablementSharedEnabledField(t *testing.T) {
	// shared.enabled: true + interface -> shared only (no local)
	sel, err := normalizeDataPlanes(LC.EBPF{
		Shared: LC.EBPFShared{Enabled: boolPtr(true), Interface: []string{"wlan2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sel.localEnabled || !sel.sharedEnabled {
		t.Fatalf("shared.enabled=true: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
	if sel.sharedDataPlane != sharedDataPlanePacketRewrite {
		t.Fatalf("shared default data plane = %q", sel.sharedDataPlane)
	}
}

func TestValidateSharedDisabledNoConfig(t *testing.T) {
	// mode=local with empty shared block should NOT error
	var shared LC.EBPFShared
	if err := validateSharedOptions(false, shared); err != nil {
		t.Fatalf("empty shared config with shared disabled should pass: %v", err)
	}
}

// Box may inject shared options even when only local interception is selected.
func TestLocalIgnoresSharedOptions(t *testing.T) {
	for _, mode := range []string{"local", "", "enabled"} {
		t.Run(mode, func(t *testing.T) {
			options := LC.EBPF{Mode: mode, Shared: LC.EBPFShared{
				IPv6: boolPtr(true), DNSMode: "invalid", Interface: []string{"lo"},
				DataPlane: "invalid", IPv6Mode: "invalid", StateCapacity: maximumStateCapacity + 1,
				BypassPortRange: []string{"invalid"}, IncludeMACAddress: []string{"invalid"},
				Advanced: LC.EBPFSharedAdvanced{TCPriority: 99, DataPlane: "invalid"},
			}}
			if mode == "enabled" {
				options.Mode = ""
				options.Local.Enabled = boolPtr(true)
				options.Shared.Enabled = boolPtr(false)
			}
			normalized, notes, err := applyLegacyOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normalized.Shared, LC.EBPFShared{Enabled: options.Shared.Enabled}) {
				t.Fatalf("disabled shared options retained: %+v", normalized.Shared)
			}
			if normalized.TCPriority != 0 || len(notes) != 0 {
				t.Fatalf("disabled shared options affected legacy conversion: %+v %v", normalized, notes)
			}
			selection, err := normalizeDataPlanes(normalized)
			if err != nil {
				t.Fatal(err)
			}
			if !selection.localEnabled || selection.sharedEnabled {
				t.Fatalf("unexpected selection: %+v", selection)
			}
			if err := validateSharedOptions(false, normalized.Shared); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActiveSharedOptionsRemainValidated(t *testing.T) {
	for _, mode := range []string{"shared", "hybrid"} {
		t.Run(mode, func(t *testing.T) {
			options, _, err := applyLegacyOptions(LC.EBPF{Mode: mode, Shared: LC.EBPFShared{IPv6: boolPtr(true)}})
			if err != nil {
				t.Fatal(err)
			}
			if options.Shared.IPv6 == nil {
				t.Fatal("active shared options were discarded")
			}
			if _, err := normalizeSharedOptions(options.Shared); err == nil {
				t.Fatal("missing shared.interface accepted")
			}
			options.Shared.IPv6Mode = "invalid"
			if _, _, err := applyLegacyOptions(options); err == nil {
				t.Fatal("invalid active shared legacy option accepted")
			}
		})
	}
}
