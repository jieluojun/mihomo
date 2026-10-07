package inbound

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_ebpf"
)

// inPlaceUpdatableFields is the allowlist the listener claims to support. The
// reflection test below holds withoutInPlaceUpdatableFields to exactly this.
var inPlaceUpdatableFields = []string{"UDPTimeout", "BypassRuleSet", "BypassTUNDirect"}

type stubEBPFListener struct {
	updates int
	applied LC.EBPF
	err     error
}

func (s *stubEBPFListener) Close() error    { return nil }
func (s *stubEBPFListener) Address() string { return "" }

func (s *stubEBPFListener) Update(options LC.EBPF) error {
	s.updates++
	if s.err != nil {
		return s.err
	}
	s.applied = options
	return nil
}

var _ sing_ebpf.Listener = (*stubEBPFListener)(nil)

// baseEBPFOption sets every field to something non-zero. The allowlist test
// cannot tell a cleared field from an empty one, so an option with holes in it
// would pass however the clearing was written.
func baseEBPFOption() *EBPFOption {
	enabled := true
	return &EBPFOption{
		BaseOption:           BaseOption{NameStr: "ebpf-in", Listen: "0.0.0.0", SpecialProxy: "DIRECT"},
		Mode:                 "hybrid",
		Network:              []string{"tcp", "udp"},
		UDPTimeout:           300,
		TCPriority:           1,
		BypassRuleSet:        []string{"ChinaIP"},
		FakeIPICMP:           "reply",
		BypassTUNDirect:      &enabled,
		DNSMode:              "hijack",
		BypassPrivateAddress: &enabled,
		TCPSplice:            true,
		Local:                LC.EBPFLocal{CgroupPath: "/sys/fs/cgroup"},
		Shared:               LC.EBPFShared{Interface: []string{"wlan2"}},
	}
}

func runningEBPF(t *testing.T, options *EBPFOption) (*EBPF, *stubEBPFListener) {
	t.Helper()
	listener, err := NewEBPF(options)
	if err != nil {
		t.Fatalf("build listener: %v", err)
	}
	stub := &stubEBPFListener{}
	listener.l = stub
	return listener, stub
}

// Nothing reaches the in-place path by accident. The comparison clears the
// updatable fields and demands everything else match, so a field added to
// EBPFOption later takes part in the comparison and forces a rebuild until
// someone classifies it -- and this test fails the moment the two disagree.
func TestEBPFUpdateClearsExactlyTheFieldsItCanApply(t *testing.T) {
	cleared := withoutInPlaceUpdatableFields(*baseEBPFOption())
	clearedValue := reflect.ValueOf(cleared)
	populated := reflect.ValueOf(*baseEBPFOption())
	optionType := reflect.TypeOf(EBPFOption{})

	var seen []string
	for index := range optionType.NumField() {
		name := optionType.Field(index).Name
		if populated.Field(index).IsZero() {
			t.Fatalf("baseEBPFOption leaves %s zero, so this test cannot tell whether it is cleared", name)
		}
		wasCleared := clearedValue.Field(index).IsZero()
		if wasCleared {
			seen = append(seen, name)
		}
		if want := slices.Contains(inPlaceUpdatableFields, name); wasCleared != want {
			t.Fatalf("%s cleared=%v, want %v -- the allowlist and the clearing disagree", name, wasCleared, want)
		}
	}
	if !slices.Equal(seen, inPlaceUpdatableFields) {
		t.Fatalf("cleared %v, want exactly %v", seen, inPlaceUpdatableFields)
	}
}

func TestEBPFUpdateAppliesTheFieldsItCan(t *testing.T) {
	listener, stub := runningEBPF(t, baseEBPFOption())

	changed := baseEBPFOption()
	changed.UDPTimeout = 600
	handled, err := listener.Update(changed)
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if !handled {
		t.Fatal("a udp-timeout change was refused, so the inbound is rebuilt and every established redirect breaks")
	}
	if stub.applied.UDPTimeout != 600 {
		t.Fatalf("applied udp-timeout = %d, want 600", stub.applied.UDPTimeout)
	}
	if listener.Config().(*EBPFOption).UDPTimeout != 600 {
		t.Fatal("the listener still answers for its old config, so every later reload re-applies the same change")
	}
}

// The per-scope bypass-rule-set keys go in place like the top-level one. Only
// that key is cleared inside each section, so the rest of a section still
// forces a rebuild; see "local section" below.
func TestEBPFUpdateAppliesScopedBypassRuleSets(t *testing.T) {
	listener, stub := runningEBPF(t, baseEBPFOption())

	changed := baseEBPFOption()
	changed.Local.BypassRuleSet = []string{"LAN"}
	changed.Shared.BypassRuleSet = []string{"ChinaIP"}
	handled, err := listener.Update(changed)
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if !handled {
		t.Fatal("a per-scope bypass-rule-set change was refused, so the inbound is rebuilt")
	}
	if !slices.Equal(stub.applied.Local.BypassRuleSet, []string{"LAN"}) ||
		!slices.Equal(stub.applied.Shared.BypassRuleSet, []string{"ChinaIP"}) {
		t.Fatalf("applied local=%v shared=%v", stub.applied.Local.BypassRuleSet, stub.applied.Shared.BypassRuleSet)
	}
}

func TestEBPFUpdateRefusesWhatItCannotApply(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*EBPFOption)
	}{
		{name: "mode", mutate: func(o *EBPFOption) { o.Mode = "local" }},
		{name: "network", mutate: func(o *EBPFOption) { o.Network = []string{"tcp"} }},
		{name: "tc-priority", mutate: func(o *EBPFOption) { o.TCPriority = 7 }},
		{name: "fakeip-icmp", mutate: func(o *EBPFOption) { o.FakeIPICMP = "off" }},
		{name: "local section", mutate: func(o *EBPFOption) { o.Local.CgroupPath = "/elsewhere" }},
		{name: "shared section", mutate: func(o *EBPFOption) { o.Shared.Interface = []string{"wlan0"} }},
		{name: "local bypass-exclude", mutate: func(o *EBPFOption) { o.Local.BypassExclude = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")} }},
		{name: "shared bypass-exclude", mutate: func(o *EBPFOption) {
			o.Shared.BypassExclude = []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::/48")}
		}},
		{name: "base option", mutate: func(o *EBPFOption) { o.SpecialProxy = "REJECT" }},
		{name: "an updatable field alongside one that is not", mutate: func(o *EBPFOption) {
			o.UDPTimeout = 600
			o.Mode = "local"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			listener, stub := runningEBPF(t, baseEBPFOption())
			changed := baseEBPFOption()
			testCase.mutate(changed)

			handled, err := listener.Update(changed)
			if err != nil {
				t.Fatalf("a refusal reported an error: %v", err)
			}
			if handled {
				t.Fatal("a change needing a rebuild was reported as handled, so it is silently never applied")
			}
			if stub.updates != 0 {
				t.Fatal("the data plane was asked to apply a change that needs a rebuild")
			}
		})
	}
}

// Adding a tag to a list that already has one keeps the backend's map sizing
// valid, so it does not need the rebuild an empty-to-non-empty change does.
func TestEBPFUpdateTakesARuleSetAddedToAnExistingList(t *testing.T) {
	listener, stub := runningEBPF(t, baseEBPFOption())

	changed := baseEBPFOption()
	changed.BypassRuleSet = []string{"ChinaIP", "MetaCN"}
	handled, err := listener.Update(changed)
	if err != nil || !handled {
		t.Fatalf("update reported handled=%v err=%v", handled, err)
	}
	if !slices.Equal(stub.applied.BypassRuleSet, []string{"ChinaIP", "MetaCN"}) {
		t.Fatalf("applied bypass_rule_set = %v", stub.applied.BypassRuleSet)
	}
}

// A data plane can refuse a change for a reason this layer cannot see -- which
// planes are running at all. That is a rebuild, not a failure: no error is
// logged and the caller does exactly what it would have without an Update.
func TestEBPFUpdateTreatsARebuildRequestAsUnhandled(t *testing.T) {
	listener, stub := runningEBPF(t, baseEBPFOption())
	stub.err = sing_ebpf.ErrRebuildRequired

	changed := baseEBPFOption()
	changed.UDPTimeout = 600
	handled, err := listener.Update(changed)
	if err != nil {
		t.Fatalf("a rebuild request was reported as a failure: %v", err)
	}
	if handled {
		t.Fatal("a rebuild request was reported as handled, so the change is silently never applied")
	}
	if listener.Config().(*EBPFOption).UDPTimeout != 300 {
		t.Fatal("a refused update adopted the config it did not apply")
	}
}

// A failed update must leave the listener answering for the config it is still
// running, so the caller's rebuild starts from the truth.
func TestEBPFUpdateKeepsTheOldConfigWhenItFails(t *testing.T) {
	listener, stub := runningEBPF(t, baseEBPFOption())
	stub.err = errors.New("map is full")

	changed := baseEBPFOption()
	changed.UDPTimeout = 600
	handled, err := listener.Update(changed)
	if handled || err == nil {
		t.Fatalf("a failed update reported handled=%v err=%v", handled, err)
	}
	if listener.Config().(*EBPFOption).UDPTimeout != 300 {
		t.Fatal("a failed update adopted the config it did not apply")
	}
}
