//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// netdAttachFixture reproduces an Android 15+ root hook: the kernel rejects
// every multi-program attach with EPERM and the hook holds one program in
// single-program (or override) mode.
type netdAttachFixture struct {
	flags      []uint32
	ownerCalls int
	detached   int
}

type ownerFinder func(CiliumEBPF.AttachType, CiliumEBPF.ProgramID, uint32) (*displacedCgroupOwner, error)

const netdPlaceholderTestName = "connect4_inet4_connect_4_19_v"

func installNetdAttachFixture(t *testing.T, owners []link.AttachedProgram, hookFlags uint32, find ownerFinder) *netdAttachFixture {
	t.Helper()
	fixture := &netdAttachFixture{}
	originalRawAttachProgram := rawAttachProgram
	originalRawDetachProgram := rawDetachProgram
	originalQuery := queryCgroupPrograms
	originalFlags := queryCgroupHookFlags
	originalFind := findDisplaceableOwner
	originalProgramNameByID := programNameByID
	t.Cleanup(func() {
		rawAttachProgram = originalRawAttachProgram
		rawDetachProgram = originalRawDetachProgram
		queryCgroupPrograms = originalQuery
		queryCgroupHookFlags = originalFlags
		findDisplaceableOwner = originalFind
		programNameByID = originalProgramNameByID
	})
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		fixture.flags = append(fixture.flags, current.Flags)
		if current.Flags&unix.BPF_F_ALLOW_MULTI != 0 {
			return unix.EPERM
		}
		return nil
	}
	rawDetachProgram = func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error {
		fixture.detached++
		return nil
	}
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{Programs: owners}, nil
	}
	queryCgroupHookFlags = func(int, CiliumEBPF.AttachType) (uint32, error) {
		return hookFlags, nil
	}
	findDisplaceableOwner = func(attachType CiliumEBPF.AttachType, ownerID CiliumEBPF.ProgramID, flags uint32) (*displacedCgroupOwner, error) {
		fixture.ownerCalls++
		return find(attachType, ownerID, flags)
	}
	// Not an interception program name, so the stale-program cleanup that
	// precedes the owner check leaves it alone.
	programNameByID = func(CiliumEBPF.ProgramID) (string, error) {
		return netdPlaceholderTestName, nil
	}
	return fixture
}

func passThroughOwner33(_ CiliumEBPF.AttachType, ownerID CiliumEBPF.ProgramID, flags uint32) (*displacedCgroupOwner, error) {
	if ownerID == 33 {
		return &displacedCgroupOwner{id: 33, flags: flags}, nil
	}
	return nil, errCgroupOwnerHasEffect
}

// The failure this reproduces: "attach eBPF cgroup programs: sb_ebpf_conn4:
// refusing to replace existing cgroup program owner(s):
// connect4_inet4_connect_4_19_v" on Android 15, where netd's placeholder must
// be replaced and handed back. The replacement uses the hook's own flags so the
// kernel swaps the program instead of refusing.
func TestRawCgroupAttachReplacesPassThroughOwner(t *testing.T) {
	for _, hookFlags := range []uint32{0, unix.BPF_F_ALLOW_OVERRIDE} {
		fixture := installNetdAttachFixture(t, []link.AttachedProgram{{ID: 33}}, hookFlags, passThroughOwner33)
		attachment, err := attachProgramRawWithMode(42, nil, CiliumEBPF.AttachCGroupInet4Connect, true)
		if err != nil {
			t.Fatal(err)
		}
		if attachment.mode != cgroupAttachModeNetdReplace {
			t.Fatalf("mode = %q, want %q", attachment.mode, cgroupAttachModeNetdReplace)
		}
		if attachment.displaced == nil || attachment.displaced.id != 33 || attachment.displaced.flags != hookFlags {
			t.Fatalf("displaced owner = %+v, want program 33 with flags %#x", attachment.displaced, hookFlags)
		}
		if !slices.Equal(fixture.flags, []uint32{unix.BPF_F_ALLOW_MULTI, hookFlags}) {
			t.Fatalf("flags=%v, want the multi attempt and then a replacement with %#x", fixture.flags, hookFlags)
		}
		if fixture.detached != 0 {
			t.Fatalf("detached %d programs, want the foreign owner left to the replacement", fixture.detached)
		}
	}
}

// Optional components fall back to userspace instead. A program of theirs in
// netd's place would be an owner the interception backend has to refuse.
func TestRawCgroupAttachOfOptionalComponentKeepsPassThroughOwner(t *testing.T) {
	fixture := installNetdAttachFixture(t, []link.AttachedProgram{{ID: 33}}, 0, passThroughOwner33)
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err == nil {
		t.Fatal("an optional component replaced the pass-through owner")
	}
	if !strings.Contains(err.Error(), netdPlaceholderTestName) {
		t.Fatalf("error %q does not name the owner", err)
	}
	if fixture.ownerCalls != 0 {
		t.Fatalf("owner inspected %d times, want none", fixture.ownerCalls)
	}
	if !slices.Equal(fixture.flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only the non-destructive multi attach", fixture.flags)
	}
}

func TestRawCgroupAttachKeepsOwnersThatAreNotPassThrough(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		owners        []link.AttachedProgram
		hookFlags     uint32
		attachType    CiliumEBPF.AttachType
		wantLookup    bool
		wantDetailErr error
	}{
		{
			name:          "owner with real work",
			owners:        []link.AttachedProgram{{ID: 57}},
			attachType:    CiliumEBPF.AttachCGroupInet4Connect,
			wantLookup:    true,
			wantDetailErr: errCgroupOwnerHasEffect,
		},
		{
			name:       "two owners on an override hook",
			owners:     []link.AttachedProgram{{ID: 33}, {ID: 34}},
			hookFlags:  unix.BPF_F_ALLOW_OVERRIDE,
			attachType: CiliumEBPF.AttachCGroupInet4Connect,
		},
		{
			name:       "multi-program hook",
			owners:     []link.AttachedProgram{{ID: 33}},
			hookFlags:  unix.BPF_F_ALLOW_MULTI,
			attachType: CiliumEBPF.AttachCGroupInet4Connect,
		},
		{
			name:       "socket-release hook",
			owners:     []link.AttachedProgram{{ID: 33}},
			attachType: CiliumEBPF.AttachCgroupInetSockRelease,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := installNetdAttachFixture(t, testCase.owners, testCase.hookFlags, passThroughOwner33)
			_, err := attachProgramRawWithMode(42, nil, testCase.attachType, true)
			if err == nil || !strings.Contains(err.Error(), "refusing to replace existing cgroup program owner") {
				t.Fatalf("error = %v, want the owner kept", err)
			}
			if !slices.Equal(fixture.flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
				t.Fatalf("flags=%v, want only the non-destructive multi attach", fixture.flags)
			}
			if (fixture.ownerCalls > 0) != testCase.wantLookup {
				t.Fatalf("owner inspections = %d, want inspection %v", fixture.ownerCalls, testCase.wantLookup)
			}
			if testCase.wantDetailErr != nil {
				if !errors.Is(err, testCase.wantDetailErr) {
					t.Fatalf("error %v does not wrap %v", err, testCase.wantDetailErr)
				}
				if !strings.Contains(err.Error(), testCase.wantDetailErr.Error()) {
					t.Fatalf("error %q does not explain the refusal", err)
				}
			}
			if !strings.Contains(err.Error(), netdPlaceholderTestName) {
				t.Fatalf("error %q does not name the owner", err)
			}
		})
	}
}

func TestRestoreDisplacedCgroupOwner(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		owners       []link.AttachedProgram
		queryErr     error
		oursIsOwner  bool
		hookFlags    uint32
		wantAttach   bool
		wantDetached int
	}{
		{name: "our program still holds the hook", owners: []link.AttachedProgram{{ID: 7}}, oursIsOwner: true, wantAttach: true},
		{name: "override hook", owners: []link.AttachedProgram{{ID: 7}}, oursIsOwner: true, hookFlags: unix.BPF_F_ALLOW_OVERRIDE, wantAttach: true},
		{name: "hook is empty", wantAttach: true},
		{name: "another program replaced ours", owners: []link.AttachedProgram{{ID: 8}}},
		{name: "two programs on the hook", owners: []link.AttachedProgram{{ID: 7}, {ID: 8}}, oursIsOwner: true},
		{name: "hook cannot be queried", queryErr: unix.EINVAL, wantAttach: true, wantDetached: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := installNetdAttachFixture(t, nil, 0, passThroughOwner33)
			originalProgramHasID := programHasID
			t.Cleanup(func() { programHasID = originalProgramHasID })
			programHasID = func(*CiliumEBPF.Program, CiliumEBPF.ProgramID) bool { return testCase.oursIsOwner }
			queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
				if testCase.queryErr != nil {
					return nil, testCase.queryErr
				}
				return &link.QueryResult{Programs: testCase.owners}, nil
			}
			displaced := &displacedCgroupOwner{id: 33, flags: testCase.hookFlags}
			if err := restoreDisplacedCgroupOwner(42, nil, displaced, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
				t.Fatal(err)
			}
			var wantFlags []uint32
			if testCase.wantAttach {
				wantFlags = []uint32{testCase.hookFlags}
			}
			if !slices.Equal(fixture.flags, wantFlags) {
				t.Fatalf("attach flags = %v, want %v", fixture.flags, wantFlags)
			}
			if fixture.detached != testCase.wantDetached {
				t.Fatalf("detached %d times, want %d", fixture.detached, testCase.wantDetached)
			}
		})
	}
}

// newDisplacingTestBackend returns a backend whose connect4 program holds a
// hook it took over from netd, without any kernel object.
func newDisplacingTestBackend(t *testing.T) *CgroupBackend {
	t.Helper()
	cgroupFile, err := os.Create(filepath.Join(t.TempDir(), "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cgroupFile.Close() })
	backend := &CgroupBackend{runtime: &cgroupRuntime{
		cgroupFile: cgroupFile,
		programs:   make([]*CiliumEBPF.Program, cgroupProgramCount),
	}}
	backend.runtime.attached[cgroupProgramConnect4] = true
	backend.runtime.attach_modes[cgroupProgramConnect4] = cgroupAttachModeNetdReplace
	backend.runtime.displaced[cgroupProgramConnect4] = &displacedCgroupOwner{id: 33}
	return backend
}

func TestCgroupBackendDetachRestoresDisplacedOwner(t *testing.T) {
	fixture := installNetdAttachFixture(t, []link.AttachedProgram{{ID: 7}}, 0, passThroughOwner33)
	originalProgramHasID := programHasID
	t.Cleanup(func() { programHasID = originalProgramHasID })
	programHasID = func(*CiliumEBPF.Program, CiliumEBPF.ProgramID) bool { return true }
	backend := newDisplacingTestBackend(t)
	if err := backend.detachProgramsLocked(); err != nil {
		t.Fatal(err)
	}
	if fixture.detached != 0 {
		t.Fatal("a detach would leave the netd hook empty instead of restored")
	}
	if !slices.Equal(fixture.flags, []uint32{0}) {
		t.Fatalf("attach flags = %v, want one unflagged restore", fixture.flags)
	}
	if backend.runtime.attached[cgroupProgramConnect4] || backend.runtime.displaced[cgroupProgramConnect4] != nil ||
		backend.runtime.attach_modes[cgroupProgramConnect4] != "" {
		t.Fatal("a restored attachment is still recorded")
	}
}

func TestCgroupBackendDetachKeepsDisplacedOwnerForRetry(t *testing.T) {
	installNetdAttachFixture(t, []link.AttachedProgram{{ID: 7}}, 0, passThroughOwner33)
	originalProgramHasID := programHasID
	t.Cleanup(func() { programHasID = originalProgramHasID })
	programHasID = func(*CiliumEBPF.Program, CiliumEBPF.ProgramID) bool { return true }
	rawAttachProgram = func(link.RawAttachProgramOptions) error { return unix.EBUSY }
	backend := newDisplacingTestBackend(t)
	if err := backend.detachProgramsLocked(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("detach error = %v, want EBUSY", err)
	}
	if !backend.runtime.attached[cgroupProgramConnect4] || backend.runtime.displaced[cgroupProgramConnect4] == nil {
		t.Fatal("a failed restore discarded the displaced owner instead of keeping it for a retry")
	}
}

func TestOptionalHookNeverReclaimsAnActiveBackend(t *testing.T) {
	fixture := installNetdAttachFixture(t, []link.AttachedProgram{{ID: 33}}, 0, passThroughOwner33)
	programNameByID = func(CiliumEBPF.ProgramID) (string, error) { return "sb_ebpf_conn4", nil }
	if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err == nil {
		t.Fatal("optional hook replaced an active interception backend")
	}
	if fixture.detached != 0 || len(fixture.flags) != 1 {
		t.Fatalf("optional hook changed existing owner: %+v", fixture)
	}
}

func TestInstructionsAlwaysAllow(t *testing.T) {
	zeroExtend := asm.Instruction{OpCode: asm.Mov.Op32(asm.RegSource), Dst: asm.R0, Src: asm.R0, Constant: 1}
	for _, testCase := range []struct {
		name         string
		instructions asm.Instructions
		want         bool
	}{
		{name: "return 1", instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}, want: true},
		{name: "return 1 with alu32", instructions: asm.Instructions{asm.Mov.Imm32(asm.R0, 1), asm.Return()}, want: true},
		{name: "return 1 with verifier zero extension", instructions: asm.Instructions{asm.Mov.Imm32(asm.R0, 1), zeroExtend, asm.Return()}, want: true},
		{name: "return 1 through another register", instructions: asm.Instructions{asm.Mov.Imm(asm.R2, 1), asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}, want: true},
		{name: "return 0", instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}},
		{name: "return of an unknown register", instructions: asm.Instructions{asm.Mov.Reg(asm.R0, asm.R1), asm.Return()}},
		{name: "return 1 with upper bits set", instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}},
		{name: "context load", instructions: asm.Instructions{asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.Mov.Imm(asm.R0, 1), asm.Return()}},
		{name: "helper call", instructions: asm.Instructions{asm.FnGetSocketCookie.Call(), asm.Mov.Imm(asm.R0, 1), asm.Return()}},
		{name: "branch", instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.JEq.Imm(asm.R1, 0, "out"), asm.Mov.Imm(asm.R0, 0), asm.Return().WithSymbol("out")}},
		{name: "arithmetic", instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Add.Imm(asm.R0, 1), asm.Return()}},
		{name: "no exit", instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1)}},
		{name: "empty"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := instructionsAlwaysAllow(testCase.instructions); got != testCase.want {
				t.Fatalf("instructionsAlwaysAllow = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestOpenNetdPinnedProgramLimitsItselfToTakeableHooks(t *testing.T) {
	originalRoots := netdPinnedProgramRoots
	t.Cleanup(func() { netdPinnedProgramRoots = originalRoots })
	dir := t.TempDir()
	// Regular files are not bpffs pins; opening them fails, which must count
	// as "no program" rather than an error.
	for _, name := range []string{"prog_netd_connect4_inet4_connect", "prog_netd_cgroupsockrelease_inet_release"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	netdPinnedProgramRoots = []string{filepath.Join(dir, "missing"), dir}
	for _, attachType := range []CiliumEBPF.AttachType{
		CiliumEBPF.AttachCGroupInet4Connect,
		CiliumEBPF.AttachCgroupInetSockRelease,
		CiliumEBPF.AttachCGroupInetIngress,
	} {
		if program := openNetdPinnedProgram(attachType); program != nil {
			t.Fatalf("%v: opened %v from a non-pin", attachType, program)
		}
	}
	if netdPinnedProgramWithID(33) {
		t.Fatal("a non-pin matched a program ID")
	}
	if _, ok := netdHookPinPrefixes[CiliumEBPF.AttachCgroupInetSockRelease]; ok {
		t.Fatal("netd's socket-release program does accounting cleanup and must never be displaced")
	}
}

func TestRestoreNetdOwnerForStaleProgramFallsBackToDetach(t *testing.T) {
	originalPresent := netdPresent
	originalPlaceholder := newHookPlaceholderProgram
	originalFlags := queryCgroupHookFlags
	t.Cleanup(func() {
		netdPresent = originalPresent
		newHookPlaceholderProgram = originalPlaceholder
		queryCgroupHookFlags = originalFlags
	})
	newHookPlaceholderProgram = func(CiliumEBPF.AttachType) (*CiliumEBPF.Program, error) {
		t.Fatal("a placeholder was loaded where the stale program should simply be detached")
		return nil, nil
	}
	hookFlags, flagsErr := uint32(0), error(nil)
	queryCgroupHookFlags = func(int, CiliumEBPF.AttachType) (uint32, error) { return hookFlags, flagsErr }
	netdPresent = func() bool { return false }
	if restored, err := restoreNetdOwnerForStaleProgram(42, CiliumEBPF.AttachCGroupInet4Connect); restored || err != nil {
		t.Fatalf("without netd: restored=%v err=%v, want a plain detach", restored, err)
	}
	netdPresent = func() bool { return true }
	if restored, err := restoreNetdOwnerForStaleProgram(42, CiliumEBPF.AttachCgroupInetSockRelease); restored || err != nil {
		t.Fatalf("socket-release hook: restored=%v err=%v, want a plain detach", restored, err)
	}
	hookFlags = unix.BPF_F_ALLOW_MULTI
	if restored, err := restoreNetdOwnerForStaleProgram(42, CiliumEBPF.AttachCGroupInet4Connect); restored || err != nil {
		t.Fatalf("multi-program hook: restored=%v err=%v, want a plain detach", restored, err)
	}
	hookFlags, flagsErr = 0, unix.EINVAL
	if restored, err := restoreNetdOwnerForStaleProgram(42, CiliumEBPF.AttachCGroupInet4Connect); restored || err != nil {
		t.Fatalf("unknown hook mode: restored=%v err=%v, want a plain detach", restored, err)
	}
}

func TestHookPlaceholderIsNotReclaimed(t *testing.T) {
	if ownedCgroupProgramName(kernelProgramNameHookPlaceholder) {
		t.Fatal("the netd placeholder would be reclaimed as stale state")
	}
}

// Linux 6.17 and 6.18 write query.revision back to offset 56 whatever
// attribute size is passed, so the query attribute must reach past it.
func TestCgroupProgQueryAttrCoversKernelOutputs(t *testing.T) {
	var attr cgroupProgQueryAttr
	if offset := unsafe.Offsetof(attr.attachFlags); offset != 12 {
		t.Fatalf("query.attach_flags at offset %d, want 12", offset)
	}
	if offset := unsafe.Offsetof(attr.programs); offset != 24 {
		t.Fatalf("query.prog_cnt at offset %d, want 24", offset)
	}
	if offset := unsafe.Offsetof(attr.revision); offset != 56 {
		t.Fatalf("query.revision at offset %d, want 56", offset)
	}
	if size := unsafe.Sizeof(attr); size < 64 {
		t.Fatalf("query attribute is %d bytes, want at least 64 so the kernel's revision write stays inside it", size)
	}
}
