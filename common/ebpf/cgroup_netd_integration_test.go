//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func dedicatedHookOwnerCgroup(t *testing.T, index int) (string, *os.File) {
	t.Helper()
	requireEBPFIntegration(t, "test cgroup hook ownership")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, root, index)
	if !dedicated {
		t.Skip("a dedicated test cgroup is required")
	}
	cgroupFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cgroupFile.Close() })
	return path, cgroupFile
}

func newHookOwnerTestProgram(t *testing.T, name string) *CiliumEBPF.Program {
	t.Helper()
	return newHookOwnerTestProgramWith(t, name, asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()})
}

// effectfulHookOwnerInstructions read the socket address before allowing, so
// they are not a pass-through and no backend may take the hook over from
// them.
var effectfulHookOwnerInstructions = asm.Instructions{
	asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
	asm.Mov.Imm(asm.R0, 1),
	asm.Return(),
}

func newHookOwnerTestProgramWith(t *testing.T, name string, instructions asm.Instructions) *CiliumEBPF.Program {
	t.Helper()
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         name,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   CiliumEBPF.AttachCGroupInet4Connect,
		License:      "GPL",
		Instructions: instructions,
	})
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup sock_addr programs are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return program
}

// detachConnect4Leftovers removes whatever a test left on the connect4 hook,
// so that the test cgroup can be removed.
func detachConnect4Leftovers(t *testing.T, cgroupFile *os.File) {
	t.Helper()
	for _, owner := range connect4ProgramIDs(t, cgroupFile) {
		if leftover, openErr := CiliumEBPF.NewProgramFromID(owner); openErr == nil {
			_ = rawDetachProgram(int(cgroupFile.Fd()), leftover, CiliumEBPF.AttachCGroupInet4Connect)
			_ = leftover.Close()
		}
	}
}

// attachExclusiveTestProgram reproduces an unflagged legacy BPF_PROG_ATTACH.
// The returned ID stays attached after the program FD is closed, exactly like
// an attachment left behind by a process that has exited.
func attachExclusiveTestProgram(t *testing.T, cgroupFile *os.File, name string) CiliumEBPF.ProgramID {
	t.Helper()
	program := newHookOwnerTestProgram(t, name)
	defer program.Close()
	return attachLikeNetd(t, cgroupFile, program)
}

// attachLikeNetd attaches program exclusively, as netd does on Android 15+,
// and returns its ID.
func attachLikeNetd(t *testing.T, cgroupFile *os.File, program *CiliumEBPF.Program) CiliumEBPF.ProgramID {
	t.Helper()
	err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cgroupFile.Fd()),
		Program: program,
		Attach:  CiliumEBPF.AttachCGroupInet4Connect,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	t.Cleanup(func() { detachConnect4Leftovers(t, cgroupFile) })
	return id
}

func connect4ProgramIDs(t *testing.T, cgroupFile *os.File) []CiliumEBPF.ProgramID {
	t.Helper()
	ids, err := queryCgroupProgramIDs(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func connect4ProgramNames(t *testing.T, cgroupFile *os.File) []string {
	t.Helper()
	var names []string
	for _, id := range connect4ProgramIDs(t, cgroupFile) {
		name, err := programNameByID(id)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

func attachTCPCgroupBackend(t *testing.T, path string, port uint16) (*CgroupBackend, error) {
	t.Helper()
	backend, err := prepareCgroupIntegrationBackend(path, true, false, false)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.LoadPrograms(port); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program loading is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return backend, backend.Attach()
}

// emulateNetdDevice makes the backend see an Android netd device whose pins
// live in a private bpffs directory, so that tests never touch a real
// /sys/fs/bpf/netd_shared.
func emulateNetdDevice(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("sing-ebpf-test-netd-%d-%s", os.Getpid(), t.Name()))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Skipf("cannot create a bpffs pin directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	originalRoots := netdPinnedProgramRoots
	originalPresent := netdPresent
	netdPinnedProgramRoots = []string{dir}
	netdPresent = func() bool { return true }
	t.Cleanup(func() {
		netdPinnedProgramRoots = originalRoots
		netdPresent = originalPresent
	})
	return dir
}

// pinNetdProgram pins program where netd pins its connect4 program.
func pinNetdProgram(t *testing.T, dir string, program *CiliumEBPF.Program) {
	t.Helper()
	pin := filepath.Join(dir, "prog_netd_connect4_inet4_connect")
	if err := program.Pin(pin); err != nil {
		t.Skipf("cannot pin into bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })
}

func requireSingleProgramHook(t *testing.T, cgroupFile *os.File, context string) {
	t.Helper()
	flags, err := queryCgroupHookFlags(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	if flags != 0 {
		t.Fatalf("%s: hook flags = %#x, want the single-program mode netd expects", context, flags)
	}
}

func requireConnect4Owners(t *testing.T, cgroupFile *os.File, want []CiliumEBPF.ProgramID, context string) {
	t.Helper()
	if ids := connect4ProgramIDs(t, cgroupFile); !slices.Equal(ids, want) {
		t.Fatalf("%s: connect4 programs = %v, want %v", context, ids, want)
	}
	requireSingleProgramHook(t, cgroupFile, context)
}

func requireConnect4Names(t *testing.T, cgroupFile *os.File, want []string, context string) {
	t.Helper()
	if names := connect4ProgramNames(t, cgroupFile); !slices.Equal(names, want) {
		t.Fatalf("%s: connect4 programs = %v, want %v", context, names, want)
	}
	requireSingleProgramHook(t, cgroupFile, context)
}

func requireTakeoverAndRestore(t *testing.T, path string, cgroupFile *os.File, port uint16, ownerID CiliumEBPF.ProgramID) {
	t.Helper()
	backend, err := attachTCPCgroupBackend(t, path, port)
	if err != nil {
		t.Fatalf("attach over a pass-through owner: %v", err)
	}
	if mode := backend.runtime.attach_modes[cgroupProgramConnect4]; mode != cgroupAttachModeNetdReplace {
		t.Fatalf("connect4 attach mode = %q, want %q", mode, cgroupAttachModeNetdReplace)
	}
	requireConnect4Names(t, cgroupFile, []string{"sb_ebpf_conn4"}, "while attached")
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{ownerID}, "after close")
}

// AOSP netd: the placeholder is pinned under netd_shared.
func TestCgroupBackendTakesOverPinnedNetdPlaceholderIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 160)
	dir := emulateNetdDevice(t)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	pinNetdProgram(t, dir, placeholder)
	netdID := attachLikeNetd(t, cgroupFile, placeholder)
	requireTakeoverAndRestore(t, path, cgroupFile, 41160, netdID)
}

// Vendor and custom-ROM netd builds name and pin their programs differently,
// as on the device that reported "connect4_inet4_connect_4_19_v". The owner's
// instructions alone must be enough.
func TestCgroupBackendTakesOverUnpinnedPassThroughOwnerIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 161)
	emulateNetdDevice(t)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	ownerID := attachLikeNetd(t, cgroupFile, placeholder)
	verdict := inspectPassThrough(placeholder.FD())
	if !verdict.known {
		t.Skip("this kernel withholds translated instructions")
	}
	requireTakeoverAndRestore(t, path, cgroupFile, 41161, ownerID)
}

// A backend that exited without restoring the placeholder leaves its own
// program as the single-program owner. Stale-program reclaim must give the
// hook back to netd's pinned program before it is taken over again.
func TestCgroupBackendReclaimRestoresPinnedNetdPlaceholderIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 162)
	dir := emulateNetdDevice(t)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	pinNetdProgram(t, dir, placeholder)
	netdID := attachLikeNetd(t, cgroupFile, placeholder)
	// The crashed backend's program replaced netd's and outlived its process.
	staleID := attachExclusiveTestProgram(t, cgroupFile, "sb_ebpf_conn4")
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{staleID}, "before start")
	requireTakeoverAndRestore(t, path, cgroupFile, 41162, netdID)
}

// Without netd's pin at hand, reclaim must still not empty the hook: an empty
// hook would end up in multi-program mode, which makes a restarting netd
// abort. A pass-through of our own keeps it as netd keeps it.
func TestCgroupBackendReclaimKeepsNetdHookSingleProgramIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 163)
	emulateNetdDevice(t)
	attachExclusiveTestProgram(t, cgroupFile, "sb_ebpf_conn4")
	backend, err := attachTCPCgroupBackend(t, path, 41163)
	if err != nil {
		t.Fatalf("attach with a stale takeover: %v", err)
	}
	if mode := backend.runtime.attach_modes[cgroupProgramConnect4]; mode != cgroupAttachModeNetdReplace {
		t.Fatalf("connect4 attach mode = %q, want %q", mode, cgroupAttachModeNetdReplace)
	}
	requireConnect4Names(t, cgroupFile, []string{"sb_ebpf_conn4"}, "while attached")
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	// The placeholder stays attached after close, as it must on a device.
	requireConnect4Names(t, cgroupFile, []string{"sb_hook_allow"}, "after close")
}

// Without netd the stale program is simply detached, as before.
func TestCgroupBackendReclaimDetachesStaleProgramWithoutNetdIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 164)
	originalPresent := netdPresent
	netdPresent = func() bool { return false }
	t.Cleanup(func() { netdPresent = originalPresent })
	attachExclusiveTestProgram(t, cgroupFile, "sb_ebpf_conn4")
	backend, err := attachTCPCgroupBackend(t, path, 41164)
	if err != nil {
		t.Fatalf("attach with a stale exclusive program: %v", err)
	}
	if mode := backend.runtime.attach_modes[cgroupProgramConnect4]; mode == cgroupAttachModeNetdReplace {
		t.Fatalf("connect4 attach mode = %q without netd", mode)
	}
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	if ids := connect4ProgramIDs(t, cgroupFile); len(ids) != 0 {
		t.Fatalf("connect4 programs after close = %v, want none", ids)
	}
}

// A program that does more than "return 1" stays, even when netd pinned it.
func TestCgroupBackendKeepsNetdProgramWithLogicIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 165)
	dir := emulateNetdDevice(t)
	program := newHookOwnerTestProgramWith(t, "connect4_inet4_", effectfulHookOwnerInstructions)
	t.Cleanup(func() { _ = program.Close() })
	pinNetdProgram(t, dir, program)
	netdID := attachLikeNetd(t, cgroupFile, program)
	if verdict := inspectPassThrough(program.FD()); !verdict.known {
		t.Skip("this kernel withholds translated instructions")
	}
	_, err := attachTCPCgroupBackend(t, path, 41165)
	if err == nil || !errors.Is(err, errCgroupOwnerHasEffect) {
		t.Fatalf("attach error = %v, want the owner kept and explained by errCgroupOwnerHasEffect", err)
	}
	if !strings.Contains(err.Error(), "connect4_inet4_") {
		t.Fatalf("attach error %q does not name the owner", err)
	}
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{netdID}, "after refusal")
}

// Optional components, such as the process tracker on the cgroup v2 root, keep
// the placeholder and fall back to userspace.
func TestOptionalCgroupAttachKeepsNetdPlaceholderIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 166)
	emulateNetdDevice(t)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	netdID := attachLikeNetd(t, cgroupFile, placeholder)
	tracker := newHookOwnerTestProgramWith(t, "sb_proc_conn4", effectfulHookOwnerInstructions)
	t.Cleanup(func() { _ = tracker.Close() })
	programLink, err := attachCgroupProgram(path, tracker, CiliumEBPF.AttachCGroupInet4Connect)
	if err == nil {
		_ = programLink.Close()
		t.Fatal("an optional component replaced the netd placeholder")
	}
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{netdID}, "after refusal")
}

func TestInspectPassThroughIntegration(t *testing.T) {
	requireEBPFIntegration(t, "read translated instructions")
	passThrough := newHookOwnerTestProgram(t, "pass_through")
	t.Cleanup(func() { _ = passThrough.Close() })
	effectful := newHookOwnerTestProgramWith(t, "effectful", effectfulHookOwnerInstructions)
	t.Cleanup(func() { _ = effectful.Close() })
	verdict := inspectPassThrough(passThrough.FD())
	if !verdict.known {
		t.Skip("this kernel withholds translated instructions")
	}
	if !verdict.passThrough {
		t.Fatalf("return 1 judged %+v, want a pass-through", verdict)
	}
	if verdict = inspectPassThrough(effectful.FD()); !verdict.known || verdict.passThrough {
		t.Fatalf("context load judged %+v, want a known program with effect", verdict)
	}
}
