//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Android 15 (API 35) netd attaches a program to every socket-address hook of
// the cgroup v2 root with an unflagged BPF_PROG_ATTACH. The kernel then holds
// each hook in single-program mode and rejects every multi-program attachment
// on it and in every descendant cgroup, BPF_LINK_CREATE included, with EPERM.
// The programs on the connect, sendmsg and recvmsg hooks are pass-through
// placeholders ("return BPF_ALLOW") that reserve the hook for the system; the
// only way to run an interception program on such a device is to replace them.
//
// netd also depends on those hooks staying in single-program mode: when it
// restarts it attaches again without flags, which the kernel refuses on a
// multi-program hook, and it then aborts if BPF_PROG_QUERY does not report
// exactly one program. The backend therefore never converts such a hook; it
// swaps the owner for its own program, which keeps the mode, and swaps it
// back on detach.
//
// Only the interception backend takes a hook over. Optional components that
// attach to the same root hooks, such as the process tracker, have a userspace
// fallback; a program of theirs in netd's place would be an owner that does
// real work, which the backend would then have to refuse.
//
// Vendor and custom-ROM builds of netd differ in program names, BTF and pin
// layout, so the decision rests on what the owner does, not on what it is
// called: it must be the single program of a hook in single-program mode, and
// its translated instructions must reduce to "r0 = 1; exit". Only when the
// kernel withholds the instructions is a program accepted on identity, and
// then only the one netd pinned for that hook. Every other owner is kept.
// netd's socket-release program does real traffic-accounting cleanup and its
// hook is never taken over.

// netdPinnedProgramRoots lists the bpffs directories in which Android's BPF
// loaders pin programs. Tests point it at a private directory.
var netdPinnedProgramRoots = []string{"/sys/fs/bpf/netd_shared", "/sys/fs/bpf/netd_readonly", "/sys/fs/bpf"}

// netdPresent reports whether this is an Android 13+ device whose netd owns
// cgroup hooks. Tests replace it.
var netdPresent = func() bool {
	info, err := os.Stat("/sys/fs/bpf/netd_shared")
	return err == nil && info.IsDir()
}

// netdHookPinPrefixes maps each hook the backend may take over to the prefix
// of the pin AOSP netd creates for its program there:
// "prog_<object>_<section with '/' replaced by '_'>", where the section name
// starts with the attach type. Suffixes vary between releases and kernel
// version variants, so only the prefix is contractual.
var netdHookPinPrefixes = map[CiliumEBPF.AttachType]string{
	CiliumEBPF.AttachCGroupInet4Connect: "prog_netd_connect4_",
	CiliumEBPF.AttachCGroupInet6Connect: "prog_netd_connect6_",
	CiliumEBPF.AttachCGroupUDP4Sendmsg:  "prog_netd_sendmsg4_",
	CiliumEBPF.AttachCGroupUDP6Sendmsg:  "prog_netd_sendmsg6_",
	CiliumEBPF.AttachCGroupUDP4Recvmsg:  "prog_netd_recvmsg4_",
	CiliumEBPF.AttachCGroupUDP6Recvmsg:  "prog_netd_recvmsg6_",
}

// maxPassThroughInstructions bounds the instructions read from an owner. A
// pass-through is two instructions, three with a zero-extension the verifier
// inserts on some architectures; anything longer does real work.
const maxPassThroughInstructions = 8
const kernelProgramNameHookPlaceholder = "sb_hook_allow"

var (
	// errCgroupOwnerHasEffect reports an owner whose instructions do more than
	// allow. Replacing it would change what the system does on that hook.
	errCgroupOwnerHasEffect = errors.New("the program on this hook does more than allow, so it is kept")
	// errCgroupOwnerUnverifiable reports an owner whose instructions the kernel
	// withholds and which is not netd's pinned program for the hook.
	errCgroupOwnerUnverifiable = errors.New("the kernel withholds the instructions of the program on this hook " +
		"and it is not Android netd's pinned program for it, so it is kept")
)

// displacedCgroupOwner is a program the backend replaced on a single-program
// hook and must attach again when it releases the hook.
type displacedCgroupOwner struct {
	id      CiliumEBPF.ProgramID
	program *CiliumEBPF.Program
	// flags is the hook's attach mode, 0 or BPF_F_ALLOW_OVERRIDE; replacing
	// and restoring must both use it.
	flags uint32
}

func (o *displacedCgroupOwner) Close() error {
	if o == nil || o.program == nil {
		return nil
	}
	err := o.program.Close()
	o.program = nil
	return err
}

// displaceableCgroupOwner decides whether the programs found on a hook that
// rejected multi-program attachment may be replaced. It returns nil and an
// explanation for an owner that was examined and kept.
func displaceableCgroupOwner(target int, attachType CiliumEBPF.AttachType, owners []link.AttachedProgram) (*displacedCgroupOwner, error) {
	if len(owners) != 1 {
		return nil, nil
	}
	if _, takeable := netdHookPinPrefixes[attachType]; !takeable {
		return nil, nil
	}
	flags, err := queryCgroupHookFlags(target, attachType)
	if err != nil || flags&unix.BPF_F_ALLOW_MULTI != 0 {
		return nil, nil
	}
	return findDisplaceableOwner(attachType, owners[0].ID, flags)
}

// findDisplaceableOwner opens the owner and keeps it open for the restore
// when it is a pass-through. Tests replace it.
var findDisplaceableOwner = func(attachType CiliumEBPF.AttachType, ownerID CiliumEBPF.ProgramID, flags uint32) (*displacedCgroupOwner, error) {
	program, err := newProgramFromID(ownerID)
	if err != nil {
		return nil, E.Cause(err, "open the program on this hook")
	}
	verdict := inspectPassThrough(program.FD())
	switch {
	case verdict.known && verdict.passThrough:
	case verdict.known:
		_ = program.Close()
		return nil, fmt.Errorf("%w (%s)", errCgroupOwnerHasEffect, verdict.detail)
	case netdPinnedProgramWithID(ownerID):
	default:
		_ = program.Close()
		return nil, errCgroupOwnerUnverifiable
	}
	return &displacedCgroupOwner{id: ownerID, program: program, flags: flags}, nil
}

type passThroughVerdict struct {
	passThrough bool
	// known is false when the kernel did not disclose the instructions.
	known  bool
	detail string
}

// inspectPassThrough reads the owner's translated instructions straight from
// BPF_OBJ_GET_INFO_BY_FD. cilium/ebpf's ProgramInfo.Instructions also parses
// the program's BTF and fails on BTF it cannot read, which vendor builds
// carry; the instructions alone are all that is needed here.
func inspectPassThrough(programFD int) passThroughVerdict {
	instructions, total, err := readTranslatedInstructions(programFD, maxPassThroughInstructions)
	switch {
	case err != nil || total == 0:
		return passThroughVerdict{}
	case total > maxPassThroughInstructions:
		return passThroughVerdict{known: true, detail: fmt.Sprintf("%d translated instructions", total)}
	case instructions == nil:
		return passThroughVerdict{}
	case instructionsAlwaysAllow(instructions):
		return passThroughVerdict{passThrough: true, known: true}
	default:
		return passThroughVerdict{known: true, detail: fmt.Sprintf("instructions %v", instructionSummary(instructions))}
	}
}

// bpfProgInfoPrefix is the leading part of struct bpf_prog_info, which is all
// BPF_OBJ_GET_INFO_BY_FD needs to return the translated instructions.
type bpfProgInfoPrefix struct {
	programType     uint32
	id              uint32
	tag             [8]byte
	jitedProgLen    uint32
	xlatedProgLen   uint32
	jitedProgInsns  uint64
	xlatedProgInsns uint64
}

// readTranslatedInstructions returns up to limit translated instructions and
// the program's total count. A nil slice with a non-zero total means the
// program is longer than limit or the kernel withheld the instructions
// (constant blinding without raw dump access); a zero total means the caller
// may not read them at all.
func readTranslatedInstructions(programFD int, limit int) (asm.Instructions, int, error) {
	buffer := make([]byte, limit*asm.InstructionSize)
	info := new(bpfProgInfoPrefix)
	var pinner runtime.Pinner
	pinner.Pin(&buffer[0])
	pinner.Pin(info)
	defer pinner.Unpin()
	info.xlatedProgLen = uint32(len(buffer))
	info.xlatedProgInsns = uint64(uintptr(unsafe.Pointer(&buffer[0])))
	attr := struct {
		bpfFD   uint32
		infoLen uint32
		info    uint64
	}{
		bpfFD:   uint32(programFD),
		infoLen: uint32(unsafe.Sizeof(*info)),
		info:    uint64(uintptr(unsafe.Pointer(info))),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return nil, 0, errno
	}
	total := int(info.xlatedProgLen) / asm.InstructionSize
	if total == 0 || total > limit || info.xlatedProgInsns == 0 {
		return nil, total, nil
	}
	instructions, err := asm.AppendInstructions(nil, bytes.NewReader(buffer[:total*asm.InstructionSize]), binary.NativeEndian, "linux")
	if err != nil {
		return nil, total, err
	}
	return instructions, total, nil
}

// instructionsAlwaysAllow reports whether straight-line code made only of
// register moves ends in an exit with r0 = 1. That covers "return 1" in both
// ALU widths and the zero-extension the verifier inserts after a 32-bit move
// on some architectures. Any load, store, call or branch makes the program
// one that does real work.
func instructionsAlwaysAllow(instructions asm.Instructions) bool {
	var known [asm.R10 + 1]bool
	var value [asm.R10 + 1]uint64
	for index, instruction := range instructions {
		opCode := instruction.OpCode
		switch opCode.Class() {
		case asm.ALU64Class, asm.ALUClass:
			if opCode.ALUOp() != asm.Mov || instruction.Offset != 0 || instruction.Dst > asm.R9 {
				return false
			}
			var result uint64
			var resultKnown bool
			if opCode.Source() == asm.ImmSource {
				result, resultKnown = uint64(instruction.Constant), true
			} else {
				if instruction.Src > asm.R10 {
					return false
				}
				result, resultKnown = value[instruction.Src], known[instruction.Src]
			}
			if opCode.Class() == asm.ALUClass {
				result = uint64(uint32(result))
			}
			value[instruction.Dst], known[instruction.Dst] = result, resultKnown
		case asm.JumpClass:
			return opCode.JumpOp() == asm.Exit && index == len(instructions)-1 &&
				known[asm.R0] && value[asm.R0] == 1
		default:
			return false
		}
	}
	return false
}

func instructionSummary(instructions asm.Instructions) string {
	parts := make([]string, 0, len(instructions))
	for _, instruction := range instructions {
		parts = append(parts, strings.TrimSpace(fmt.Sprint(instruction)))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// netdPinnedProgramWithID reports whether a program pinned by Android's BPF
// loaders is the program with id.
func netdPinnedProgramWithID(id CiliumEBPF.ProgramID) bool {
	found := false
	forEachNetdPinnedProgram("prog_", func(program *CiliumEBPF.Program) bool {
		info, err := program.Info()
		if err != nil {
			return false
		}
		programID, ok := info.ID()
		found = ok && programID == id
		return found
	})
	return found
}

// forEachNetdPinnedProgram opens every pinned program whose name starts with
// prefix and calls visit until it returns true. visit must not retain the
// program; it is closed afterwards.
func forEachNetdPinnedProgram(prefix string, visit func(*CiliumEBPF.Program) bool) {
	for _, root := range netdPinnedProgramRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
				continue
			}
			program, err := CiliumEBPF.LoadPinnedProgram(filepath.Join(root, entry.Name()), &CiliumEBPF.LoadPinOptions{ReadOnly: true})
			if err != nil {
				// A pin that cannot be opened (or a non-program pin) is not a
				// candidate.
				continue
			}
			done := visit(program)
			_ = program.Close()
			if done {
				return
			}
		}
	}
}

// openNetdPinnedProgram opens the program netd pinned for attachType, or
// returns nil when no pin directory holds one.
func openNetdPinnedProgram(attachType CiliumEBPF.AttachType) *CiliumEBPF.Program {
	prefix, ok := netdHookPinPrefixes[attachType]
	if !ok {
		return nil
	}
	var result *CiliumEBPF.Program
	forEachNetdPinnedProgram(prefix, func(program *CiliumEBPF.Program) bool {
		clone, err := program.Clone()
		if err != nil {
			return false
		}
		result = clone
		return true
	})
	return result
}

// replaceCgroupOwner attaches program in place of the single-program owner
// of the hook. An attach with the hook's own flags (0 or ALLOW_OVERRIDE) on
// such a hook swaps the program atomically and keeps the hook's mode, which
// is the state netd expects to find again later.
func replaceCgroupOwner(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType, flags uint32) error {
	return rawAttachProgram(link.RawAttachProgramOptions{
		Target:  target,
		Program: program,
		Attach:  attachType,
		Flags:   flags,
	})
}

// restoreDisplacedCgroupOwner puts the displaced program back on the hook
// that ours currently holds, then closes it. It swaps atomically when ours is
// still the owner, attaches to an empty hook, and leaves any other owner
// alone: a program that replaced ours meanwhile, such as netd's own after a
// netd restart, is not ours to displace.
func restoreDisplacedCgroupOwner(target int, ours *CiliumEBPF.Program, displaced *displacedCgroupOwner, attachType CiliumEBPF.AttachType) error {
	if displaced == nil {
		return nil
	}
	owners, queryErr := queryCgroupPrograms(link.QueryOptions{Target: target, Attach: attachType})
	switch {
	case queryErr != nil:
		// Without a view of the hook, fall back to the two-step sequence.
		if err := rawDetachProgram(target, ours, attachType); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	case len(owners.Programs) == 0:
	case len(owners.Programs) == 1 && programHasID(ours, owners.Programs[0].ID):
	default:
		return displaced.Close()
	}
	if err := replaceCgroupOwner(target, displaced.program, attachType, displaced.flags); err != nil {
		return E.Cause(err, "restore displaced cgroup program")
	}
	return displaced.Close()
}

// programHasID reports whether program is the kernel program with id. A
// program whose ID cannot be read is assumed to be the owner being asked
// about, since the caller only reaches this on a hook it attached to.
var programHasID = func(program *CiliumEBPF.Program, id CiliumEBPF.ProgramID) bool {
	if program == nil {
		return true
	}
	info, err := program.Info()
	if err != nil {
		return true
	}
	programID, ok := info.ID()
	return !ok || programID == id
}

// restoreNetdOwnerForStaleProgram is used by stale-program reclaim on a hook
// whose single program is a stale interception program: an earlier backend
// took the hook over from netd and exited without handing it back. Detaching
// would leave the hook empty, and an empty hook would let the next attach put
// it in multi-program mode, which makes a restarting netd abort. Instead the
// stale program is swapped for netd's pinned program, or, when that is not at
// hand, for an equivalent pass-through, so the hook stays as netd keeps it.
// It reports false when the device has no netd, the hook is not one the
// backend takes over, or the hook is not known to be in single-program mode;
// the caller then detaches as usual.
func restoreNetdOwnerForStaleProgram(target int, attachType CiliumEBPF.AttachType) (bool, error) {
	if _, takeable := netdHookPinPrefixes[attachType]; !takeable || !netdPresent() {
		return false, nil
	}
	flags, err := queryCgroupHookFlags(target, attachType)
	if err != nil || flags&unix.BPF_F_ALLOW_MULTI != 0 {
		return false, nil
	}
	program := openNetdPinnedProgram(attachType)
	if program == nil {
		program, err = newHookPlaceholderProgram(attachType)
		if err != nil {
			return false, E.Cause(err, "load pass-through cgroup program")
		}
	}
	defer program.Close()
	if err = replaceCgroupOwner(target, program, attachType, flags); err != nil {
		return false, E.Cause(err, "restore netd cgroup program")
	}
	return true, nil
}

// newHookPlaceholderProgram loads a "return 1" socket-address program, the
// same behavior as netd's own placeholder on these hooks.
var newHookPlaceholderProgram = func(attachType CiliumEBPF.AttachType) (*CiliumEBPF.Program, error) {
	return CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameHookPlaceholder,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   attachType,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
}
