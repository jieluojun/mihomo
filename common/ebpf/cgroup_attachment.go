//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type cgroupProgramLink interface {
	Close() error
}

type retryableCgroupProgramLink interface {
	cgroupProgramLink
	IsClosed() bool
}

// cgroupProgramLinkCloseComplete distinguishes a failed legacy detach, whose
// target FD must be retained for another attempt, from link.Close errors where
// the link FD has already been consumed and cannot be retried safely.
func cgroupProgramLinkCloseComplete(programLink cgroupProgramLink, closeErr error) bool {
	if closeErr == nil {
		return true
	}
	retryableLink, retryable := programLink.(retryableCgroupProgramLink)
	return !retryable || retryableLink.IsClosed()
}

// attachCgroupProgram prefers BPF_LINK_CREATE, whose cgroup implementation is
// inherently multi-program, then falls back to legacy BPF_PROG_ATTACH. The
// legacy path tries BPF_F_ALLOW_MULTI first and retries without flags only when
// the kernel rejects multi attachment with a compatibility error.
func attachCgroupProgram(path string, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) (cgroupProgramLink, error) {
	cgroupFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	programLink, linkErr := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cgroupFile.Fd()),
		Program: program,
		Attach:  attachType,
	})
	if linkErr == nil {
		_ = cgroupFile.Close()
		return programLink, nil
	}
	if !cgroupLinkUnavailable(linkErr) {
		_ = cgroupFile.Close()
		return nil, linkErr
	}
	if err = attachProgramRaw(int(cgroupFile.Fd()), program, attachType); err != nil {
		_ = cgroupFile.Close()
		return nil, E.Errors(linkErr, err)
	}
	return &legacyCgroupProgramLink{
		cgroupFile: cgroupFile,
		program:    program,
		attachType: attachType,
	}, nil
}

type legacyCgroupProgramLink struct {
	cgroupFile *os.File
	program    *CiliumEBPF.Program
	attachType CiliumEBPF.AttachType
	// detachProgram is nil in production. Tests inject a transient detach
	// failure to prove that the target FD remains owned for a cleanup retry.
	detachProgram func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error
}

func (l *legacyCgroupProgramLink) Close() error {
	if l == nil || l.cgroupFile == nil {
		return nil
	}
	detachProgram := l.detachProgram
	if detachProgram == nil {
		detachProgram = rawDetachProgram
	}
	detachErr := detachProgram(int(l.cgroupFile.Fd()), l.program, l.attachType)
	if detachErr != nil && !errors.Is(detachErr, unix.ENOENT) && !errors.Is(detachErr, unix.ESRCH) {
		return detachErr
	}
	closeErr := l.cgroupFile.Close()
	l.cgroupFile = nil
	return closeErr
}

func (l *legacyCgroupProgramLink) IsClosed() bool {
	return l == nil || l.cgroupFile == nil
}

// lockCgroupFile takes the exclusive lock that marks this cgroup as managed
// here.
//
// A lock that is already held is still reported as EBUSY, so callers matching
// on it keep working, but it is described for what is known rather than what is
// likely. The holder may be another running instance, and it may equally be a
// handle this process itself has not let go of, because a close that could not
// detach every program keeps the cgroup open. Naming only the first would send
// the reader looking for a second process that need not exist.
func lockCgroupFile(cgroupFile *os.File) error {
	err := unix.Flock(int(cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		return E.Cause(unix.EBUSY,
			"the exclusive lock on this cgroup is already held, "+
				"either by another active instance or by an earlier close that did not finish: ",
			"lock cgroup")
	}
	return eBPFOperationError("lock cgroup", err)
}

func detachOwnedCgroupPrograms(cgroupFD int) error {
	for _, definition := range cgroupProgramDefinitions {
		if _, err := detachOwnedCgroupProgramsForAttach(cgroupFD, definition.attachType); err != nil {
			if definition.attachType == CiliumEBPF.AttachCgroupInetSockRelease && socketReleaseUnavailable(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// detachOwnedCgroupProgramsForAttach removes only programs that belong to a
// sing-ebpf generation. Older releases used the sing_ebpf_ prefix, while the
// current diagnostic names use sb_ebpf_. Never detach an unknown owner: the
// caller may be sharing the host cgroup with netd or another eBPF service.
func detachOwnedCgroupProgramsForAttach(cgroupFD int, attachType CiliumEBPF.AttachType) (bool, error) {
	first, err := queryCgroupProgramIDs(cgroupFD, attachType)
	if err != nil {
		return false, err
	}
	second, err := queryCgroupProgramIDs(cgroupFD, attachType)
	if err != nil {
		return false, err
	}
	if !sameProgramIDs(first, second) {
		return false, unix.ESTALE
	}
	var detached bool
	for _, programID := range first {
		name, nameErr := programNameByID(programID)
		if nameErr != nil {
			return detached, nameErr
		}
		if ownedCgroupProgramName(name) {
			program, openErr := newProgramFromID(programID)
			if openErr != nil {
				return detached, openErr
			}
			// A stale program that is the hook's only program may have taken the
			// hook over from Android netd and never given it back. Put a netd
			// placeholder back instead of emptying the hook; the interception
			// backend takes it over again when it attaches and restores it on
			// detach.
			if len(first) == 1 {
				restored, restoreErr := restoreNetdOwnerForStaleProgram(cgroupFD, attachType)
				if restoreErr != nil {
					_ = program.Close()
					return detached, restoreErr
				}
				if restored {
					detached = true
					if closeErr := program.Close(); closeErr != nil {
						return detached, closeErr
					}
					continue
				}
			}
			if detachErr := rawDetachProgram(cgroupFD, program, attachType); detachErr != nil {
				_ = program.Close()
				return detached, detachErr
			}
			detached = true
			if closeErr := program.Close(); closeErr != nil {
				return detached, closeErr
			}
		}
	}
	return detached, nil
}

func ownedCgroupProgramName(name string) bool {
	return strings.HasPrefix(name, "sb_ebpf_") || strings.HasPrefix(name, "sing_ebpf_")
}

func queryCgroupProgramIDs(cgroupFD int, attachType CiliumEBPF.AttachType) ([]CiliumEBPF.ProgramID, error) {
	result, err := queryCgroupPrograms(link.QueryOptions{Target: cgroupFD, Attach: attachType})
	if err != nil {
		return nil, err
	}
	ids := make([]CiliumEBPF.ProgramID, len(result.Programs))
	for index := range result.Programs {
		ids[index] = result.Programs[index].ID
	}
	return ids, nil
}

// cgroupProgQueryAttr is the BPF_PROG_QUERY member of union bpf_attr, through
// query.revision. It must not be shortened: Linux 6.17 and 6.18 write
// query.revision back to offset 56 whatever attribute size the caller passes,
// so a shorter attribute lets the kernel write past it (fixed upstream by
// "bpf: fix BPF_PROG_QUERY OOB write and cgroup backward compat"). The layout
// matches cilium/ebpf's sys.ProgQueryAttr.
type cgroupProgQueryAttr struct {
	targetFD           uint32
	attachType         uint32
	queryFlags         uint32
	attachFlags        uint32
	programIDs         uint64
	programs           uint32
	_                  uint32
	programAttachFlags uint64
	linkIDs            uint64
	linkAttachFlags    uint64
	revision           uint64
}

// queryCgroupHookFlags returns the attach mode the kernel recorded for a
// cgroup hook (0, BPF_F_ALLOW_OVERRIDE or BPF_F_ALLOW_MULTI). cilium/ebpf's
// QueryPrograms does not expose this field, so the request is issued directly;
// with prog_cnt = 0 every kernel since BPF_PROG_QUERY was introduced returns
// only the count and the flags.
var queryCgroupHookFlags = func(cgroupFD int, attachType CiliumEBPF.AttachType) (uint32, error) {
	attr := cgroupProgQueryAttr{
		targetFD:   uint32(cgroupFD),
		attachType: uint32(attachType),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_QUERY, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return attr.attachFlags, nil
}

var newProgramFromID = CiliumEBPF.NewProgramFromID

var programNameByID = func(programID CiliumEBPF.ProgramID) (string, error) {
	program, err := newProgramFromID(programID)
	if err != nil {
		return "", err
	}
	info, infoErr := program.Info()
	closeErr := program.Close()
	if infoErr != nil {
		return "", infoErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return info.Name, nil
}

func cgroupProgramOwnerNames(result *link.QueryResult) ([]string, error) {
	owners := make([]string, 0, len(result.Programs))
	for _, attached := range result.Programs {
		name, err := programNameByID(attached.ID)
		if err != nil {
			return nil, err
		}
		if name == "" {
			name = fmt.Sprintf("program-%d", attached.ID)
		}
		owners = append(owners, name)
	}
	return owners, nil
}

func (b *CgroupBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	attachOrder := make([]int, 0, cgroupProgramCount)
	if b.runtime.programs[cgroupProgramSocketRelease] != nil {
		attachOrder = append(attachOrder, cgroupProgramSocketRelease)
	}
	for slot := range b.runtime.programs {
		if slot != cgroupProgramSocketRelease {
			attachOrder = append(attachOrder, slot)
		}
	}
	for _, slot := range attachOrder {
		program := b.runtime.programs[slot]
		if program == nil {
			continue
		}
		programLink, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  cgroupFD,
			Program: program,
			Attach:  cgroupProgramDefinitions[slot].attachType,
		})
		if err == nil {
			b.runtime.links[slot] = programLink
			b.runtime.attach_modes[slot] = cgroupAttachModeLinkCreate
		} else if cgroupLinkUnavailable(err) {
			var attachment legacyCgroupAttachment
			attachment, err = attachProgramRawWithMode(cgroupFD, program, cgroupProgramDefinitions[slot].attachType, true)
			if err == nil {
				b.runtime.attach_modes[slot] = attachment.mode
				b.runtime.displaced[slot] = attachment.displaced
			}
		}
		if err != nil {
			_ = b.detachProgramsLocked()
			return eBPFBackendOperationError("attach eBPF cgroup programs", cgroupProgramDefinitions[slot].name, err)
		}
		b.runtime.attached[slot] = true
	}
	if b.runtime.enable_udp && b.runtime.socket_release_supported &&
		!b.runtime.attached[cgroupProgramSocketRelease] {
		_ = b.detachProgramsLocked()
		return eBPFOperationError("attach eBPF cgroup UDP cleanup", unix.EINVAL)
	}
	return nil
}

func cgroupLinkUnavailable(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, linuxErrnoNotSupported)
}

func (b *CgroupBackend) detachProgramsLocked() error {
	if b.runtime == nil || b.runtime.cgroupFile == nil {
		return nil
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	var detachErr error
	for slot := cgroupProgramCount - 1; slot >= 0; slot-- {
		if !b.runtime.attached[slot] {
			continue
		}
		programLink := b.runtime.links[slot]
		var err error
		if programLink != nil {
			err = programLink.Close()
			b.runtime.links[slot] = nil
			b.runtime.attached[slot] = false
			b.runtime.attach_modes[slot] = ""
			if err != nil {
				detachErr = E.Errors(detachErr, err)
			}
			continue
		} else if displaced := b.runtime.displaced[slot]; displaced != nil {
			// Put the netd placeholder back in place of our program. A
			// failure keeps the displaced owner for a cleanup retry.
			err = restoreDisplacedCgroupOwner(cgroupFD, b.runtime.programs[slot], displaced, cgroupProgramDefinitions[slot].attachType)
			if err == nil {
				b.runtime.displaced[slot] = nil
			}
		} else {
			err = rawDetachProgram(cgroupFD, b.runtime.programs[slot], cgroupProgramDefinitions[slot].attachType)
		}
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			b.runtime.attached[slot] = false
			b.runtime.attach_modes[slot] = ""
			continue
		}
		detachErr = E.Errors(detachErr, err)
	}
	return detachErr
}

// DisplacedHooks names the hooks where attaching replaced a program another
// owner had attached exclusively, with that program's name. Each is put back
// when the backend detaches.
func (b *CgroupBackend) DisplacedHooks() []string {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	var hooks []string
	for slot, displaced := range b.runtime.displaced {
		if displaced == nil {
			continue
		}
		name := "unnamed"
		if info, err := displaced.program.Info(); err == nil && info.Name != "" {
			name = info.Name
		}
		hooks = append(hooks, cgroupProgramDefinitions[slot].attachType.String()+" ("+name+")")
	}
	return hooks
}

func lenOpenCgroupProgramLinks(links []cgroupProgramLink) int {
	count := 0
	for _, l := range links {
		if l != nil {
			count++
		}
	}
	return count
}
