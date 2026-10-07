//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

const (
	selfBypassSocketCapacity        = 65536
	CompactSelfBypassSocketCapacity = 16384
)

// SelfBypass owns the socket-cookie map used by the local TC classifier. The
// map is populated by cgroup hooks when the process has an exclusive cgroup,
// or by the socket control callback when cgroup attachment is unavailable.
type SelfBypass struct {
	access   sync.RWMutex
	sockets  *CiliumEBPF.Map
	programs []*CiliumEBPF.Program
	links    []cgroupProgramLink
	mode     atomic.Uint32
}

type SelfBypassCgroupConfig struct {
	EnableTCP  bool
	EnableUDP  bool
	EnableIPv6 bool
}

type SelfBypassMode uint32

const (
	SelfBypassUserspace SelfBypassMode = iota
	SelfBypassCgroupSocket
	SelfBypassCgroupSocketAddr
	// SelfBypassUserspaceRelease keeps userspace socket registration while
	// using a cgroup sock_release hook for lifecycle cleanup. This is useful
	// when socket-create/connect hooks are unavailable, including TC-only
	// deployments where the cgroup data plane is not loaded.
	SelfBypassUserspaceRelease
)

func (m SelfBypassMode) String() string {
	switch m {
	case SelfBypassCgroupSocket:
		return "cgroup_socket_cookie"
	case SelfBypassCgroupSocketAddr:
		return "cgroup_socket_addr"
	case SelfBypassUserspaceRelease:
		return "userspace_socket_cookie_release"
	default:
		return "userspace_socket_cookie"
	}
}

// CleanupMode reports how entries in the self-bypass map are removed.
// lru_fallback is a safety net, not a precise socket lifecycle mechanism.
func (m SelfBypassMode) CleanupMode() string {
	switch m {
	case SelfBypassCgroupSocket, SelfBypassUserspaceRelease:
		return "socket_release"
	default:
		return "lru_fallback"
	}
}

func NewSelfBypass() (*SelfBypass, error) {
	return NewSelfBypassWithCapacity(selfBypassSocketCapacity)
}

func NewSelfBypassWithCapacity(capacity uint32) (*SelfBypass, error) {
	if capacity == 0 || capacity > MaxConfigurableMapCapacity {
		return nil, E.New("invalid eBPF self-bypass socket map capacity: ", capacity)
	}
	_ = raiseMemlockLimit()
	sockets, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_self_sockets",
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: capacity,
	})
	if err != nil {
		return nil, E.Cause(err, "create eBPF self-bypass socket map")
	}
	return &SelfBypass{sockets: sockets}, nil
}

// Map returns the map that must be shared with the local TC programs. The map
// is borrowed: callers must not close or retain it beyond SelfBypass.Close.
func (b *SelfBypass) Map() *CiliumEBPF.Map {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.sockets
}

// AttachCgroup enables automatic socket-cookie registration when the current
// cgroup is exclusive to this process. It first tries socket create/release
// hooks, then connect/sendmsg hooks for kernels that expose only the latter.
// When those hooks cannot be used, it still attempts a release-only hook so
// userspace registration does not leave entries behind on pure TC systems.
// A failure leaves the map usable by the userspace registration fallback.
func (b *SelfBypass) AttachCgroup(config SelfBypassCgroupConfig) error {
	if b == nil {
		return E.New("eBPF self-bypass map is unavailable")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.sockets == nil {
		return E.New("eBPF self-bypass map is unavailable")
	}
	if b.mode.Load() != uint32(SelfBypassUserspace) {
		return nil
	}
	if lenOpenCgroupProgramLinks(b.links) > 0 {
		if err := b.closeHooks(); err != nil {
			return E.Cause(err, "finish previous eBPF self-bypass cleanup")
		}
	}
	cgroupPath, err := DetectProcessCgroup2Path()
	if err != nil {
		return E.Cause(err, "detect process cgroup v2")
	}
	exclusive, exclusiveErr := processCgroupExclusive(cgroupPath)
	var attachErrors []error
	if exclusiveErr != nil {
		attachErrors = append(attachErrors, exclusiveErr)
	}
	if exclusive {
		createReleaseErr := b.attachCgroupSocket(cgroupPath)
		if createReleaseErr == nil {
			b.mode.Store(uint32(SelfBypassCgroupSocket))
			return nil
		}
		attachErrors = append(attachErrors, createReleaseErr)
		if lenOpenCgroupProgramLinks(b.links) > 0 {
			return E.Errors(attachErrors...)
		}
		socketAddrErr := b.attachCgroupSocketAddr(cgroupPath, config)
		if socketAddrErr == nil {
			b.mode.Store(uint32(SelfBypassCgroupSocketAddr))
			return nil
		}
		attachErrors = append(attachErrors, socketAddrErr)
		if lenOpenCgroupProgramLinks(b.links) > 0 {
			return E.Errors(attachErrors...)
		}
	} else if exclusiveErr == nil {
		attachErrors = append(attachErrors, E.New("process cgroup contains other processes"))
	}

	// A release-only hook is safe on a shared cgroup: it only deletes entries
	// whose cookies are already present in our map, and never marks sockets.
	if releaseErr := b.attachCgroupRelease(cgroupPath); releaseErr == nil {
		b.mode.Store(uint32(SelfBypassUserspaceRelease))
		return nil
	} else {
		attachErrors = append(attachErrors, releaseErr)
	}
	return E.Errors(attachErrors...)
}

func (b *SelfBypass) CgroupAttached() bool {
	if b == nil {
		return false
	}
	mode := SelfBypassMode(b.mode.Load())
	return mode == SelfBypassCgroupSocket || mode == SelfBypassCgroupSocketAddr
}

func (b *SelfBypass) Mode() SelfBypassMode {
	if b == nil {
		return SelfBypassUserspace
	}
	return SelfBypassMode(b.mode.Load())
}

func (b *SelfBypass) attachCgroupSocket(path string) error {
	createProgram, err := newSelfBypassCreateProgram(b.sockets.FD())
	if err != nil {
		return err
	}
	releaseProgram, err := newSelfBypassReleaseProgram(b.sockets.FD())
	if err != nil {
		_ = createProgram.Close()
		return err
	}
	createLink, err := attachCgroupProgram(path, createProgram, CiliumEBPF.AttachCGroupInetSockCreate)
	if err != nil {
		_ = releaseProgram.Close()
		_ = createProgram.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-create hook")
	}
	releaseLink, err := attachCgroupProgram(path, releaseProgram, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		_ = releaseProgram.Close()
		b.programs = []*CiliumEBPF.Program{createProgram}
		b.links = []cgroupProgramLink{createLink}
		return E.Errors(
			E.Cause(err, "attach eBPF self-bypass socket-release hook"),
			b.closeHooks(),
		)
	}
	b.programs = []*CiliumEBPF.Program{createProgram, releaseProgram}
	b.links = []cgroupProgramLink{createLink, releaseLink}
	return nil
}

func (b *SelfBypass) attachCgroupRelease(path string) error {
	program, err := newSelfBypassReleaseProgram(b.sockets.FD())
	if err != nil {
		return err
	}
	programLink, err := attachCgroupProgram(path, program, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		_ = program.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-release cleanup hook")
	}
	b.programs = []*CiliumEBPF.Program{program}
	b.links = []cgroupProgramLink{programLink}
	return nil
}

func (b *SelfBypass) attachCgroupSocketAddr(path string, config SelfBypassCgroupConfig) error {
	hooks := selfBypassSocketAddrHooks(config)
	programs := make([]*CiliumEBPF.Program, 0, len(hooks))
	links := make([]cgroupProgramLink, 0, len(hooks))
	closeAttached := func() error {
		b.programs = programs
		b.links = links
		return b.closeHooks()
	}
	for _, hook := range hooks {
		program, err := newSelfBypassSocketAddrProgram(b.sockets.FD(), hook)
		if err != nil {
			return E.Errors(err, closeAttached())
		}
		programs = append(programs, program)
		programLink, err := attachCgroupProgram(path, program, hook.attachType)
		if err != nil {
			return E.Errors(E.Cause(err, "attach eBPF self-bypass ", hook.hookName, " hook"), closeAttached())
		}
		links = append(links, programLink)
	}
	b.programs = programs
	b.links = links
	return nil
}

type selfBypassSocketAddrHook struct {
	hookName          string
	kernelProgramName string
	attachType        CiliumEBPF.AttachType
}

func selfBypassSocketAddrHooks(config SelfBypassCgroupConfig) []selfBypassSocketAddrHook {
	hooks := make([]selfBypassSocketAddrHook, 0, 4)
	if config.EnableTCP {
		hooks = append(hooks, selfBypassSocketAddrHook{"connect4", "sb_self_conn4", CiliumEBPF.AttachCGroupInet4Connect})
		if config.EnableIPv6 {
			hooks = append(hooks, selfBypassSocketAddrHook{"connect6", "sb_self_conn6", CiliumEBPF.AttachCGroupInet6Connect})
		}
	}
	if config.EnableUDP {
		hooks = append(hooks, selfBypassSocketAddrHook{"sendmsg4", "sb_self_send4", CiliumEBPF.AttachCGroupUDP4Sendmsg})
		if config.EnableIPv6 {
			hooks = append(hooks, selfBypassSocketAddrHook{"sendmsg6", "sb_self_send6", CiliumEBPF.AttachCGroupUDP6Sendmsg})
		}
	}
	return hooks
}

func newSelfBypassCreateProgram(mapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "sb_self_create",
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCGroupInetSockCreate,
		License:      "GPL",
		Instructions: selfBypassCreateInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-create hook")
	}
	return program, nil
}

func newSelfBypassReleaseProgram(mapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "sb_self_release",
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCgroupInetSockRelease,
		License:      "GPL",
		Instructions: selfBypassReleaseInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-release hook")
	}
	return program, nil
}

func newSelfBypassSocketAddrProgram(mapFD int, hook selfBypassSocketAddrHook) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         hook.kernelProgramName,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   hook.attachType,
		License:      "GPL",
		Instructions: selfBypassSocketAddrInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass ", hook.hookName, " hook")
	}
	return program, nil
}

func selfBypassCreateInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.StoreImm(asm.RFP, -12, 1, asm.Word),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -12),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

func selfBypassReleaseInstructions(mapFD int) asm.Instructions {
	return socketCookieDeleteInstructions(mapFD)
}

func socketCookieDeleteInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

func selfBypassSocketAddrInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "mark"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.Mov.Reg(asm.R5, asm.R0),
		asm.And.Imm(asm.R5, SocketMetadataSelfBypass),
		asm.JNE.Imm(asm.R5, 0, "allow"),
		asm.Or.Imm(asm.R0, SocketMetadataSelfBypass),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.Ja.Label("update"),
		asm.StoreImm(asm.RFP, -12, SocketMetadataSelfBypass, asm.Word).WithSymbol("mark"),
		asm.LoadMapPtr(asm.R1, mapFD).WithSymbol("update"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -12),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

// RegisterSocket records a socket created by the consumer when cgroup hooks
// cannot mark it automatically. It performs one SO_COOKIE read and one map
// update per socket.
func (b *SelfBypass) RegisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.sockets == nil {
		return nil
	}
	var cookie uint64
	err := control.Raw(rawConn, func(fd uintptr) error {
		var err error
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		return err
	})
	if err != nil {
		return E.Cause(err, "read socket cookie for eBPF self-bypass")
	}
	if cookie == 0 {
		return E.New("socket returned an empty eBPF self-bypass cookie")
	}
	value := uint32(1)
	if err = b.sockets.Update(&cookie, &value, CiliumEBPF.UpdateAny); err != nil {
		return E.Cause(err, "register eBPF self-bypass socket")
	}
	return nil
}

// UnregisterSocket removes a socket previously registered by RegisterSocket.
// Call it before closing the socket when no kernel release hook is active.
// The cookie is read from the supplied live socket, so deletion cannot target
// a different socket that reused an old descriptor.
func (b *SelfBypass) UnregisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.sockets == nil || b.CgroupAttached() {
		return nil
	}
	var cookie uint64
	err := control.Raw(rawConn, func(fd uintptr) error {
		var err error
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		return err
	})
	if err != nil {
		return E.Cause(err, "read socket cookie for eBPF self-bypass unregister")
	}
	if cookie == 0 {
		return nil
	}
	if err = b.sockets.Delete(&cookie); err != nil {
		return E.Cause(err, "unregister eBPF self-bypass socket")
	}
	return nil
}

func processCgroupExclusive(path string) (bool, error) {
	pid := os.Getpid()
	found, exclusive, err := readExclusiveCgroupMembers(path, pid)
	if err != nil || !exclusive || !found {
		return found && exclusive, err
	}
	return inspectExclusiveCgroupDescendants(path)
}

func readExclusiveCgroupMembers(path string, pid int) (found bool, exclusive bool, err error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, false, E.Cause(err, "read process cgroup members")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		member, parseErr := strconv.Atoi(line)
		if parseErr != nil {
			return false, false, E.Cause(parseErr, "parse process cgroup member")
		}
		if member != pid {
			return found, false, nil
		}
		found = true
	}
	if err = scanner.Err(); err != nil {
		return false, false, E.Cause(err, "read process cgroup members")
	}
	return found, true, nil
}

func inspectExclusiveCgroupDescendants(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, E.Cause(err, "read process cgroup children")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		childPath := filepath.Join(path, entry.Name())
		populated, childErr := cgroupHasMembers(childPath)
		if childErr != nil {
			return false, childErr
		}
		if populated {
			return false, nil
		}
		childExclusive, childErr := inspectExclusiveCgroupDescendants(childPath)
		if childErr != nil || !childExclusive {
			return false, childErr
		}
	}
	return true, nil
}

func cgroupHasMembers(path string) (bool, error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, E.Cause(err, "read child cgroup members")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() != "" {
			return true, nil
		}
	}
	if err = scanner.Err(); err != nil {
		return false, E.Cause(err, "read child cgroup members")
	}
	return false, nil
}

func (b *SelfBypass) closeHooks() error {
	if b == nil {
		return nil
	}
	var closeErr error
	linksClosed := true
	for index := len(b.links) - 1; index >= 0; index-- {
		if b.links[index] != nil {
			linkErr := b.links[index].Close()
			closeErr = E.Errors(closeErr, linkErr)
			if cgroupProgramLinkCloseComplete(b.links[index], linkErr) {
				b.links[index] = nil
			} else {
				linksClosed = false
			}
		}
	}
	if !linksClosed {
		return closeErr
	}
	for index := len(b.programs) - 1; index >= 0; index-- {
		if b.programs[index] != nil {
			closeErr = E.Errors(closeErr, b.programs[index].Close())
			b.programs[index] = nil
		}
	}
	b.links = nil
	b.programs = nil
	b.mode.Store(uint32(SelfBypassUserspace))
	return closeErr
}

func (b *SelfBypass) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	closeErr := b.closeHooks()
	if lenOpenCgroupProgramLinks(b.links) > 0 {
		return closeErr
	}
	if b.sockets != nil {
		closeErr = E.Errors(closeErr, b.sockets.Close())
		b.sockets = nil
	}
	return closeErr
}

func (b *SelfBypass) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.sockets == nil && lenOpenCgroupProgramLinks(b.links) == 0
}
