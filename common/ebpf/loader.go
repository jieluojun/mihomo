//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	BPFGen "github.com/metacubex/mihomo/common/ebpf/internal/bpfgen"
	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const bpfFlagNoPrealloc = 1

var rawAttachProgram = link.RawAttachProgram
var queryCgroupPrograms = link.QueryPrograms

var loadTC = BPFGen.LoadTC

var loadCgroup = BPFGen.LoadCgroup

var loadCgroupCoarse = BPFGen.LoadCgroupCoarse

var loadSharedNetwork = BPFGen.LoadSharedNetwork

var loadFakeIPICMP = BPFGen.LoadFakeIPICMP

const (
	cgroupAttachModeLinkCreate      = "link_create"
	cgroupAttachModeLegacyMulti     = "legacy_multi"
	cgroupAttachModeLegacyExclusive = "legacy_exclusive"
	// cgroupAttachModeNetdReplace is an unflagged attach that replaced the
	// pass-through placeholder Android netd holds on the hook. The hook stays
	// in single-program mode and the placeholder returns on detach.
	cgroupAttachModeNetdReplace = "legacy_netd_replace"
)

// legacyCgroupAttachment describes a successful legacy BPF_PROG_ATTACH: the
// variant that succeeded and, for cgroupAttachModeNetdReplace, the program it
// displaced, which the owner of the attachment must restore on detach.
type legacyCgroupAttachment struct {
	mode      string
	displaced *displacedCgroupOwner
}

// attachProgramRaw is the legacy attach of optional components. It never
// displaces an existing owner, not even a pass-through one.
func attachProgramRaw(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	_, err := attachProgramRawWithMode(target, program, attachType, false)
	return err
}

// attachProgramRawMultiOnly is used for optional capability probes. Probes
// must never fall back to the unflagged legacy operation because that variant
// replaces an existing exclusive cgroup owner. A denied multi attach simply
// means that the optional capability is unavailable.
func attachProgramRawMultiOnly(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	return rawAttachProgram(link.RawAttachProgramOptions{
		Target:  target,
		Program: program,
		Attach:  attachType,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	})
}

// attachProgramRawWithMode reports the legacy attach variant that actually
// succeeded. The distinction is operationally important on Android: a
// vendor kernel can reject BPF_F_ALLOW_MULTI while still accepting the
// single-program legacy operation. Callers must expose the effective path,
// not merely the attempted fast path.
//
// replacePassThrough lets the attach replace a pass-through owner, such as the
// placeholder Android 15+ netd keeps on the root socket-address hooks (see
// cgroup_netd.go). Only the interception backend sets it: it has no fallback,
// and it restores the displaced owner on detach.
func attachProgramRawWithMode(
	target int,
	program *CiliumEBPF.Program,
	attachType CiliumEBPF.AttachType,
	replacePassThrough bool,
) (legacyCgroupAttachment, error) {
	options := link.RawAttachProgramOptions{
		Target:  target,
		Program: program,
		Attach:  attachType,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	}
	multiErr := rawAttachProgram(options)
	if multiErr == nil {
		return legacyCgroupAttachment{mode: cgroupAttachModeLegacyMulti}, nil
	}
	if !cgroupMultiAttachUnavailable(multiErr) {
		return legacyCgroupAttachment{}, multiErr
	}
	// An unflagged legacy attach replaces the current exclusive owner. Do not
	// displace a vendor/OS cgroup hook that we cannot restore after shutdown;
	// callers will use their userspace fallback instead. The one exception is
	// a pass-through owner when replacePassThrough is set: it is held open and
	// restored on detach. Kernels without BPF_PROG_QUERY retain the historical
	// fallback because there is no safe way to distinguish an empty hook from
	// an unqueryable one.
	if result, queryErr := queryCgroupPrograms(link.QueryOptions{Target: target, Attach: attachType}); queryErr == nil && len(result.Programs) > 0 {
		if replacePassThrough {
			// Only the interception backend owns the exclusive cgroup lock.
			if _, cleanupErr := detachOwnedCgroupProgramsForAttach(target, attachType); cleanupErr != nil {
				return legacyCgroupAttachment{}, E.Cause(cleanupErr, "clean stale eBPF cgroup program")
			}
		}
		result, queryErr = queryCgroupPrograms(link.QueryOptions{Target: target, Attach: attachType})
		if queryErr != nil {
			return legacyCgroupAttachment{}, queryErr
		}
		if len(result.Programs) > 0 {
			var keptReason error
			if replacePassThrough {
				var displaced *displacedCgroupOwner
				displaced, keptReason = displaceableCgroupOwner(target, attachType, result.Programs)
				if displaced != nil {
					if err := replaceCgroupOwner(target, program, attachType, displaced.flags); err != nil {
						_ = displaced.Close()
						return legacyCgroupAttachment{}, err
					}
					return legacyCgroupAttachment{mode: cgroupAttachModeNetdReplace, displaced: displaced}, nil
				}
			}
			owners, ownerErr := cgroupProgramOwnerNames(result)
			if ownerErr != nil {
				return legacyCgroupAttachment{}, E.Cause(ownerErr, "refusing to replace existing cgroup program owner (unable to identify existing program)")
			}
			message := "refusing to replace existing cgroup program owner(s): " + strings.Join(owners, ", ")
			if keptReason != nil {
				return legacyCgroupAttachment{}, E.Cause(keptReason, message)
			}
			return legacyCgroupAttachment{}, E.New(message)
		}
	}
	// Keep the legacy fallback used before multi-only attachment was adopted.
	// Some vendor kernels reject ALLOW_MULTI for otherwise usable hooks. An
	// unflagged attach can replace an existing single-program attachment, so it
	// is attempted only after errors known to indicate unavailable multi attach.
	options.Flags = 0
	if err := rawAttachProgram(options); err != nil {
		return legacyCgroupAttachment{}, err
	}
	return legacyCgroupAttachment{mode: cgroupAttachModeLegacyExclusive}, nil
}

func cgroupMultiAttachUnavailable(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, linuxErrnoNotSupported)
}

// rawDetachProgram is a variable so tests can observe the detach that
// precedes restoring a displaced owner without a kernel object.
var rawDetachProgram = func(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	return link.RawDetachProgram(link.RawDetachProgramOptions{Target: target, Program: program, Attach: attachType})
}

func sameProgramIDs(left, right []CiliumEBPF.ProgramID) bool {
	return slices.Equal(left, right)
}

func verifierErrorStage(err error) string {
	var verifierErr *CiliumEBPF.VerifierError
	if errors.As(err, &verifierErr) {
		return fmt.Sprintf("verifier rejected program: %v", verifierErr)
	}
	return ""
}

type programSelection struct {
	section string
	name    string
}

type mapSpecOverride struct {
	name       string
	mapType    CiliumEBPF.MapType
	maxEntries uint32
	flags      uint32
}

func loadObjectMaps(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	overrides map[string]mapSpecOverride,
) (map[string]*CiliumEBPF.Map, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, E.Cause(err, "parse eBPF object")
	}
	clear(spec.Programs)
	for name, mapSpec := range spec.Maps {
		override, selected := overrides[name]
		if !selected {
			delete(spec.Maps, name)
			continue
		}
		if override.name == "" || override.mapType == CiliumEBPF.UnspecifiedMap ||
			override.maxEntries == 0 {
			return nil, E.New("invalid eBPF map override for ", name)
		}
		mapSpec.Name = override.name
		mapSpec.Type = override.mapType
		mapSpec.MaxEntries = override.maxEntries
		mapSpec.Flags = override.flags
		mapSpec.Extra = nil
	}
	for name := range overrides {
		if spec.Maps[name] == nil {
			return nil, E.New("eBPF object is missing map ", name)
		}
	}
	collection, err := CiliumEBPF.NewCollection(spec)
	if err != nil {
		return nil, eBPFOperationError("create eBPF maps", err)
	}
	maps := make(map[string]*CiliumEBPF.Map, len(collection.Maps))
	for name, mapInstance := range collection.Maps {
		maps[name] = mapInstance
		delete(collection.Maps, name)
	}
	collection.Close()
	return maps, nil
}

func loadObjectPrograms(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]*CiliumEBPF.Map,
	selections []programSelection,
) ([]*CiliumEBPF.Program, error) {
	return loadObjectProgramsWithOptions(loadSpec, maps, selections, CiliumEBPF.ProgramOptions{})
}

func loadObjectProgramsWithOptions(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]*CiliumEBPF.Map,
	selections []programSelection,
	programOptions CiliumEBPF.ProgramOptions,
) ([]*CiliumEBPF.Program, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, E.Cause(err, "parse eBPF object")
	}
	selectedSections := make(map[string]int, len(selections))
	for index, selection := range selections {
		selectedSections[selection.section] = index
	}
	programSymbols := make([]string, len(selections))
	for symbol, program := range spec.Programs {
		index, selected := selectedSections[program.SectionName]
		if !selected {
			delete(spec.Programs, symbol)
			continue
		}
		if program.Type == CiliumEBPF.UnspecifiedProgram {
			return nil, E.New("eBPF program section has unknown type: ", program.SectionName)
		}
		program.Name = selections[index].name
		programSymbols[index] = symbol
	}
	for index, symbol := range programSymbols {
		if symbol == "" {
			return nil, E.New("eBPF object is missing program section ", selections[index].section)
		}
	}
	for name := range spec.Maps {
		if maps[name] == nil {
			delete(spec.Maps, name)
		}
	}
	for name, mapInstance := range maps {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return nil, E.New("eBPF object is missing map ", name)
		}
		info, infoErr := mapInstance.Info()
		if infoErr != nil {
			return nil, E.Cause(infoErr, "inspect replacement eBPF map ", name)
		}
		mapSpec.Type = info.Type
		mapSpec.KeySize = info.KeySize
		mapSpec.ValueSize = info.ValueSize
		mapSpec.MaxEntries = info.MaxEntries
		mapSpec.Flags = info.Flags
		mapSpec.Extra = nil
	}
	collection, err := CiliumEBPF.NewCollectionWithOptions(spec, CiliumEBPF.CollectionOptions{
		MapReplacements: maps,
		Programs:        programOptions,
	})
	if err != nil {
		return nil, eBPFOperationError("load eBPF programs", err)
	}
	programs := make([]*CiliumEBPF.Program, len(selections))
	for index, symbol := range programSymbols {
		programs[index] = collection.DetachProgram(symbol)
		if programs[index] == nil {
			_ = closePrograms(programs)
			collection.Close()
			return nil, E.New("loaded eBPF collection is missing program ", symbol)
		}
	}
	collection.Close()
	return programs, nil
}

func closePrograms(programs []*CiliumEBPF.Program) error {
	var closeErr error
	for index, program := range slices.Backward(programs) {
		if program == nil {
			continue
		}
		closeErr = E.Errors(closeErr, program.Close())
		programs[index] = nil
	}
	return closeErr
}

func closeMaps(maps map[string]*CiliumEBPF.Map) error {
	var closeErr error
	for name, mapInstance := range maps {
		if mapInstance == nil {
			continue
		}
		closeErr = E.Errors(closeErr, mapInstance.Close())
		delete(maps, name)
	}
	return closeErr
}
