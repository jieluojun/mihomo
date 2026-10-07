//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"slices"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestRawCgroupAttachPrefersMulti(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	callCount := 0
	var options link.RawAttachProgramOptions
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		callCount++
		options = current
		return nil
	}
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("raw attach called %d times, want one multi-program attempt", callCount)
	}
	if options.Target != 42 || options.Attach != CiliumEBPF.AttachCgroupInetSockRelease || options.Flags != unix.BPF_F_ALLOW_MULTI {
		t.Fatalf("raw attach options = %+v, want target=42 attach=socket_release flags=BPF_F_ALLOW_MULTI", options)
	}
}

func TestRawCgroupAttachMultiOnlyNeverFallsBack(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	callCount := 0
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		callCount++
		if current.Flags != unix.BPF_F_ALLOW_MULTI {
			t.Fatalf("multi-only probe used flags %#x", current.Flags)
		}
		return unix.EPERM
	}
	if err := attachProgramRawMultiOnly(42, nil, CiliumEBPF.AttachCgroupInetSockRelease); !errors.Is(err, unix.EPERM) {
		t.Fatalf("multi-only attach error = %v, want EPERM", err)
	}
	if callCount != 1 {
		t.Fatalf("multi-only attach called %d times, want one attempt", callCount)
	}
}

func TestRawCgroupAttachFallsBackToExclusiveAfterMultiCompatibilityError(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	var flags []uint32
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		if current.Target != 42 || current.Attach != CiliumEBPF.AttachCGroupInet4Connect {
			t.Fatalf("unexpected attach options: %+v", current)
		}
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	}
	if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
		t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
	}
}

func TestRawCgroupAttachPreservesExistingOwner(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	originalQuery := queryCgroupPrograms
	originalProgramNameByID := programNameByID
	t.Cleanup(func() {
		rawAttachProgram = originalRawAttachProgram
		queryCgroupPrograms = originalQuery
		programNameByID = originalProgramNameByID
	})
	var flags []uint32
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	}
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{Programs: []link.AttachedProgram{{ID: 1}}}, nil
	}
	programNameByID = func(CiliumEBPF.ProgramID) (string, error) { return "netd_conn4", nil }
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err == nil {
		t.Fatal("existing cgroup owner was replaced")
	}
	if !strings.Contains(err.Error(), "netd_conn4") {
		t.Fatalf("error = %v, want existing owner name", err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only the non-destructive multi attach", flags)
	}
}

func TestRawCgroupAttachFallbackErrors(t *testing.T) {
	for _, multiErr := range []error{
		unix.EINVAL,
		unix.EPERM,
		unix.ENOTSUP,
		unix.EOPNOTSUPP,
		linuxErrnoNotSupported,
	} {
		t.Run(multiErr.Error(), func(t *testing.T) {
			originalRawAttachProgram := rawAttachProgram
			t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
			var flags []uint32
			rawAttachProgram = func(current link.RawAttachProgramOptions) error {
				flags = append(flags, current.Flags)
				if current.Flags == unix.BPF_F_ALLOW_MULTI {
					return multiErr
				}
				return nil
			}
			if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
				t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
			}
		})
	}
}

func TestRawCgroupAttachDoesNotFallbackOnFatalError(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	wantErr := unix.EACCES
	callCount := 0
	rawAttachProgram = func(link.RawAttachProgramOptions) error {
		callCount++
		return wantErr
	}
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if callCount != 1 {
		t.Fatalf("raw attach called %d times, want no exclusive fallback", callCount)
	}
}

func TestOwnedCgroupProgramNameIncludesLegacyPrefix(t *testing.T) {
	for _, testCase := range []struct {
		name string
		want bool
	}{
		{name: "sb_ebpf_conn4", want: true},
		{name: "sing_ebpf_conn4", want: true},
		{name: "cilium_conn4", want: false},
		{name: "", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ownedCgroupProgramName(testCase.name); got != testCase.want {
				t.Fatalf("ownedCgroupProgramName(%q)=%v, want %v", testCase.name, got, testCase.want)
			}
		})
	}
}
