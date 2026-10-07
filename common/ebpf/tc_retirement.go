//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

type tcRetiredKey struct {
	Flow       tcAssignKey
	Reserved   uint32
	Generation uint64
}

// DeleteUDPAssignment retires exactly the assignment observed by the caller.
// The kernel can concurrently publish a newer generation; it is never deleted.
// The next packet rebuilds retired metadata, while bounded LRUs reclaim storage.
func (b *TCBackend) DeleteUDPAssignment(source, destination netip.AddrPort, interfaceIndex uint32, expected TCAssignment) error {
	if b == nil {
		return errBackendClosed
	}
	if expected.Generation == 0 {
		return unix.EINVAL
	}
	key, err := makeTCAssignKey(ProtocolUDP, source, destination, interfaceIndex)
	if err != nil {
		return err
	}
	identity := tcRetiredKey{Flow: key, Generation: expected.Generation}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	value := uint8(1)
	return updateMap(b.runtime.maps["tc_retired_assignment"].FD(), unsafe.Pointer(&identity), unsafe.Pointer(&value))
}
