//go:build with_ebpf && (linux || android)

package ebpf

import (
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// UDPReleaseEvent is also the immutable recovery-payload key. The token index
// is only a bounded LRU hint; expiry never deletes an index a new socket owns.
type UDPReleaseEvent struct {
	SocketCookie uint64
	ReleasedAtNS uint64
}

func monotonicNowNS() uint64 {
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &now) != nil {
		return 0
	}
	return uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec)
}

func recoveryExpired(event UDPReleaseEvent, now uint64, idle time.Duration) bool {
	return event.ReleasedAtNS != 0 && idle > 0 && now >= event.ReleasedAtNS && now-event.ReleasedAtNS >= uint64(idle)
}

func (b *CgroupBackend) ReadUDPRelease(deadline time.Time) (UDPReleaseEvent, error) {
	if b == nil {
		return UDPReleaseEvent{}, unix.EOPNOTSUPP
	}
	b.udpReleaseReadAccess.Lock()
	defer b.udpReleaseReadAccess.Unlock()
	b.access.RLock()
	if b.runtime == nil || b.runtime.udpReleaseReader == nil {
		b.access.RUnlock()
		return UDPReleaseEvent{}, unix.EOPNOTSUPP
	}
	reader := b.runtime.udpReleaseReader
	b.access.RUnlock()
	reader.SetDeadline(deadline)
	record, err := reader.Read()
	if err != nil {
		return UDPReleaseEvent{}, err
	}
	if len(record.RawSample) != 16 {
		return UDPReleaseEvent{}, unix.EPROTO
	}
	event := UDPReleaseEvent{binary.NativeEndian.Uint64(record.RawSample[:8]), binary.NativeEndian.Uint64(record.RawSample[8:])}
	if event.SocketCookie == 0 || event.ReleasedAtNS == 0 {
		return UDPReleaseEvent{}, unix.EPROTO
	}
	return event, nil
}

func (b *CgroupBackend) DeleteUDPRecovery(event UDPReleaseEvent) error {
	if b == nil {
		return errBackendClosed
	}
	if event.ReleasedAtNS == 0 {
		return unix.EINVAL
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	err := deleteMap(b.runtime.maps["cgroup_udp_recovery_value"].FD(), unsafe.Pointer(&event))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// SweepUDPRecovery also covers overflow, unsupported ring buffers and recovery
// records produced by userspace idle cleanup. Iteration is resumable and bound
// by budget even on kernels with batch operations.
func (b *CgroupBackend) SweepUDPRecovery(budget uint32) (bool, error) {
	if b == nil {
		return true, nil
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.runtime.enable_udp {
		return true, nil
	}
	m := b.runtime.maps["cgroup_udp_recovery_value"]
	now, idle := monotonicNowNS(), time.Duration(b.udpTimeoutSeconds)*time.Second
	var expired []UDPReleaseEvent
	scan, err := b.recoverySweepScratch.scanFallback(m.FD(), min(b.mapCapacity.UDPRedirect, uint32(UDPRecoveryMapCapacity)), budget,
		func(key UDPReleaseEvent, _ originalDestinationValue) {
			if recoveryExpired(key, now, idle) {
				expired = append(expired, key)
			}
		})
	if err != nil {
		return false, err
	}
	for _, key := range expired {
		if err = deleteMap(m.FD(), unsafe.Pointer(&key)); err != nil && !errors.Is(err, unix.ENOENT) {
			return false, err
		}
	}
	return scan.Complete, nil
}

type udpReleaseQueue []UDPReleaseEvent

func (q udpReleaseQueue) Len() int           { return len(q) }
func (q udpReleaseQueue) Less(i, j int) bool { return q[i].ReleasedAtNS < q[j].ReleasedAtNS }
func (q udpReleaseQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *udpReleaseQueue) Push(v any)        { *q = append(*q, v.(UDPReleaseEvent)) }
func (q *udpReleaseQueue) Pop() any {
	previous := *q
	last := previous[len(previous)-1]
	*q = previous[:len(previous)-1]
	return last
}

// RunUDPRecoveryCleanup keeps late-packet recovery for the configured UDP
// timeout, then retires that release's exact payload. Its queue is bounded;
// the ordinary janitor covers events dropped by either queue.
func (b *CgroupBackend) RunUDPRecoveryCleanup(ctx context.Context) error {
	queue := make(udpReleaseQueue, 0, 64)
	for ctx.Err() == nil {
		b.access.RLock()
		idle := time.Duration(b.udpTimeoutSeconds) * time.Second
		b.access.RUnlock()
		now := monotonicNowNS()
		for queue.Len() > 0 && recoveryExpired(queue[0], now, idle) {
			if err := b.DeleteUDPRecovery(heap.Pop(&queue).(UDPReleaseEvent)); err != nil {
				return err
			}
		}
		event, err := b.ReadUDPRelease(time.Now().Add(time.Second))
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			b.access.Lock()
			if b.runtime != nil {
				b.runtime.udpReleaseFallback = "ringbuf_read_failed"
			}
			b.access.Unlock()
			return err
		}
		if queue.Len() < UDPRecoveryMapCapacity {
			heap.Push(&queue, event)
		} else {
			b.udpReleaseQueueDrops.Add(1)
		}
	}
	return nil
}

func (b *CgroupBackend) UDPReleaseNotificationDrops() (uint64, error) {
	if b == nil {
		return 0, unix.EOPNOTSUPP
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return 0, errBackendClosed
	}
	stats := b.runtime.maps["cgroup_udp_release_stats"]
	if stats == nil {
		return 0, unix.EOPNOTSUPP
	}
	var counts []uint64
	if err := stats.Lookup(uint32(0), &counts); err != nil {
		return 0, err
	}
	total := b.udpReleaseQueueDrops.Load()
	for _, n := range counts {
		total += n
	}
	return total, nil
}

type UDPStateDiagnostics struct {
	CleanupMode          string `json:"cleanup_mode"`
	RecoveryMode         string `json:"recovery_mode"`
	UserspaceCleanupMode string `json:"userspace_cleanup_mode"`
	FallbackReason       string `json:"fallback_reason,omitempty"`
	ReleaseDrops         uint64 `json:"release_drops"`
}

func (b *CgroupBackend) UDPStateDiagnostics() UDPStateDiagnostics {
	d := UDPStateDiagnostics{CleanupMode: cgroupUDPCleanupDisabled, RecoveryMode: "reverse_index", UserspaceCleanupMode: "deadline"}
	if b == nil {
		return d
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return d
	}
	d.CleanupMode = cgroupUDPCleanupModeLocked(b.runtime)
	d.FallbackReason = b.runtime.udpReleaseFallback
	if b.runtime.udpReleaseReader != nil && b.runtime.udpReleaseFallback == "" {
		d.UserspaceCleanupMode = "ringbuf"
	}
	d.ReleaseDrops = b.udpReleaseQueueDrops.Load()
	if stats := b.runtime.maps["cgroup_udp_release_stats"]; stats != nil {
		var counts []uint64
		if stats.Lookup(uint32(0), &counts) == nil {
			for _, n := range counts {
				d.ReleaseDrops += n
			}
		}
	}
	return d
}
