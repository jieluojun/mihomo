//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

const udpIdleSweepBudget = 1024

// udpReplySocketMaxIdle bounds how long an unused transparent reply socket is
// kept. It is deliberately far below udp-timeout: a reply socket is keyed by
// original destination, and destinations cluster on a handful of well-known
// ports, so holding them for a session's whole lifetime is what fills the
// 16x64 pool on a gateway. A flow that is still exchanging packets keeps its
// socket regardless -- sweepIdle never touches a leased entry, which is what
// makes a short idle bound safe rather than merely cheap.
const udpReplySocketMaxIdle = 30 * time.Second

// udpTimeoutValue is the configured udp-timeout. A config reload can change it
// under a running inbound, so every reader goes through here rather than
// keeping a copy.
func (i *Inbound) udpTimeoutValue() time.Duration {
	return time.Duration(i.udpTimeout.Load())
}

// udpJanitorInterval paces the sweep at half the session timeout, bounded so a
// very short timeout does not spin and a very long one still notices a dead
// session within half a minute.
func (i *Inbound) udpJanitorInterval() time.Duration {
	interval := i.udpTimeoutValue() / 2
	if interval < time.Second {
		return time.Second
	}
	if interval > 30*time.Second {
		return 30 * time.Second
	}
	return interval
}

// udpReplySocketIdleTimeout keeps the bound under udp-timeout, so lowering that
// still lowers this.
func (i *Inbound) udpReplySocketIdleTimeout() time.Duration {
	return min(udpReplySocketMaxIdle, i.udpTimeoutValue())
}

var udpActivityEpoch = time.Now()

func udpActivityNow() int64 { return time.Since(udpActivityEpoch).Nanoseconds() }

type udpActivity struct {
	last    atomic.Int64
	pending atomic.Int64
}

func (a *udpActivity) touch()                 { a.last.Store(udpActivityNow()) }
func (a *udpActivity) retain()                { a.pending.Add(1) }
func (a *udpActivity) release()               { a.touch(); a.pending.Add(-1) }
func (a *udpActivity) idle(cutoff int64) bool { return a.pending.Load() == 0 && a.last.Load() < cutoff }

// Caller excludes ingress and reply handling with lifecycleAccess. Never
// expire packets queued in the tunnel or DNS requests still being resolved.
func (t *udpClientTable) expire(cutoff int64, all bool) []netip.Addr {
	progress := t.sweepProgress(all)
	var redirects []netip.Addr
	for progress.more() {
		redirects = append(redirects, t.expireBatch(cutoff, all, &progress)...)
	}
	return redirects
}

// expireUDPBatch drains one shard batch and removes the clients that still look
// idle. Written once for both client tables, which differ only in their state
// type and their removal call.
//
// The second idle check is load-bearing: the shard lock is dropped between
// selecting a client and removing it, so a client that becomes active in that
// window must not have its flow torn down.
func expireUDPBatch[S any, R any](
	shard *udpClientShard[S],
	count int,
	idle func(*S) bool,
	remove func(netip.AddrPort, *S) []R,
) []R {
	var candidates [udpIdleSweepBatch]*S
	var clients [udpIdleSweepBatch]netip.AddrPort
	shard.access.Lock()
	for n := 0; n < count; n++ {
		client, loaded := shard.sweep.advance()
		if !loaded {
			break
		}
		state := shard.clients[client]
		if idle(state) {
			candidates[n], clients[n] = state, client
		}
	}
	shard.access.Unlock()
	var results []R
	for n, state := range candidates {
		if state != nil && idle(state) {
			results = append(results, remove(clients[n], state)...)
		}
	}
	return results
}

func (t *udpClientTable) expireBatch(cutoff int64, all bool, progress *udpSweepProgress) []netip.Addr {
	idx, count := progress.nextBatch()
	if count == 0 {
		return nil
	}
	return expireUDPBatch(&t.clientShards[idx], count,
		func(state *udpClientState) bool { return all || state.activity.idle(cutoff) },
		t.delete)
}

func (t *sharedUDPClientTable) expire(cutoff int64, all bool) []sharedUDPRedirectRelease {
	progress := t.sweepProgress(all)
	var releases []sharedUDPRedirectRelease
	for progress.more() {
		releases = append(releases, t.expireBatch(cutoff, all, &progress)...)
	}
	return releases
}

func (t *sharedUDPClientTable) expireBatch(cutoff int64, all bool, progress *udpSweepProgress) []sharedUDPRedirectRelease {
	idx, count := progress.nextBatch()
	if count == 0 {
		return nil
	}
	return expireUDPBatch(&t.clientShards[idx], count,
		func(state *sharedUDPClientState) bool { return all || state.activity.idle(cutoff) },
		t.deleteShared)
}
func (i *Inbound) startUDPJanitor() {
	if !i.enableUDP {
		return
	}
	parent := i.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	i.udpJanitorCancel = cancel
	i.udpJanitorDone = make(chan struct{})
	go func() {
		interval := i.udpJanitorInterval()
		defer close(i.udpJanitorDone)
		timer := time.NewTimer(interval)
		defer timer.Stop()
		var round udpSweepRound
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				// Re-read every round: udp-timeout can be changed by a config
				// reload without the inbound being rebuilt, and a sweep pacing
				// itself off the value the process started with would keep
				// scanning on the old schedule for the rest of its life.
				interval = i.udpJanitorInterval()
				next := interval
				if i.expireUDP(udpActivityNow()-i.udpTimeout.Load(), &round) {
					next = time.Second
				}
				timer.Reset(next)
			}
		}
	}()
}
func (i *Inbound) stopUDPJanitor() {
	if i.udpJanitorCancel != nil {
		i.udpJanitorCancel()
		<-i.udpJanitorDone
	}
}

// A large table is scanned across bounded passes, with one-second continuations
// until the snapshot has been covered. A completed round returns to the normal
// interval, including when all clients are active or there is no traffic.
type udpSweepRound struct {
	local, shared udpSweepProgress
	started       bool
}

func (i *Inbound) expireUDP(cutoff int64, round *udpSweepRound) bool {
	if !round.started {
		round.local = i.udpClientTable.sweepProgress(true)
		round.shared = udpSweepProgress{}
		if s := i.sharedRewrite; s != nil {
			round.shared = s.sharedUDPClientTable.sweepProgress(true)
		}
		round.started = true
	}
	progress := &round.local
	roundLimit := progress.limit
	progress.limit = min(roundLimit, progress.scanned+udpIdleSweepBudget)
	for progress.more() {
		i.lifecycleAccess.Lock()
		redirects := i.udpClientTable.expireBatch(cutoff, false, progress)
		if backend := i.cgroupBackendInstance(); backend != nil {
			for _, addr := range redirects {
				_ = backend.DeleteRedirect(ECommon.ProtocolUDP, netip.AddrPortFrom(addr, i.listeners.selectedPort()))
			}
		}
		i.lifecycleAccess.Unlock()
	}
	progress.limit = roundLimit
	// No lifecycleAccess here: the reply socket pool synchronises itself. Every
	// shard takes its own lock, and sweepIdle skips any entry that still has a
	// lease, which lease() installs under that same shard lock. Taking the
	// exclusive lock would block the inbound's single UDP read loop while the
	// sweep walks the table and closes sockets.
	_ = i.udpReplySockets.sweepIdle(time.Now(), i.udpReplySocketIdleTimeout())
	if s := i.sharedRewrite; s != nil {
		progress := &round.shared
		roundLimit := progress.limit
		progress.limit = min(roundLimit, progress.scanned+udpIdleSweepBudget)
		for progress.more() {
			s.lifecycleAccess.Lock()
			s.releaseFlows(s.sharedUDPClientTable.expireBatch(cutoff, false, progress))
			s.lifecycleAccess.Unlock()
		}
		progress.limit = roundLimit
	}
	recoveryPending := false
	if backend := i.cgroupBackendInstance(); backend != nil {
		complete, err := backend.SweepUDPRecovery(udpIdleSweepBudget)
		recoveryPending = err == nil && !complete
	}
	pending := round.local.more() || round.shared.more() || recoveryPending
	if !pending {
		round.started = false
	}
	return pending
}
