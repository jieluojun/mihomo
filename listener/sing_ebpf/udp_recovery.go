//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"

	"github.com/metacubex/mihomo/log"
)

func (i *Inbound) startUDPRecoveryCleanup() {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	d := backend.UDPStateDiagnostics()
	log.Infoln("[EBPF] UDP recovery: index=%s, cleanup=%s, userspace=%s, fallback=%s", d.RecoveryMode, d.CleanupMode, d.UserspaceCleanupMode, d.FallbackReason)
	if d.UserspaceCleanupMode != "ringbuf" {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	i.udpRecoveryCancel = cancel
	i.udpRecoveryDone = make(chan struct{})
	go func() {
		defer close(i.udpRecoveryDone)
		if err := backend.RunUDPRecoveryCleanup(ctx); err != nil && ctx.Err() == nil {
			log.Warnln("[EBPF] UDP recovery events unavailable; deadline cleanup remains active: %s", err)
		}
	}()
}

func (i *Inbound) stopUDPRecoveryCleanup() {
	if i.udpRecoveryCancel != nil {
		i.udpRecoveryCancel()
		<-i.udpRecoveryDone
	}
}
