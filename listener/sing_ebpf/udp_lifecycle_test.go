//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"net/netip"
	"testing"
	"time"
)

func TestUDPIdleExpiryProtectsQueuedPacketsAndReplies(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	dest := netip.MustParseAddrPort("1.1.1.1:443")
	retired := 0
	table.setDirectBinding(client, dest, nil, 0, false, func() { retired++ })
	state, _ := table.load(client)
	state.activity.last.Store(1)
	state.activity.pending.Store(1)
	table.expire(2, false)
	if len(table.clientShard(client).clients) != 1 {
		t.Fatal("queued packet expired")
	}
	state.activity.release()
	table.expire(2, false)
	if len(table.clientShard(client).clients) != 1 {
		t.Fatal("recently completed packet expired")
	}
	state.activity.last.Store(1)
	table.expire(2, false)
	if len(table.clientShard(client).clients) != 0 || !state.closed {
		t.Fatal("idle session not removed")
	}
	table.delete(client, state)
	if retired != 1 {
		t.Fatalf("assignment retired %d times, want once", retired)
	}
	if table.setDirectReplyBinding(client, state, dest) {
		t.Fatal("expired writer recreated binding")
	}
}
func TestSharedUDPPurgeReleasesReferences(t *testing.T) {
	var table sharedUDPClientTable
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	dest := netip.MustParseAddrPort("1.1.1.1:443")
	token := netip.MustParseAddr("127.128.0.1")
	flow := new(ECommon.SharedNetworkFlowHandle)
	_, ok := table.setSharedBinding(client, ECommon.OriginalDestination{Destination: dest}, token, flow)
	if !ok {
		t.Fatal("binding rejected")
	}
	state, _ := table.load(client)
	state.activity.last.Store(1)
	state.activity.pending.Store(1)
	if got := table.expire(2, false); len(got) != 0 {
		t.Fatal("in-flight session expired")
	}
	released := table.expire(0, true)
	if len(released) != 1 || released[0].sharedFlow != flow {
		t.Fatalf("lost flow release: %+v", released)
	}
	if len(table.redirectReferences) != 0 || len(state.bindings) != 0 {
		t.Fatal("purge retained state")
	}
	if got := table.expire(0, true); len(got) != 0 {
		t.Fatal("double release")
	}
}
func TestUDPJanitorStopsOnClose(t *testing.T) {
	i := &Inbound{enableUDP: true}
	i.udpTimeout.Store(int64(time.Minute))
	i.startUDPJanitor()
	i.stopUDPJanitor()
	select {
	case <-i.udpJanitorDone:
	default:
		t.Fatal("janitor still running")
	}
}

func TestUDPIdleExpiryReclaimsClientChurn(t *testing.T) {
	var local udpClientTable
	var shared sharedUDPClientTable
	for port := uint16(10000); port < 20000; port++ {
		client := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)
		local.loadOrCreate(client).activity.last.Store(1)
		shared.loadOrCreate(client).activity.last.Store(1)
	}
	for n := 0; n < 10; n++ {
		local.expire(2, false)
		shared.expire(2, false)
	}
	for idx := range local.clientShards {
		if len(local.clientShards[idx].clients) != 0 || len(shared.clientShards[idx].clients) != 0 {
			t.Fatal("client churn retained idle state")
		}
	}
}

func TestUDPReplyActivityKeepsIdleClientAlive(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	state := table.loadOrCreate(client)
	state.activity.last.Store(1)
	// Same touch used by both write-back paths, even when no upstream packets arrive.
	state.activity.touch()
	table.expire(2, false)
	if len(table.clientShard(client).clients) != 1 {
		t.Fatal("downstream-active client expired")
	}
}

func TestSharedTopologyPurgeRejectsOldWriter(t *testing.T) {
	var table sharedUDPClientTable
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	dest := netip.MustParseAddrPort("1.1.1.1:443")
	token := netip.MustParseAddr("127.128.0.1")
	table.setSharedBinding(client, ECommon.OriginalDestination{Destination: dest}, token, new(ECommon.SharedNetworkFlowHandle))
	old, _ := table.load(client)
	table.expire(0, true)
	replacement := table.loadOrCreate(client)
	if replacement == old {
		t.Fatal("client generation reused")
	}
	_, installed := table.setSharedReplyBinding(client, old, ECommon.OriginalDestination{Destination: dest}, token, new(ECommon.SharedNetworkFlowHandle))
	if installed {
		t.Fatal("stale reply writer changed replacement client")
	}
}

func TestUDPForwardRetainsUntilTunnelDrop(t *testing.T) {
	tunnel := &holdingUDPTunnel{}
	i := &Inbound{tunnel: tunnel}
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	dest := netip.MustParseAddrPort("1.1.1.1:443")
	i.forwardLocalUDP(pool.Get(64), client, dest, false)
	state, _ := i.udpClientTable.load(client)
	if state.activity.pending.Load() != 1 {
		t.Fatal("forward did not retain queued packet")
	}
	state.activity.last.Store(1)
	i.udpClientTable.expire(2, false)
	if len(i.udpClientTable.clientShard(client).clients) != 1 {
		t.Fatal("queued packet swept")
	}
	tunnel.packet.Drop()
	tunnel.packet.Drop()
	if state.activity.pending.Load() != 0 {
		t.Fatal("Drop did not release exactly once")
	}
}

type holdingUDPTunnel struct {
	dropTunnel
	packet C.UDPPacket
}

func (h *holdingUDPTunnel) HandleUDPPacket(p C.UDPPacket, _ *C.Metadata) { h.packet = p }
