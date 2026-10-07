//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	udpClientShardCount         = 16
	udpReplyAliasLimit          = 64
	udpReplySocketShardCapacity = 64
)

var errUDPReplySocketPoolBusy = errors.New("eBPF UDP reply socket pool has no idle slot")

type udpClientTable struct {
	clientShards [udpClientShardCount]udpClientShard[udpClientState]
}

// udpClientShard is shared by the local and the shared-rewrite client tables:
// they differ only in the state they hang off each client, and keeping one
// shard type is what lets the sweep and expiry bookkeeping be written once.
type udpClientShard[S any] struct {
	sweep   udpSweepQueue
	access  sync.RWMutex
	clients map[netip.AddrPort]*S
}

type udpClientState struct {
	sweep           udpSweepEntry
	activity        udpActivity
	access          sync.RWMutex
	sourceMAC       net.HardwareAddr
	socketCookie    uint64
	bindings        map[netip.AddrPort]udpRedirectBinding
	replyAliasCount uint16
	closed          bool
	cgroupDataPlane bool
	cgroupOriginals map[netip.Addr]commonEBPF.OriginalDestination
	// lAddr is the address the tunnel keys its NAT table on, built once per
	// client instead of formatted for every packet.
	lAddr net.Addr
}

type udpRedirectBinding struct {
	retireTC        func()
	replyAlias      bool
	redirectAddress netip.Addr
	packetInfo      []byte
	connected       bool
	// sharedPath records which role's kernel rule selected this flow. The TC
	// data plane carries local egress and shared socket-assignment flows on one
	// listener, and the assignment that says which is only read for the first
	// packet, so the answer has to live with the binding for every packet after
	// it. dns-mode is configured per role, so a flow handled as the wrong one is
	// relayed when it should have been forwarded, or the reverse.
	sharedPath bool
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	state, loaded := shard.clients[client]
	shard.access.RUnlock()
	return state, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if state, loaded := t.load(client); loaded {
		return state
	}
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[client]; loaded {
		return state
	}
	if shard.clients == nil {
		shard.clients = make(map[netip.AddrPort]*udpClientState)
	}
	state := &udpClientState{
		bindings:        make(map[netip.AddrPort]udpRedirectBinding),
		cgroupOriginals: make(map[netip.Addr]commonEBPF.OriginalDestination),
		lAddr:           newUDPClientAddr(client),
	}
	state.activity.touch()
	shard.clients[client] = state
	shard.sweep.add(&state.sweep, client)
	return state
}

func (t *udpClientTable) cachedCgroupOriginal(client netip.AddrPort, redirectAddress netip.Addr) (commonEBPF.OriginalDestination, bool) {
	state, loaded := t.load(client)
	if !loaded {
		return commonEBPF.OriginalDestination{}, false
	}
	state.access.RLock()
	original, loaded := state.cgroupOriginals[redirectAddress]
	state.access.RUnlock()
	return original, loaded
}

func (t *udpClientTable) setCgroupBinding(client netip.AddrPort, original commonEBPF.OriginalDestination, redirectAddress netip.Addr) {
	state := t.loadOrCreate(client)
	state.access.Lock()
	state.cgroupOriginals[redirectAddress] = original
	state.socketCookie = original.SocketCookie
	state.cgroupDataPlane = true
	state.bindings[original.Destination] = udpRedirectBinding{
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
		connected:       original.ConnectedUDP,
	}
	state.access.Unlock()
}

func (t *udpClientTable) setCgroupReplyBinding(client netip.AddrPort, expected *udpClientState, destination netip.AddrPort, redirectAddress netip.Addr) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.cgroupOriginals[redirectAddress] = commonEBPF.OriginalDestination{Destination: destination}
	expected.cgroupDataPlane = true
	expected.bindings[destination] = udpRedirectBinding{
		replyAlias:      true,
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
	}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) clientShard(client netip.AddrPort) *udpClientShard[udpClientState] {
	return &t.clientShards[shardIndexForAddrPort(client, udpClientShardCount)]
}

func (t *udpClientTable) setDirectBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
	socketCookie uint64,
	sharedPath bool,
	retireTC func(),
) {
	state := t.loadOrCreate(client)
	state.access.Lock()
	defer state.access.Unlock()
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.socketCookie = socketCookie
	state.bindings[destination] = udpRedirectBinding{sharedPath: sharedPath, retireTC: retireTC}
}

func (t *udpClientTable) setDirectReplyBinding(
	client netip.AddrPort,
	expected *udpClientState,
	destination netip.AddrPort,
) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed {
		return false
	}
	if _, loaded := expected.bindings[destination]; loaded {
		return true
	}
	if expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.bindings[destination] = udpRedirectBinding{replyAlias: true}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) []netip.Addr {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expected {
		return nil
	}
	delete(shard.clients, client)
	shard.sweep.remove(&expected.sweep)
	expected.access.Lock()
	redirects := make([]netip.Addr, 0, len(expected.cgroupOriginals))
	for address := range expected.cgroupOriginals {
		redirects = append(redirects, address)
	}
	expected.closed = true
	for _, binding := range expected.bindings {
		if binding.retireTC != nil {
			binding.retireTC()
		}
	}
	clear(expected.bindings)
	clear(expected.cgroupOriginals)
	expected.cgroupDataPlane = false
	expected.replyAliasCount = 0
	expected.access.Unlock()
	return redirects
}

func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}

// udpReplySocketPool shares transparent reply sockets between all clients of
// an inbound. A socket bound to an original destination can send replies to any
// client, so keeping it at client-state scope needlessly multiplies sockets.
type udpReplySocketPool struct {
	shards [udpClientShardCount]udpReplySocketShard
	closed atomic.Bool
}

type udpReplySocketShard struct {
	access sync.Mutex
	// live includes retired sockets which still have an active lease. Keeping
	// those in the count makes the descriptor bound strict even when every
	// cached socket is concurrently writing.
	live    int
	sockets map[netip.AddrPort]*udpReplySocketEntry
	newest  *udpReplySocketEntry
	oldest  *udpReplySocketEntry
}

type udpReplySocketEntry struct {
	source   netip.AddrPort
	socket   *net.UDPConn
	newer    *udpReplySocketEntry
	older    *udpReplySocketEntry
	lastUsed time.Time
	leases   int
	retired  bool
}

// udpReplySocketLease pins an entry until the caller finishes its sendmsg.
// Eviction, idle sweeping, reset, and close can unlink a leased entry, but its
// socket is closed only after the last lease is released.
type udpReplySocketLease struct {
	shard *udpReplySocketShard
	entry *udpReplySocketEntry
}

func (p *udpReplySocketPool) lease(
	source netip.AddrPort,
	create func(netip.AddrPort) (*net.UDPConn, error),
) (udpReplySocketLease, error) {
	if p.closed.Load() {
		return udpReplySocketLease{}, net.ErrClosed
	}
	shard := &p.shards[p.shardIndex(source)]
	shard.access.Lock()
	defer shard.access.Unlock()
	if p.closed.Load() {
		return udpReplySocketLease{}, net.ErrClosed
	}
	if entry := shard.sockets[source]; entry != nil {
		entry.leases++
		return udpReplySocketLease{shard: shard, entry: entry}, nil
	}
	if shard.live >= udpReplySocketShardCapacity {
		entry := shard.oldest
		for entry != nil && entry.leases != 0 {
			entry = entry.newer
		}
		if entry == nil {
			return udpReplySocketLease{}, errUDPReplySocketPoolBusy
		}
		socket := shard.retireLocked(entry)
		// The entry has no lease, so closing under the shard lock cannot block a
		// writer and prevents a replacement bind from racing the old socket.
		_ = socket.Close()
	}
	socket, err := create(source)
	if err != nil {
		return udpReplySocketLease{}, err
	}
	if shard.sockets == nil {
		shard.sockets = make(map[netip.AddrPort]*udpReplySocketEntry)
	}
	entry := &udpReplySocketEntry{
		source:   source,
		socket:   socket,
		lastUsed: time.Now(),
		leases:   1,
	}
	shard.sockets[source] = entry
	shard.live++
	shard.insertNewestLocked(entry)
	return udpReplySocketLease{shard: shard, entry: entry}, nil
}

// shardIndexForAddrPort mixes every address byte with the port, and is the one
// placement function for all the sharded UDP tables. A port-only key collapses
// onto a single shard whenever many distinct addresses share one port, which is
// the normal case rather than the exotic one: reply sockets are keyed by
// destination and those cluster on a handful of well-known ports, while client
// keys collapse for any downstream application that dials from a fixed source
// port (WireGuard, games) across many hosts.
//
// shardCount must be a power of two. This only changes how entries are spread;
// nothing depends on which shard a key lands in, as long as every lookup and
// insert goes through here.
func shardIndexForAddrPort(addrPort netip.AddrPort, shardCount int) int {
	address := addrPort.Addr().As16()
	hash := uint32(addrPort.Port()) * 0x9e3779b1
	for offset := 0; offset < len(address); offset += 4 {
		hash ^= uint32(address[offset])<<24 |
			uint32(address[offset+1])<<16 |
			uint32(address[offset+2])<<8 |
			uint32(address[offset+3])
		hash *= 0x85ebca6b
	}
	hash ^= hash >> 16
	return int(hash & uint32(shardCount-1))
}

func (p *udpReplySocketPool) shardIndex(source netip.AddrPort) int {
	return shardIndexForAddrPort(source, udpClientShardCount)
}

func (l udpReplySocketLease) release() {
	if l.entry == nil {
		return
	}
	shard := l.shard
	shard.access.Lock()
	entry := l.entry
	if entry.leases == 0 {
		shard.access.Unlock()
		return
	}
	entry.leases--
	if !entry.retired {
		entry.lastUsed = time.Now()
		shard.moveNewestLocked(entry)
		shard.access.Unlock()
		return
	}
	if entry.leases == 0 {
		socket := entry.socket
		entry.socket = nil
		shard.live--
		_ = socket.Close()
	}
	shard.access.Unlock()
}

func (s *udpReplySocketShard) insertNewestLocked(entry *udpReplySocketEntry) {
	entry.newer = nil
	entry.older = s.newest
	if s.newest != nil {
		s.newest.newer = entry
	} else {
		s.oldest = entry
	}
	s.newest = entry
}

func (s *udpReplySocketShard) moveNewestLocked(entry *udpReplySocketEntry) {
	if s.newest == entry {
		return
	}
	s.unlinkLocked(entry)
	s.insertNewestLocked(entry)
}

func (s *udpReplySocketShard) unlinkLocked(entry *udpReplySocketEntry) {
	if entry.newer != nil {
		entry.newer.older = entry.older
	} else {
		s.newest = entry.older
	}
	if entry.older != nil {
		entry.older.newer = entry.newer
	} else {
		s.oldest = entry.newer
	}
	entry.newer = nil
	entry.older = nil
}

// retireLocked removes an entry from the reusable cache. The caller may close
// the returned socket immediately; a nil return means an active lease owns the
// eventual close.
func (s *udpReplySocketShard) retireLocked(entry *udpReplySocketEntry) *net.UDPConn {
	delete(s.sockets, entry.source)
	s.unlinkLocked(entry)
	entry.retired = true
	if entry.leases != 0 {
		return nil
	}
	socket := entry.socket
	entry.socket = nil
	s.live--
	return socket
}

func (p *udpReplySocketPool) close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.closeSockets()
}

// reset closes sockets tied to the previous network path while keeping the
// pool usable for the next interface generation.
func (p *udpReplySocketPool) reset() error {
	if p == nil || p.closed.Load() {
		return nil
	}
	return p.closeSockets()
}

// sweepIdle closes sockets which have not completed a write within maxIdle.
// A leased socket is never considered idle even if its sendmsg is long-lived.
func (p *udpReplySocketPool) sweepIdle(now time.Time, maxIdle time.Duration) error {
	if p == nil || p.closed.Load() || maxIdle <= 0 {
		return nil
	}
	cutoff := now.Add(-maxIdle)
	var closeErr error
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for entry := shard.oldest; entry != nil; {
			// Insert and lease release update lastUsed under this same lock
			// and move the entry to newest. Once an entry is recent, every
			// following entry is recent too, including any leased entries.
			if entry.lastUsed.After(cutoff) {
				break
			}
			next := entry.newer
			if entry.leases == 0 {
				socket := shard.retireLocked(entry)
				closeErr = errors.Join(closeErr, socket.Close())
			}
			entry = next
		}
		shard.access.Unlock()
	}
	return closeErr
}

func (p *udpReplySocketPool) closeSockets() error {
	var closeErr error
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for _, entry := range shard.sockets {
			if socket := shard.retireLocked(entry); socket != nil {
				closeErr = errors.Join(closeErr, socket.Close())
			}
		}
		shard.sockets = nil
		shard.access.Unlock()
	}
	return closeErr
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) hasAddressFamily(ipv4 bool) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	for destination := range s.bindings {
		if destination.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}

func (s *udpClientState) processSocketCookie() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.socketCookie
}

// newUDPClientAddr builds the address the tunnel keys its NAT table on. Both
// client tables go through it, so the local and shared data planes can never
// end up keying NAT differently for the same client.
func newUDPClientAddr(client netip.AddrPort) net.Addr {
	return N.NewCustomAddr(C.EBPF.String(), client.String(), net.UDPAddrFromAddrPort(client))
}

// localAddr is fixed at construction from the client key, so reading it on the
// packet path needs no lock: formatting the address and allocating a
// net.UDPAddr per packet was pure overhead on the read loop.
func (s *udpClientState) localAddr() net.Addr { return s.lAddr }

// hasDirectBinding reports whether a TC client already has a validated
// binding for destination, so the per-flow assignment lookup can be skipped
// for the packets that follow the first one. Reply aliases do not count: they
// were installed for a remote that answered, not for a flow the kernel
// assigned.
// hasDirectBinding also reports which role selected the flow, so the caller can
// apply that role's dns-mode without re-reading the assignment per packet.
func (t *udpClientTable) hasDirectBinding(client netip.AddrPort, destination netip.AddrPort) (bool, bool) {
	state, loaded := t.load(client)
	if !loaded {
		return false, false
	}
	state.access.RLock()
	binding, loaded := state.bindings[destination]
	ready := loaded && !binding.replyAlias && !state.closed && !state.cgroupDataPlane
	sharedPath := ready && binding.sharedPath
	state.access.RUnlock()
	return ready, sharedPath
}

// replyBinding reads the reply binding and the data plane of the client in one
// critical section; the reply path needs both for every packet it writes.
func (s *udpClientState) replyBinding(destination netip.AddrPort) (udpRedirectBinding, bool, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	cgroupDataPlane := s.cgroupDataPlane
	s.access.RUnlock()
	return binding, loaded, cgroupDataPlane
}
