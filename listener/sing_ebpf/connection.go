//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// addrPortOf reads the address of an accepted connection without formatting
// it to text and parsing it back. The internal listeners only ever hand out
// *net.TCPAddr / *net.UDPAddr; anything else takes the slow path. IPv4
// addresses are unmapped so the result matches what the text round trip used
// to produce.
func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	var addrPort netip.AddrPort
	switch typed := addr.(type) {
	case *net.TCPAddr:
		addrPort = typed.AddrPort()
	case *net.UDPAddr:
		addrPort = typed.AddrPort()
	case nil:
		return netip.AddrPort{}, false
	default:
		parsed, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		addrPort = parsed
	}
	if !addrPort.IsValid() {
		return netip.AddrPort{}, false
	}
	if address := addrPort.Addr(); address.Is4In6() {
		addrPort = netip.AddrPortFrom(address.Unmap(), addrPort.Port())
	}
	return addrPort, true
}

// NewConnection handles a TCP connection accepted by the internal listeners.
// It dispatches between the cgroup and TC data planes by the redirect address
// the connection was steered into.
func (i *Inbound) NewConnection(conn net.Conn) {
	localAddr, ok := addrPortOf(conn.LocalAddr())
	if !ok {
		_ = conn.Close()
		return
	}
	if i.localCgroupEnabled() && i.isCgroupRedirectAddress(localAddr.Addr()) {
		i.newCgroupTCPConnection(conn, localAddr)
		return
	}
	backend := i.tcBackend()
	if backend == nil {
		_ = conn.Close()
		return
	}
	i.newTCConnection(backend, conn, localAddr)
}

func (i *Inbound) newCgroupTCPConnection(conn net.Conn, listenerDestination netip.AddrPort) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	original, err := backend.TakeOriginal(ECommon.ProtocolTCP, listenerDestination)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) {
			i.udpWarnings.cleanup.warn(i.logWarn, "lookup cgroup eBPF TCP original destination: ", err)
		}
		_ = conn.Close()
		return
	}
	source, ok := addrPortOf(conn.RemoteAddr())
	if !ok {
		_ = conn.Close()
		return
	}
	if i.hijackDNS(original.Destination) {
		i.startTCPDNSRelay(conn)
		return
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   original.Destination.Addr().Unmap(),
		DstPort: original.Destination.Port(),
		SrcIP:   source.Addr().Unmap(),
		SrcPort: source.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)
	i.tunnel.HandleTCPConn(conn, metadata)
}

func (i *Inbound) newTCConnection(backend *ECommon.TCBackend, conn net.Conn, destination netip.AddrPort) {
	source, ok := addrPortOf(conn.RemoteAddr())
	if !ok {
		_ = conn.Close()
		return
	}
	assignment, err := backend.LookupAssignment(ECommon.ProtocolTCP, source, destination, 0, true)
	if err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "lookup TC eBPF TCP assignment: ", err)
		_ = conn.Close()
		return
	}
	if i.hijackTCDNS(destination, assignment.Path == ECommon.TCPathShared) {
		i.startTCPDNSRelay(conn)
		return
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   source.Addr().Unmap(),
		SrcPort: source.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)
	i.tunnel.HandleTCPConn(conn, metadata)
}

// NewPacket handles a UDP datagram received by the internal listeners. It runs
// on the listener's single read loop, so everything here has to be cheap and
// must never wait on the network: a stall stops every UDP client of the
// inbound at once.
func (i *Inbound) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	i.lifecycleAccess.RLock()
	defer i.lifecycleAccess.RUnlock()
	// One pass over the control messages serves both data planes; the cgroup
	// path only needs the packet address and the TC path the original
	// destination, and both come out of the same walk.
	packetAddress, destination, interfaceIndex, err := packetDestinationsFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logWarn, "read eBPF UDP packet info: ", err)
		_ = pool.Put(data)
		return
	}
	if i.localCgroupEnabled() && i.isCgroupRedirectAddress(packetAddress) {
		i.newCgroupPacket(data, packetAddress, source)
		return
	}
	backend := i.tcBackend()
	if backend == nil {
		_ = pool.Put(data)
		return
	}
	i.newTCPacket(backend, data, destination, interfaceIndex, source)
}

func (i *Inbound) newCgroupPacket(data []byte, redirectAddress netip.Addr, source netip.AddrPort) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		i.udpWarnings.originalDestination.warn(i.logWarn, "cgroup eBPF backend is closed; dropping packet redirected to ", redirectAddress)
		_ = pool.Put(data)
		return
	}
	client := source
	original, loaded := i.udpClientTable.cachedCgroupOriginal(client, redirectAddress)
	if !loaded {
		redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
		var err error
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverUDPOriginal(redirectDestination)
		}
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverConnectedUDPOriginal(redirectDestination)
		}
		if err != nil {
			i.udpWarnings.originalDestination.warn(i.logWarn, "lookup cgroup eBPF UDP original destination: ", err)
			_ = pool.Put(data)
			return
		}
		i.udpClientTable.setCgroupBinding(client, original, redirectAddress)
	}
	if i.hijackDNS(original.Destination) {
		clientState := i.udpClientTable.loadOrCreate(client)
		// Resolving may take a network round trip; never do that on the read
		// loop. The DNS goroutine owns and returns the payload to the pool.
		i.startUDPDNSRelay(data, client, clientState, original.Destination)
		return
	}
	i.forwardLocalUDP(data, client, original.Destination, original.ConnectedUDP)
}

func (i *Inbound) newTCPacket(backend *ECommon.TCBackend, data []byte, destination netip.AddrPort, interfaceIndex uint32, source netip.AddrPort) {
	if !destination.IsValid() {
		i.udpWarnings.packetInfo.warn(i.logWarn, "TC eBPF UDP original destination is missing")
		_ = pool.Put(data)
		return
	}
	client := source
	// The assignment record only carries per-flow facts (source MAC, socket
	// cookie, path), so it is read once per client/destination pair. Every
	// later packet of the flow skips the map syscall and the state write.
	bound, sharedPath := i.udpClientTable.hasDirectBinding(client, destination)
	if !bound {
		assignment, err := backend.LookupAssignment(ECommon.ProtocolUDP, client, destination, interfaceIndex, false)
		if err != nil && interfaceIndex != 0 {
			interfaceIndex = 0
			assignment, err = backend.LookupAssignment(ECommon.ProtocolUDP, client, destination, 0, false)
		}
		if err != nil {
			i.udpWarnings.originalDestination.warn(i.logWarn, "lookup TC eBPF UDP assignment: ", err)
			_ = pool.Put(data)
			return
		}
		sharedPath = assignment.Path == ECommon.TCPathShared
		var sourceMAC net.HardwareAddr
		if sharedPath && assignment.SourceMACValid != 0 {
			sourceMAC = net.HardwareAddr(assignment.SourceMAC[:])
		}
		i.udpClientTable.setDirectBinding(client, destination, sourceMAC, assignment.SocketCookie, sharedPath, func() {
			_ = backend.DeleteUDPAssignment(client, destination, interfaceIndex, assignment)
		})
	}
	if i.hijackTCDNS(destination, sharedPath) {
		clientState := i.udpClientTable.loadOrCreate(client)
		i.startUDPDNSRelay(data, client, clientState, destination)
		return
	}
	i.forwardLocalUDP(data, client, destination, false)
}

// forwardLocalUDP forwards a UDP datagram from a local or TC client to the
// mihomo tunnel with per-packet write-back through the reply socket / cgroup
// redirect as selected by the client's data plane.
func (i *Inbound) forwardLocalUDP(data []byte, client netip.AddrPort, destination netip.AddrPort, connected bool) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)

	clientState := i.udpClientTable.loadOrCreate(client)
	clientState.activity.retain()
	packet := &udpPacket{
		inbound:     i,
		client:      client,
		clientState: clientState,
		data:        data,
		lAddr:       clientState.localAddr(),
	}
	i.tunnel.HandleUDPPacket(packet, metadata)
}

// hijackDNS reports whether a port-53 flow the local role delivered should be
// relayed through the resolver. The shared role carries its own dns-mode and
// must ask hijackSharedDNS instead: the kernel honours the two settings
// separately, so answering a shared flow with the local mode sends it to the
// client's original DNS server whenever the two differ.
func (i *Inbound) hijackDNS(destination netip.AddrPort) bool {
	return i.localDNSMode != dnsModeOff && destination.Port() == 53
}

// hijackSharedDNS is hijackDNS for the shared role.
func (i *Inbound) hijackSharedDNS(destination netip.AddrPort) bool {
	return i.sharedDNSMode != dnsModeOff && destination.Port() == 53
}

// hijackTCDNS is hijackDNS for the TC data plane, which carries local egress
// and shared socket-assignment flows on one listener. sharedPath comes from the
// kernel assignment that steered the flow here, so each one is judged by the
// dns-mode of the role that actually selected it.
func (i *Inbound) hijackTCDNS(destination netip.AddrPort, sharedPath bool) bool {
	if sharedPath {
		return i.hijackSharedDNS(destination)
	}
	return i.hijackDNS(destination)
}

type udpPacket struct {
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
	data        []byte
	lAddr       net.Addr
}

func (p *udpPacket) Data() []byte {
	return p.data
}

func (p *udpPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	destination, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("invalid UDP reply address")
	}
	if p.clientState == nil {
		return 0, E.New("missing eBPF UDP state for ", p.client)
	}
	if err := p.inbound.writeUDPReply(p.client, p.clientState, destination.AddrPort(), b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// writeUDPReply writes a UDP reply toward the client through the data plane of
// the client's state: cgroup clients use the internal listener writeUDP with
// the redirect address as source (the kernel restores the reply path), while
// TC clients use a transparent reply socket bound to the original destination.
func (i *Inbound) writeUDPReply(client netip.AddrPort, clientState *udpClientState, destinationAddress netip.AddrPort, payload []byte) error {
	// Read-locked: replies for different clients flow concurrently, and only a
	// topology update -- which purges the UDP state and resets the reply
	// sockets -- has to exclude them. Holding a plain mutex here serialised
	// every UDP reply of the inbound through one lock, syscall included.
	i.lifecycleAccess.RLock()
	defer i.lifecycleAccess.RUnlock()
	clientState.activity.touch()
	binding, loaded, cgroupPlane := clientState.replyBinding(destinationAddress)
	if !loaded {
		if cgroupPlane {
			backend := i.cgroupBackendInstance()
			if backend == nil {
				return E.New("cgroup eBPF backend is closed")
			}
			redirectAddress, err := backend.ReserveUDPReplyRedirect(destinationAddress, i.listeners.selectedPort())
			if err != nil {
				return err
			}
			if !i.udpClientTable.setCgroupReplyBinding(client, clientState, destinationAddress, redirectAddress) {
				_ = backend.DeleteRedirect(
					ECommon.ProtocolUDP,
					netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort()),
				)
				return E.New("cgroup eBPF UDP reply binding was rejected")
			}
			binding, loaded = clientState.redirectBinding(destinationAddress)
			if !loaded {
				return E.New("cgroup eBPF UDP reply binding is unavailable")
			}
		}
	}
	if !loaded {
		if !clientState.hasAddressFamily(destinationAddress.Addr().Is4()) {
			return E.New("eBPF UDP reply alias limit reached or address family unavailable")
		}
		installed := i.udpClientTable.setDirectReplyBinding(client, clientState, destinationAddress)
		if !installed {
			return E.New("eBPF UDP session closed or reply alias was rejected")
		}
		binding, loaded = clientState.redirectBinding(destinationAddress)
		if !loaded {
			return E.New("eBPF UDP reply binding is unavailable")
		}
	}
	if cgroupPlane {
		return i.listeners.writeUDP(payload, binding.packetInfo, client, binding.redirectAddress)
	}
	lease, err := i.udpReplySockets.lease(destinationAddress, i.newTCUDPReplySocket)
	if err != nil {
		return err
	}
	defer lease.release()
	_, err = lease.entry.socket.WriteToUDPAddrPort(payload, client)
	return err
}

// Drop returns the payload to the pool. The read loop copied the datagram
// into a pooled buffer and handed ownership to this packet; the tunnel calls
// Drop once the outbound has written it. Without this every packet's buffer
// became garbage, and the pool never had anything to hand back.
func (p *udpPacket) Drop() {
	if p.data != nil && p.clientState != nil {
		p.clientState.activity.release()
	}
	data := p.data
	if data == nil {
		return
	}
	p.data = nil
	_ = pool.Put(data)
}

func (p *udpPacket) LocalAddr() net.Addr {
	return p.lAddr
}

var _ C.UDPPacket = (*udpPacket)(nil)

func (i *Inbound) newTCUDPReplySocket(source netip.AddrPort) (*net.UDPConn, error) {
	network := "udp6"
	if source.Addr().Is4() {
		network = "udp4"
	}
	listenConfig := net.ListenConfig{Control: func(_ string, _ string, rawConn syscall.RawConn) error {
		if err := rawConn.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				return
			}
			if source.Addr().Is4() {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			} else {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
			}
		}); err != nil {
			return err
		}
		if i.selfBypass != nil {
			return i.selfBypass.RegisterSocket(rawConn)
		}
		return nil
	}}
	packetConnection, err := listenConfig.ListenPacket(contextBackground(), network, source.String())
	if err != nil {
		return nil, E.Cause(err, "bind eBPF UDP reply socket to ", source)
	}
	udpConnection, loaded := packetConnection.(*net.UDPConn)
	if !loaded {
		_ = packetConnection.Close()
		return nil, E.New("eBPF UDP reply socket has unexpected type")
	}
	return udpConnection, nil
}

func packetDestinationsFromOOB(oob []byte) (netip.Addr, netip.AddrPort, uint32, error) {
	var packetAddress netip.Addr
	var originalDestination netip.AddrPort
	var interfaceIndex uint32
	for len(oob) > 0 {
		header, data, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return netip.Addr{}, netip.AddrPort{}, 0, E.Cause(err, "parse IP packet info")
		}
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO:
			if len(data) < unix.SizeofInet4Pktinfo {
				return netip.Addr{}, netip.AddrPort{}, 0, E.New("invalid IPv4 packet info length: ", len(data))
			}
			interfaceIndex = binary.NativeEndian.Uint32(data[:4])
			var address [4]byte
			copy(address[:], data[8:12])
			packetAddress = netip.AddrFrom4(address)
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO:
			if len(data) < unix.SizeofInet6Pktinfo {
				return netip.Addr{}, netip.AddrPort{}, 0, E.New("invalid IPv6 packet info length: ", len(data))
			}
			interfaceIndex = binary.NativeEndian.Uint32(data[16:20])
			var address [16]byte
			copy(address[:], data[:16])
			packetAddress = netip.AddrFrom16(address)
		case header.Level == unix.SOL_IP && header.Type == unix.IP_RECVORIGDSTADDR && len(data) >= 8:
			var address [4]byte
			copy(address[:], data[4:8])
			originalDestination = netip.AddrPortFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(data[2:4]))
		case header.Level == unix.SOL_IPV6 && header.Type == unix.IPV6_RECVORIGDSTADDR && len(data) >= 24:
			var address [16]byte
			copy(address[:], data[8:24])
			originalDestination = netip.AddrPortFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(data[2:4]))
		}
		oob = remainder
	}
	if !packetAddress.IsValid() {
		return netip.Addr{}, netip.AddrPort{}, 0, E.New("IP packet info is missing")
	}
	return packetAddress, originalDestination, interfaceIndex, nil
}
