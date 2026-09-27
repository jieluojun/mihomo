package cns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	cnsAtypIPv4 = 1
	cnsAtypIPv6 = 3

	cnsIPv4HeaderLen = 12
	cnsIPv6HeaderLen = 24
	cnsMaxFrameLen   = 1<<16 - 1
)

// OverTCPPacketConn carries CNS UDP packets over a single TCP connection.
type OverTCPPacketConn struct {
	conn     net.Conn
	password []byte

	readMu   sync.Mutex
	readSub  int
	writeMu  sync.Mutex
	writeSub int
}

func NewUDPPacketConn(conn net.Conn, password string) *OverTCPPacketConn {
	return &OverTCPPacketConn{
		conn:     conn,
		password: []byte(password),
	}
}

func (c *OverTCPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var lengthBytes [2]byte
	if err := c.readAndDecrypt(lengthBytes[:]); err != nil {
		return 0, nil, err
	}

	bodyLen := int(binary.LittleEndian.Uint16(lengthBytes[:]))
	if bodyLen < cnsIPv4HeaderLen-2 {
		return 0, nil, fmt.Errorf("invalid CNS UDP frame length: %d", bodyLen)
	}
	body := make([]byte, bodyLen)
	if err := c.readAndDecrypt(body); err != nil {
		return 0, nil, err
	}

	if body[0] != 0 || body[1] != 0 || body[2] != 0 {
		return 0, nil, errors.New("invalid CNS UDP frame prefix")
	}

	var (
		ip      net.IP
		port    uint16
		payload []byte
	)
	switch body[3] {
	case cnsAtypIPv4:
		if len(body) < cnsIPv4HeaderLen-2 {
			return 0, nil, errors.New("short CNS IPv4 UDP frame")
		}
		ip = net.IP(append([]byte(nil), body[4:8]...))
		port = binary.BigEndian.Uint16(body[8:10])
		payload = body[10:]
	case cnsAtypIPv6:
		if len(body) < cnsIPv6HeaderLen-2 {
			return 0, nil, errors.New("short CNS IPv6 UDP frame")
		}
		ip = net.IP(append([]byte(nil), body[4:20]...))
		port = binary.BigEndian.Uint16(body[20:22])
		payload = body[22:]
	default:
		return 0, nil, fmt.Errorf("unsupported CNS UDP address type: %d", body[3])
	}

	n := copy(p, payload)
	return n, &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func (c *OverTCPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, err := asUDPAddr(addr)
	if err != nil {
		return 0, err
	}

	var (
		atyp      byte
		ip        net.IP
		headerLen int
	)
	if ipv4 := udpAddr.IP.To4(); ipv4 != nil {
		atyp = cnsAtypIPv4
		ip = ipv4
		headerLen = cnsIPv4HeaderLen
	} else if ipv6 := udpAddr.IP.To16(); ipv6 != nil {
		atyp = cnsAtypIPv6
		ip = ipv6
		headerLen = cnsIPv6HeaderLen
	} else {
		return 0, errors.New("invalid CNS UDP destination IP")
	}

	frameLen := headerLen + len(p)
	if frameLen-2 > cnsMaxFrameLen {
		return 0, fmt.Errorf("CNS UDP packet too large: %d", len(p))
	}
	frame := make([]byte, frameLen)
	binary.LittleEndian.PutUint16(frame[:2], uint16(frameLen-2))
	frame[5] = atyp
	copy(frame[6:], ip)
	portOffset := 6 + len(ip)
	binary.BigEndian.PutUint16(frame[portOffset:portOffset+2], uint16(udpAddr.Port))
	copy(frame[headerLen:], p)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	nextSub := Xorcrypt(frame, c.password, c.writeSub)
	if err := writeFull(c.conn, frame); err != nil {
		return 0, err
	}
	c.writeSub = nextSub
	return len(p), nil
}

func (c *OverTCPPacketConn) readAndDecrypt(data []byte) error {
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return err
	}
	c.readSub = Xorcrypt(data, c.password, c.readSub)
	return nil
}

func (c *OverTCPPacketConn) Close() error {
	return c.conn.Close()
}

func (c *OverTCPPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *OverTCPPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *OverTCPPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *OverTCPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func asUDPAddr(addr net.Addr) (*net.UDPAddr, error) {
	if addr == nil {
		return nil, errors.New("nil CNS UDP destination")
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr.Port < 0 || udpAddr.Port > 65535 {
			return nil, fmt.Errorf("invalid CNS UDP port: %d", udpAddr.Port)
		}
		return udpAddr, nil
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("resolve CNS UDP destination: %w", err)
	}
	return udpAddr, nil
}
