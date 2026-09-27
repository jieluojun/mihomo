package cns

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/cns"
	"github.com/metacubex/mihomo/transport/socks5"
)

const (
	defaultKey  = "Meng"
	defaultFlag = "httpUDP"
)

var established = []byte("HTTP/1.1 200 Connection established\r\nServer: CuteBi Network Tunnel, (%>w<%)\r\nConnection: keep-alive\r\n\r\n")

type Config struct {
	Listen   string
	Key      string
	Password string
	Flag     string
	UDP      bool
}

type Listener struct {
	listener net.Listener
	addr     string
	closed   bool
	config   Config
}

func (l *Listener) RawAddress() string { return l.addr }
func (l *Listener) Address() string    { return l.listener.Addr().String() }
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

func New(config Config, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-CNS"),
			inbound.WithSpecialRules(""),
		}
	}
	if config.Key == "" {
		config.Key = defaultKey
	}
	if config.Flag == "" {
		config.Flag = defaultFlag
	}

	ln, err := lc.Listen(context.Background(), "tcp", config.Listen)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		listener: ln,
		addr:     config.Listen,
		config:   config,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if l.closed {
					break
				}
				continue
			}
			go handleConn(conn, l.config, tunnel, additions...)
		}
	}()
	return l, nil
}

func handleConn(conn net.Conn, config Config, tunnel C.Tunnel, additions ...inbound.Addition) {
	if config.Key == "" {
		config.Key = defaultKey
	}
	if config.Flag == "" {
		config.Flag = defaultFlag
	}

	bufConn := N.NewBufferedConn(conn)
	raw, err := readHTTPHeaders(bufConn.Reader())
	if err != nil {
		_ = conn.Close()
		return
	}

	if _, err = conn.Write(established); err != nil {
		_ = conn.Close()
		return
	}

	if config.Flag != "" && strings.Contains(raw, config.Flag) {
		handleUDP(bufConn, conn.RemoteAddr(), config.Password, tunnel, additions...)
		return
	}

	host, err := headerValue(raw, config.Key)
	if err != nil || host == "" {
		log.Debugln("CNS inbound missing key header %q", config.Key)
		_ = conn.Close()
		return
	}
	host, err = cns.DecryptHost(host, config.Password)
	if err != nil {
		log.Debugln("CNS inbound decrypt host: %s", err)
		_ = conn.Close()
		return
	}
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host = net.JoinHostPort(host, "80")
	}
	target := socks5.ParseAddr(host)
	if target == nil {
		log.Debugln("CNS inbound invalid target %q", host)
		_ = conn.Close()
		return
	}

	c := cns.NewCnsConn(bufConn, config.Password)
	tunnel.HandleTCPConn(inbound.NewSocket(target, c, C.CNS, additions...))
}

func handleUDP(conn net.Conn, remote net.Addr, password string, tunnel C.Tunnel, additions ...inbound.Addition) {
	pc := cns.NewUDPPacketConn(conn, password)
	defer pc.Close()

	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		target := socks5.ParseAddrToSocksAddr(addr)
		if target == nil {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		pkt := &packet{pc: pc, rAddr: remote, payload: payload}
		tunnel.HandleUDPPacket(inbound.NewPacket(target, pkt, C.CNS, additions...))
	}
}

func readHTTPHeaders(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		b.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return b.String(), nil
}

func headerValue(raw, key string) (string, error) {
	prefix := strings.ToLower(key) + ":"
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(key)+1:]), nil
		}
	}
	return "", errMissingHeader
}

var errMissingHeader = errString("missing CNS key header")

type errString string

func (e errString) Error() string { return string(e) }
