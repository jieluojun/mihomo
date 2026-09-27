package cns

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	tc "github.com/metacubex/mihomo/transport/cns"
)

type fakeTunnel struct {
	gotHost string
	gotData chan string
	udpHost chan string
	udpData chan string
}

func (f *fakeTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	if metadata != nil {
		f.gotHost = metadata.RemoteAddress()
	}
	buf := make([]byte, 16)
	n, _ := io.ReadFull(conn, buf[:5])
	select {
	case f.gotData <- string(buf[:n]):
	default:
	}
}

func (f *fakeTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	if metadata != nil {
		select {
		case f.udpHost <- metadata.RemoteAddress():
		default:
		}
	}
	if packet != nil {
		select {
		case f.udpData <- string(packet.Data()):
		default:
		}
		packet.Drop()
	}
}

func (f *fakeTunnel) NatTable() C.NatTable { return nil }

func drainHTTP(t *testing.T, r *bufio.Reader) {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			return
		}
		if !strings.Contains(line, "200") && !strings.Contains(line, "CuteBi") && !strings.Contains(line, "keep-alive") && line != "\n" {
			// still drain
		}
	}
}

func TestHandleConnTCPPayload(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	tunnel := &fakeTunnel{gotData: make(chan string, 1)}
	go handleConn(serverRaw, Config{Key: "Meng", Password: "secret"}, tunnel)

	host := tc.EncryptHost("example.com:443", "secret")
	req := "CONNECT / HTTP/1.1\r\nMeng: " + host + "\r\nHost: cns.example\r\nConnection: keep-alive\r\n\r\n"
	if _, err := clientRaw.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	_ = clientRaw.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(clientRaw)
	drainHTTP(t, reader)

	client := tc.NewCnsConn(clientRaw, "secret")
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	select {
	case data := <-tunnel.gotData:
		if data != "hello" {
			t.Fatalf("payload = %q, want hello", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for inbound payload")
	}
	if tunnel.gotHost != "example.com:443" {
		t.Fatalf("target = %q", tunnel.gotHost)
	}
}

func TestHandleConnUDPHandshake(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	tunnel := &fakeTunnel{
		udpHost: make(chan string, 1),
		udpData: make(chan string, 1),
	}
	go handleConn(serverRaw, Config{Key: "Meng", Password: "secret", Flag: "httpUDP"}, tunnel)

	req := "CONNECT / HTTP/1.1\r\nhttpUDP\r\nHost: cns.example\r\nConnection: keep-alive\r\n\r\n"
	if _, err := clientRaw.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	_ = clientRaw.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(clientRaw)
	drainHTTP(t, reader)

	// leftover in bufio.Reader is unused; writes go to the pipe.
	pc := tc.NewUDPPacketConn(clientRaw, "secret")
	dst := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	if _, err := pc.WriteTo([]byte("query"), dst); err != nil {
		t.Fatal(err)
	}

	select {
	case host := <-tunnel.udpHost:
		if host != "8.8.8.8:53" {
			t.Fatalf("udp dest = %q", host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDP dest")
	}
	select {
	case data := <-tunnel.udpData:
		if data != "query" {
			t.Fatalf("udp payload = %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDP payload")
	}
}

func TestHeaderValue(t *testing.T) {
	raw := "CONNECT / HTTP/1.1\r\nMeng: abc\r\nHost: x\r\n\r\n"
	got, err := headerValue(raw, "Meng")
	if err != nil || got != "abc" {
		t.Fatalf("got %q err %v", got, err)
	}
}
