package cns

import (
	"net"
	"testing"
)

func TestUDPPacketConnIPv4AndIPv6(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := NewUDPPacketConn(clientRaw, "udp-password")
	server := NewUDPPacketConn(serverRaw, "udp-password")

	tests := []struct {
		name    string
		addr    *net.UDPAddr
		payload []byte
	}{
		{
			name:    "IPv4",
			addr:    &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
			payload: []byte("ipv4 dns payload"),
		},
		{
			name:    "IPv6",
			addr:    &net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 5353},
			payload: []byte("ipv6 dns payload"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writeResult := make(chan error, 1)
			go func() {
				_, err := client.WriteTo(test.payload, test.addr)
				writeResult <- err
			}()

			buffer := make([]byte, 256)
			n, addr, err := server.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-writeResult; err != nil {
				t.Fatal(err)
			}
			if string(buffer[:n]) != string(test.payload) {
				t.Fatalf("payload = %q, want %q", buffer[:n], test.payload)
			}

			got := addr.(*net.UDPAddr)
			if !got.IP.Equal(test.addr.IP) || got.Port != test.addr.Port {
				t.Fatalf("address = %s, want %s", got, test.addr)
			}
		})
	}
}

func TestUDPPacketConnRejectsOversizedPacket(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	conn := NewUDPPacketConn(clientRaw, "")
	payload := make([]byte, cnsMaxFrameLen)
	if _, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}); err == nil {
		t.Fatal("oversized packet was accepted")
	}
}
