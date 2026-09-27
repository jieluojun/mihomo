package outbound

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	TC "github.com/metacubex/mihomo/transport/cns"
)

func TestCnsRequestHeaderDefaults(t *testing.T) {
	adapter, err := NewCns(CnsOption{
		Name:     "cns-test",
		Server:   "cns.example",
		Port:     23333,
		Password: "secret",
		UDP:      true,
		Headers: map[string]string{
			"Host": "camouflage.example",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.option.Key != defaultCnsKey {
		t.Fatalf("default key = %q", adapter.option.Key)
	}
	if adapter.option.Flag != defaultCnsFlag {
		t.Fatalf("default UDP flag = %q", adapter.option.Flag)
	}

	metadata := &C.Metadata{Host: "target.example", DstPort: 443}
	header, err := adapter.requestHeader(metadata, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(header, "CONNECT camouflage.example:443 HTTP/1.1\r\n") {
		t.Fatalf("unexpected request line: %q", header)
	}
	if !strings.Contains(header, "Host: camouflage.example\r\n") {
		t.Fatalf("custom Host header missing: %q", header)
	}
	wantTarget := defaultCnsKey + ": " + TC.EncryptHost(metadata.RemoteAddress(), "secret") + "\r\n"
	if !strings.Contains(header, wantTarget) {
		t.Fatalf("encrypted target header missing: %q", header)
	}
	if !strings.Contains(header, defaultCnsFlag+"\r\n") {
		t.Fatalf("UDP flag missing: %q", header)
	}
}


func TestCnsRequestHeaderDefaultConnectSlash(t *testing.T) {
	adapter, err := NewCns(CnsOption{
		Name:   "cns-test",
		Server: "cns.example",
		Port:   23333,
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := adapter.requestHeader(&C.Metadata{Host: "target.example", DstPort: 443}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(header, "CONNECT / HTTP/1.1\r\n") {
		t.Fatalf("without camouflage Host the CONNECT target must stay /: %q", header)
	}
	if !strings.Contains(header, "Host: cns.example\r\n") {
		t.Fatalf("default Host should be the CNS server: %q", header)
	}
}

func TestCnsRequestHeaderHostWithPort(t *testing.T) {
	adapter, err := NewCns(CnsOption{
		Name:   "cns-test",
		Server: "cns.example",
		Port:   23333,
		Headers: map[string]string{
			"Host": "m.youku.com:80",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := adapter.requestHeader(&C.Metadata{Host: "target.example", DstPort: 443}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(header, "CONNECT m.youku.com:80 HTTP/1.1\r\n") {
		t.Fatalf("Host with port should be used as CONNECT target: %q", header)
	}
	if !strings.Contains(header, "Host: m.youku.com:80\r\n") {
		t.Fatalf("Host header should keep the user value: %q", header)
	}
}

func TestCnsTargetPrecedesCamouflageWhenKeyIsHost(t *testing.T) {
	adapter, err := NewCns(CnsOption{
		Name:     "cns-test",
		Server:   "cns.example",
		Port:     23333,
		Key:      "Host",
		Password: "secret",
		Headers: map[string]string{
			"host": "camouflage.example",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := adapter.requestHeader(&C.Metadata{Host: "target.example", DstPort: 443}, false)
	if err != nil {
		t.Fatal(err)
	}

	wantPrefix := "CONNECT camouflage.example:443 HTTP/1.1\r\nHost: " + TC.EncryptHost("target.example:443", "secret") + "\r\n"
	if !strings.HasPrefix(header, wantPrefix) {
		t.Fatalf("target key is not the first Host occurrence: %q", header)
	}
	if strings.Count(strings.ToLower(header), "host: camouflage.example\r\n") != 1 {
		t.Fatalf("case-insensitive Host override was not applied once: %q", header)
	}
}

func TestCnsHandshakePreservesBufferedTunnelData(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	adapter, err := NewCns(CnsOption{
		Name:     "cns-test",
		Server:   "127.0.0.1",
		Port:     23333,
		Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	const tunnelPayload = "first bytes after CNS response"
	serverErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverRaw)
		var request strings.Builder
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				serverErr <- readErr
				return
			}
			request.WriteString(line)
			if strings.HasSuffix(request.String(), "\r\n\r\n") {
				break
			}
		}
		if !strings.Contains(request.String(), defaultCnsKey) {
			serverErr <- &cnsTestMismatchError{got: request.String(), want: "CNS key header"}
			return
		}

		encrypted := []byte(tunnelPayload)
		TC.Xorcrypt(encrypted, []byte("secret"), 0)
		response := append([]byte("HTTP/1.1 200 Connection established\r\nConnection: keep-alive\r\n\r\n"), encrypted...)
		_, writeErr := serverRaw.Write(response)
		serverErr <- writeErr
	}()

	metadata := &C.Metadata{Host: "target.example", DstPort: 443}
	conn, err := adapter.StreamConnContext(context.Background(), clientRaw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(tunnelPayload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != tunnelPayload {
		t.Fatalf("tunnel payload = %q, want %q", received, tunnelPayload)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

type cnsTestMismatchError struct {
	got  string
	want string
}

func (e *cnsTestMismatchError) Error() string {
	return "payload mismatch: got " + e.got + ", want " + e.want
}
