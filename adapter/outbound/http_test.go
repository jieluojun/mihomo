package outbound

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// startFakeProxy starts a TCP listener that behaves like an HTTP CONNECT proxy:
// it reads the request headers, pushes the raw request into the returned
// channel and answers "200 Connection established".
func startFakeProxy(t *testing.T) (string, <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	requests := make(chan string, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		var request strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			request.WriteString(line)
			if line == "\r\n" || line == "\n" {
				break // end of request headers
			}
		}
		requests <- request.String()

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		// keep the tunnel open until the test finishes
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	return ln.Addr().String(), requests
}

// dialThroughFakeProxy builds an HTTP proxy adapter pointed at the fake proxy,
// performs a real dial (exercising shakeHandContext) and returns the raw
// CONNECT request the proxy received.
func dialThroughFakeProxy(t *testing.T, headers map[string]string) string {
	t.Helper()

	addr, requests := startFakeProxy(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := NewHttp(HttpOption{
		Name:    "mianliu-test",
		Server:  host,
		Port:    port,
		Headers: headers,
	})
	if err != nil {
		t.Fatal(err)
	}

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.HTTP,
		Host:    "example.com",
		DstPort: 443,
	}

	conn, err := proxy.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	select {
	case request := <-requests:
		return request
	default:
		t.Fatal("no request captured")
		return ""
	}
}

func firstLine(request string) string {
	line, _, _ := strings.Cut(request, "\r\n")
	return line
}

func TestHttpConnectLineDefault(t *testing.T) {
	line := firstLine(dialThroughFakeProxy(t, nil))
	if want := "CONNECT example.com:443 HTTP/1.1"; line != want {
		t.Fatalf("CONNECT line = %q, want %q", line, want)
	}
}

// With-At rewrites the CONNECT target to "<target>@<free-flow-host>", the
// trick used by China Unicom DingTalk direct free-flow (ported from the
// with-at branch of PuerNya/sing).
func TestHttpConnectLineWithAt(t *testing.T) {
	request := dialThroughFakeProxy(t, map[string]string{
		"With-At": "im.dingtalk.com",
	})
	if want := "CONNECT example.com:443@im.dingtalk.com HTTP/1.1"; firstLine(request) != want {
		t.Fatalf("CONNECT line = %q, want %q", firstLine(request), want)
	}
	// The pseudo header must be consumed locally and never sent upstream.
	if strings.Contains(strings.ToLower(request), "with-at:") {
		t.Fatalf("With-At header leaked into the request:\n%s", request)
	}
	// The Host header keeps the real target, matching the sing implementation.
	if !strings.Contains(request, "Host: example.com:443\r\n") {
		t.Fatalf("Host header missing in request:\n%s", request)
	}
}

func TestHttpConnectLineWithAtLowercase(t *testing.T) {
	line := firstLine(dialThroughFakeProxy(t, map[string]string{
		"with-at": "im.dingtalk.com",
	}))
	if want := "CONNECT example.com:443@im.dingtalk.com HTTP/1.1"; line != want {
		t.Fatalf("CONNECT line = %q, want %q", line, want)
	}
}

// Baidu-Direct drops the space before "HTTP/1.1" (fake-first-packet variant,
// also from PuerNya/sing).
func TestHttpConnectLineBaiduDirect(t *testing.T) {
	line := firstLine(dialThroughFakeProxy(t, map[string]string{
		"Baidu-Direct": "true",
	}))
	if want := "CONNECT example.com:443HTTP/1.1"; line != want {
		t.Fatalf("CONNECT line = %q, want %q", line, want)
	}
}

// Normal custom headers must still be sent as headers and must not touch the
// CONNECT line.
func TestHttpConnectLineWithNormalHeader(t *testing.T) {
	request := dialThroughFakeProxy(t, map[string]string{
		"X-Custom": "hello",
	})
	if want := "CONNECT example.com:443 HTTP/1.1"; firstLine(request) != want {
		t.Fatalf("CONNECT line = %q, want %q", firstLine(request), want)
	}
	if !strings.Contains(request, "X-Custom: hello\r\n") {
		t.Fatalf("custom header missing in request:\n%s", request)
	}
}
