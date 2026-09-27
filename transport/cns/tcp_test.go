package cns

import (
	"io"
	"net"
	"testing"
)

func TestCnsConnBidirectionalStream(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	const password = "secret"
	client := NewCnsConn(clientRaw, password)
	clientPayload := []byte("client payload split across cipher cycles")
	serverPayload := []byte("server reply in differently sized writes")

	serverErr := make(chan error, 1)
	go func() {
		received := make([]byte, len(clientPayload))
		if _, err := io.ReadFull(serverRaw, received); err != nil {
			serverErr <- err
			return
		}
		Xorcrypt(received, []byte(password), 0)
		if string(received) != string(clientPayload) {
			serverErr <- &payloadMismatchError{got: string(received), want: string(clientPayload)}
			return
		}

		encrypted := append([]byte(nil), serverPayload...)
		Xorcrypt(encrypted, []byte(password), 0)
		if _, err := serverRaw.Write(encrypted[:7]); err != nil {
			serverErr <- err
			return
		}
		if _, err := serverRaw.Write(encrypted[7:]); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	if _, err := client.Write(clientPayload[:9]); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(clientPayload[9:]); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(serverPayload))
	if _, err := io.ReadFull(client, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(serverPayload) {
		t.Fatalf("reply = %q, want %q", received, serverPayload)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

type payloadMismatchError struct {
	got  string
	want string
}

func (e *payloadMismatchError) Error() string {
	return "payload mismatch: got " + e.got + ", want " + e.want
}
