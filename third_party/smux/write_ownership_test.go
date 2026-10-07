package smux

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestQueuedFrameOwnsPayloadAfterWriteReturns(t *testing.T) {
	for _, cause := range []string{"deadline", "close", "socket error"} {
		t.Run(cause, func(t *testing.T) {
			s := &Session{
				shaper:             make(chan writeRequest),
				die:                make(chan struct{}),
				chSocketWriteError: make(chan struct{}),
			}
			deadline := make(chan time.Time, 1)
			original := []byte("queued TLS record")
			payload := append([]byte(nil), original...)
			done := make(chan error, 1)
			go func() {
				_, err := s.writeFrameInternal(Frame{data: payload}, deadline, CLSDATA)
				done <- err
			}()
			// The shaper has accepted the frame, but sendLoop has not consumed it.
			request := <-s.shaper
			var want error
			switch cause {
			case "deadline":
				want = ErrTimeout
				deadline <- time.Now()
			case "close":
				want = io.ErrClosedPipe
				close(s.die)
			case "socket error":
				want = io.ErrUnexpectedEOF
				s.socketWriteError.Store(want)
				close(s.chSocketWriteError)
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("write error = %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled write did not return")
			}
			// The caller can reuse its buffer immediately after Write.
			for index := range payload {
				payload[index] = 0
			}
			if !bytes.Equal(request.frame.data, original) {
				t.Fatalf("queued payload changed after caller reuse: %q", request.frame.data)
			}
		})
	}
}
