package inbound_test

import (
	"sync"
	"testing"
)

func TestVMessInteropWaitsForProcessStartup(t *testing.T) {
	output := vmessInteropProcessOutput{ready: make(chan struct{})}
	_, _ = output.Write([]byte("V2Ray 5.51.2 (V2Fly)\n"))
	select {
	case <-output.ready:
		t.Fatal("version banner is not a readiness signal")
	default:
	}
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for range 100 {
			_ = output.String()
		}
	}()
	_, _ = output.Write([]byte("[Warning] core: V2Ray 5.51.2 sta"))
	_, _ = output.Write([]byte("rted\n"))
	_, _ = output.Write([]byte("[Warning] core: V2Ray 5.51.2 started\n"))
	readers.Wait()
	select {
	case <-output.ready:
	default:
		t.Fatal("complete startup message did not signal readiness")
	}
}
