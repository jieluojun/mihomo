package dialer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestSocketProtectOwnersSurviveEitherCloseOrder(t *testing.T) {
	for _, closeFirst := range []bool{true, false} {
		UnregisterSocketProtectFunc()
		var calls [2]atomic.Int32
		register := func(index int) func() {
			return RegisterSocketProtectFunc(func(context.Context, string, string, syscall.RawConn) error { calls[index].Add(1); return nil })
		}
		first, second := register(0), register(1)
		if err := ApplySocketProtect("tcp", "", nil); err != nil {
			t.Fatal(err)
		}
		if calls[0].Load() != 1 || calls[1].Load() != 1 {
			t.Fatal("not every owner registered the socket")
		}
		cleanup, survivor := first, 1
		if !closeFirst {
			cleanup, survivor = second, 0
		}
		cleanup()
		cleanup()
		if err := ApplySocketProtect("tcp", "", nil); err != nil {
			t.Fatal(err)
		}
		if calls[survivor].Load() != 2 || calls[1-survivor].Load() != 1 {
			t.Fatal("cleanup removed or retained the wrong owner")
		}
		first()
		second()
		_ = ApplySocketProtect("tcp", "", nil)
		if calls[survivor].Load() != 2 {
			t.Fatal("closed owner still invoked")
		}
	}
}

func TestSocketProtectClearAndConcurrentCleanup(t *testing.T) {
	UnregisterSocketProtectFunc()
	t.Cleanup(UnregisterSocketProtectFunc)
	failure := errors.New("protect failed")
	old := RegisterSocketProtectFunc(func(context.Context, string, string, syscall.RawConn) error { return failure })
	UnregisterSocketProtectFunc()
	var calls atomic.Int32
	current := RegisterSocketProtectFunc(func(context.Context, string, string, syscall.RawConn) error { calls.Add(1); return nil })
	old()
	if err := ApplySocketProtect("udp", "", nil); err != nil || calls.Load() != 1 {
		t.Fatalf("stale cleanup changed new registration: %v", err)
	}
	broken := RegisterSocketProtectFunc(func(context.Context, string, string, syscall.RawConn) error { return failure })
	if err := ApplySocketProtect("udp", "", nil); !errors.Is(err, failure) || calls.Load() != 2 {
		t.Fatalf("hook error hid another owner: %v", err)
	}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() { _ = ApplySocketProtect("udp", "", nil); current(); broken() })
	}
	workers.Wait()
}
