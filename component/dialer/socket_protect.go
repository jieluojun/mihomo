package dialer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
)

type protectFn = func(ctx context.Context, network, address string, c syscall.RawConn) error

// DefaultSocketProtect holds an optional socket-protect function that is
// appended to every control chain in this package. It is used to register
// eBPF socket cookies so that the eBPF inbound does not capture sockets
// created by mihomo itself. It is an append-only hook and never replaces the
// bind/mark/TFO controls.
var DefaultSocketProtect atomic.Value // holds protectFn or nil

var socketProtectRegistry struct {
	sync.Mutex
	next  uint64
	hooks map[uint64]protectFn
}

// RegisterSocketProtectFunc adds one owner and returns an idempotent cleanup.
// Every active inbound must register the socket in its own bypass map.
func RegisterSocketProtectFunc(fn protectFn) func() {
	if fn == nil {
		return func() {}
	}
	socketProtectRegistry.Lock()
	socketProtectRegistry.next++
	id := socketProtectRegistry.next
	if socketProtectRegistry.hooks == nil {
		socketProtectRegistry.hooks = make(map[uint64]protectFn)
	}
	socketProtectRegistry.hooks[id] = fn
	publishSocketProtectLocked()
	socketProtectRegistry.Unlock()
	return sync.OnceFunc(func() {
		socketProtectRegistry.Lock()
		defer socketProtectRegistry.Unlock()
		delete(socketProtectRegistry.hooks, id)
		publishSocketProtectLocked()
	})
}

func publishSocketProtectLocked() {
	hooks := make([]protectFn, 0, len(socketProtectRegistry.hooks))
	for _, hook := range socketProtectRegistry.hooks {
		hooks = append(hooks, hook)
	}
	var fn protectFn
	if len(hooks) == 1 {
		fn = hooks[0]
	} else if len(hooks) > 1 {
		fn = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			var err error
			for _, hook := range hooks {
				err = errors.Join(err, hook(ctx, network, address, c))
			}
			return err
		}
	}
	DefaultSocketProtect.Store(fn)
}

// UnregisterSocketProtectFunc removes the active socket-protect function.
func UnregisterSocketProtectFunc() {
	socketProtectRegistry.Lock()
	defer socketProtectRegistry.Unlock()
	clear(socketProtectRegistry.hooks)
	DefaultSocketProtect.Store((protectFn)(nil))
}

// ApplySocketProtect invokes the active socket-protect function, if any. It is
// exposed so socket-creation paths outside this package (for example inbound
// listener control chains) can register their sockets with the eBPF inbound.
func ApplySocketProtect(network, address string, c syscall.RawConn) error {
	if fn, loaded := DefaultSocketProtect.Load().(protectFn); loaded && fn != nil {
		return fn(context.Background(), network, address, c)
	}
	return nil
}
