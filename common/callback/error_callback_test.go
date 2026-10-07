package callback

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
)

type failingConn struct {
	C.Conn
	err    error
	closed int
}

func (c *failingConn) Read([]byte) (int, error)      { return 0, c.err }
func (c *failingConn) Write([]byte) (int, error)     { return 0, c.err }
func (c *failingConn) ReadBuffer(*buf.Buffer) error  { return c.err }
func (c *failingConn) WriteBuffer(*buf.Buffer) error { return c.err }
func (c *failingConn) Close() error                  { c.closed++; return c.err }

func TestErrorCallbackObservesMidTransferAndFiltersLifecycle(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		var readErr, writeErr atomic.TypedValue[error]
		base := &failingConn{}
		conn := NewErrorCallBackConn(base, &readErr, &writeErr)
		read := func() {
			if buffered {
				_ = conn.ReadBuffer(nil)
			} else {
				_, _ = conn.Read(nil)
			}
		}
		write := func() {
			if buffered {
				_ = conn.WriteBuffer(nil)
			} else {
				_, _ = conn.Write(nil)
			}
		}
		read()
		write()
		for _, err := range []error{net.ErrClosed, os.ErrDeadlineExceeded} {
			base.err = err
			read()
			write()
		}
		if readErr.Load() != nil || writeErr.Load() != nil {
			t.Fatal("lifecycle error charged to node")
		}
		failure := errors.New("mid-transfer failure")
		base.err = failure
		read()
		write()
		base.err = io.EOF
		read()
		write()
		if readErr.Load() != failure || writeErr.Load() != failure {
			t.Fatal("first transfer failure was lost")
		}
		if _, ok := conn.(interface{ ReaderReplaceable() bool }); ok {
			t.Fatal("copy engine could bypass observer")
		}
	}
}

func TestFirstWriteCloseForwardsOnceConcurrently(t *testing.T) {
	failure := errors.New("close failed")
	base := &failingConn{err: failure}
	conn := NewFirstWriteCallBackConn(base, nil)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			if err := conn.Close(); err != failure {
				t.Errorf("close = %v", err)
			}
		})
	}
	workers.Wait()
	if base.closed != 1 {
		t.Fatalf("underlying closed %d times", base.closed)
	}
}
