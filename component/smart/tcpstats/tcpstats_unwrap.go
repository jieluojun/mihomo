package tcpstats

import (
	"net"
	"reflect"
	"syscall"
)

// maxUnwrapSteps is a runaway guard only; real wrapper chains stay far below it.
const maxUnwrapSteps = 256

// GetTCPStats unwraps the connection wrappers until a socket is found; nil means the
// counters are not available for this connection.
func GetTCPStats(conn net.Conn) *Stats {
	var seenBuf [16]uintptr
	seen := seenBuf[:0]
outer:
	for depth := 0; depth < maxUnwrapSteps; depth++ {
		if rv := reflect.ValueOf(conn); rv.Kind() == reflect.Ptr {
			ptr := rv.Pointer()
			for _, prev := range seen {
				if prev == ptr {
					return nil
				}
			}
			seen = append(seen, ptr)
		}

		if sc, ok := conn.(interface {
			SyscallConn() (syscall.RawConn, error)
		}); ok {
			rawConn, err := sc.SyscallConn()
			if err != nil {
				return nil
			}
			return readTCPStats(rawConn)
		}
		if u, ok := conn.(interface{ Upstream() any }); ok {
			if next, ok2 := u.Upstream().(net.Conn); ok2 {
				conn = next
				continue outer
			}
			// fall through to other unwrap methods
		}
		if nc, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = nc.NetConn()
			continue outer
		}
		{
			v := reflect.ValueOf(conn)
			if v.Kind() == reflect.Ptr {
				v = v.Elem()
			}
			if v.Kind() == reflect.Struct {
				t := v.Type()
				for i := 0; i < v.NumField(); i++ {
					f := v.Field(i)
					if !t.Field(i).IsExported() || !f.CanInterface() {
						continue
					}
					if inner, ok := f.Interface().(net.Conn); ok {
						conn = inner
						continue outer
					}
				}
			}
		}
		return nil
	}
	return nil
}
