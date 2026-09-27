package cns

import (
	"io"
	"net"
	"sync"
)

// CnsConn encrypts and decrypts a CNS TCP stream. Each direction has an
// independent cipher position, as required by the CNS server.
type CnsConn struct {
	net.Conn
	password []byte

	readMu   sync.Mutex
	readSub  int
	writeMu  sync.Mutex
	writeSub int
}

func NewCnsConn(conn net.Conn, password string) *CnsConn {
	return &CnsConn{
		Conn:     conn,
		password: []byte(password),
	}
}

func (c *CnsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	n, err := c.Conn.Read(p)
	if n > 0 {
		c.readSub = Xorcrypt(p[:n], c.password, c.readSub)
	}
	return n, err
}

func (c *CnsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	data := append([]byte(nil), p...)
	nextSub := Xorcrypt(data, c.password, c.writeSub)
	if err := writeFull(c.Conn, data); err != nil {
		return 0, err
	}
	c.writeSub = nextSub
	return len(p), nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
