package inbound

import (
	"bufio"
	"net"

	"github.com/xtls/xray-core/transport/internet/stat"
)

// preloadedConn wraps a connection with a bufio.Reader to preserve peeked bytes
type preloadedConn struct {
	reader *bufio.Reader
	conn   stat.Connection
}

// newPreloadedConn creates a new preloaded connection
func newPreloadedConn(reader *bufio.Reader, conn stat.Connection) *preloadedConn {
	return &preloadedConn{
		reader: reader,
		conn:   conn,
	}
}

// Read reads from the buffered reader first, then from the connection
func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

// Write writes directly to the underlying connection
func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.conn.Write(b)
}

// Close closes the underlying connection
func (pc *preloadedConn) Close() error {
	return pc.conn.Close()
}

// LocalAddr returns the local network address
func (pc *preloadedConn) LocalAddr() net.Addr {
	return pc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (pc *preloadedConn) RemoteAddr() net.Addr {
	return pc.conn.RemoteAddr()
}
