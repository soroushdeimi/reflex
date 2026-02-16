package inbound

import (
	"bufio"
	"encoding/binary"
	gonet "net"

	"github.com/xtls/xray-core/transport/internet/stat"
)

// IsReflexHandshake checks if the given data looks like a Reflex handshake
func IsReflexHandshake(data []byte) bool {
	h := &Handler{}
	return h.isReflexHandshake(data)
}

// HandleFallbackDeny sends a 403 Forbidden response
func HandleFallbackDeny(conn stat.Connection) error {
	h := &Handler{}
	return h.handleFallbackDeny(conn)
}

// NewPreloadedConn creates a connection that preserves peeked bytes
func NewPreloadedConn(r *bufio.Reader, conn gonet.Conn) *preloadedConn {
	return &preloadedConn{
		Reader:     r,
		Connection: conn,
	}
}

// IsReflexMagic checks if the data starts with the Reflex magic number
func IsReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(data[:4]) == ReflexMagic
}
