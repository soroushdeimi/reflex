//go:build quic
// +build quic

package inbound

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// QUICConfig holds QUIC transport configuration
type QUICConfig struct {
	Enabled     bool
	TLSConfig   *tls.Config
	QUICConfig  *quic.Config
	ListenAddr  string
}

// quicStreamConn wraps quic.Stream to implement net.Conn interface
type quicStreamConn struct {
	stream quic.Stream
	conn   quic.Connection
	local  net.Addr
	remote net.Addr
}

// Read reads from the QUIC stream
func (c *quicStreamConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

// Write writes to the QUIC stream
func (c *quicStreamConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

// Close closes the QUIC stream
func (c *quicStreamConn) Close() error {
	return c.stream.Close()
}

// LocalAddr returns local address
func (c *quicStreamConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (c *quicStreamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.conn.RemoteAddr()
}

// SetDeadline sets read/write deadline
func (c *quicStreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// handleQUICConnection handles a QUIC connection
func (h *Handler) handleQUICConnection(ctx context.Context, conn quic.Connection, dispatcher routing.Dispatcher) error {
	// Accept a stream for Reflex
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return errors.New("failed to accept QUIC stream").Base(err)
	}

	// Create stream wrapper
	streamConn := &quicStreamConn{
		stream: stream,
		conn:   conn,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}

	// Wrap in stat.Connection for compatibility
	statConn := stat.Connection(streamConn)

	// Log QUIC connection
	errors.LogInfo(ctx, "QUIC connection from ", conn.RemoteAddr())

	// Process Reflex protocol on QUIC stream
	// This reuses the existing Process method
	return h.Process(ctx, net.Network_TCP, statConn, dispatcher)
}

// SetupQUICListener sets up a QUIC listener for Reflex
// Note: This is a helper function. In practice, QUIC listener should be set up
// at the transport layer (similar to how Xray handles it in splithttp)
func (h *Handler) SetupQUICListener(ctx context.Context, addr string, tlsConfig *tls.Config, dispatcher routing.Dispatcher) error {
	// Parse address
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return errors.New("failed to resolve UDP address").Base(err)
	}

	// Listen on UDP
	udpConn, err := internet.ListenSystemPacket(ctx, udpAddr, nil)
	if err != nil {
		return errors.New("failed to listen UDP").Base(err)
	}

	// Create QUIC config
	quicConfig := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		EnableDatagrams: false, // We use streams, not datagrams
	}

	// Create QUIC listener
	listener, err := quic.ListenEarly(udpConn, tlsConfig, quicConfig)
	if err != nil {
		return errors.New("failed to create QUIC listener").Base(err)
	}

	errors.LogInfo(ctx, "QUIC listener started on ", addr)

	// Accept connections
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				// Check if context is cancelled
				if ctx.Err() != nil {
					return
				}
				errors.LogWarning(ctx, "failed to accept QUIC connection").Base(err)
				continue
			}

			// Handle each connection in a goroutine
			go func(c quic.Connection) {
				if err := h.handleQUICConnection(ctx, c, dispatcher); err != nil {
					errors.LogWarning(ctx, "failed to handle QUIC connection").Base(err)
				}
			}(conn)
		}
	}()

	return nil
}

// QUICSession represents a QUIC session with connection migration support
type QUICSession struct {
	conn    quic.Connection
	stream  quic.Stream
	migrated bool
}

// MigrateToDirect migrates QUIC connection to direct server address
// This implements the QUICstep technique for censorship evasion
func (s *QUICSession) MigrateToDirect(ctx context.Context, serverAddr string, tlsConfig *tls.Config) error {
	// Close old connection
	s.conn.CloseWithError(0, "migrating")

	// Resolve new address
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return errors.New("failed to resolve server address").Base(err)
	}

	// Dial new connection
	quicConfig := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		// Try to preserve connection ID for migration
		// Note: This is a simplified implementation
		// Real connection migration requires preserving connection state
	}

	newConn, err := quic.DialAddr(ctx, udpAddr.String(), tlsConfig, quicConfig)
	if err != nil {
		return errors.New("failed to dial new QUIC connection").Base(err)
	}

	// Open new stream
	newStream, err := newConn.OpenStreamSync(ctx)
	if err != nil {
		newConn.CloseWithError(0, "")
		return errors.New("failed to open new stream").Base(err)
	}

	// Update session
	s.conn = newConn
	s.stream = newStream
	s.migrated = true

	return nil
}

// GetConnectionState returns QUIC connection state
func (s *QUICSession) GetConnectionState() quic.ConnectionState {
	return s.conn.ConnectionState()
}

