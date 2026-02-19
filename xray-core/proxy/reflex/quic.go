package reflex

import (
	"context"
	"crypto/tls"
	stdnet "net"
	"time"

	"github.com/quic-go/quic-go"
)

type QUICSession struct {
	conn     *quic.Conn
	stream   quic.Stream
	migrated bool
}

func (s *QUICSession) MigrateToDirect(serverAddr string, tlsConfig *tls.Config) error {
	s.conn.CloseWithError(0, "migrating")

	newConn, err := quic.DialAddr(context.Background(), serverAddr, tlsConfig, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return err
	}

	s.conn = newConn
	s.migrated = true

	return nil
}

func SetupQUICListener(addr string, tlsConfig *tls.Config) (*quic.EarlyListener, error) {
	udpAddr, err := stdnet.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := stdnet.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	listener, err := quic.ListenEarly(udpConn, tlsConfig, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	return listener, nil
}

type QuicStreamConn struct {
	Stream     *quic.Stream
	Conn       *quic.Conn
	remoteAddr stdnet.Addr
	localAddr  stdnet.Addr
}

func (c *QuicStreamConn) Read(b []byte) (int, error) {
	return c.Stream.Read(b)
}

func (c *QuicStreamConn) Write(b []byte) (int, error) {
	return c.Stream.Write(b)
}

func (c *QuicStreamConn) Close() error {
	return c.Stream.Close()
}

func (c *QuicStreamConn) RemoteAddr() stdnet.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	if c.Conn != nil {
		state := c.Conn.ConnectionState()
		if len(state.TLS.PeerCertificates) > 0 {
			return &netAddrWrapper{addr: state.TLS.PeerCertificates[0].Subject.String()}
		}
	}
	return &netAddrWrapper{addr: "unknown"}
}

func (c *QuicStreamConn) LocalAddr() stdnet.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return &netAddrWrapper{addr: "local"}
}

func (c *QuicStreamConn) SetDeadline(t time.Time) error {
	return (*c.Stream).SetDeadline(t)
}

func (c *QuicStreamConn) SetReadDeadline(t time.Time) error {
	return (*c.Stream).SetReadDeadline(t)
}

func (c *QuicStreamConn) SetWriteDeadline(t time.Time) error {
	return (*c.Stream).SetWriteDeadline(t)
}

type netAddrWrapper struct {
	addr string
}

func (a *netAddrWrapper) Network() string {
	return "quic"
}

func (a *netAddrWrapper) String() string {
	return a.addr
}
