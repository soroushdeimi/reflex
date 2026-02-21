package tests

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	reflexin "github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport"
)

type memConn struct {
	r bytes.Reader
	w bytes.Buffer
}

func newMemConn(in []byte) *memConn                 { return &memConn{r: *bytes.NewReader(in)} }
func (c *memConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *memConn) Write(b []byte) (int, error)      { return c.w.Write(b) }
func (c *memConn) Close() error                     { return nil }
func (c *memConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type deadDispatcher struct{}

func (deadDispatcher) Type() interface{} { return (*routing.Dispatcher)(nil) }
func (deadDispatcher) Start() error      { return nil }
func (deadDispatcher) Close() error      { return nil }
func (deadDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, io.EOF
}
func (deadDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return io.EOF
}

func buildHandshakeBinary(t *testing.T, userID [16]byte) []byte {
	t.Helper()
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pub [32]byte
	copy(pub[:], priv.PublicKey().Bytes())

	var nonce [16]byte
	copy(nonce[:], []byte("nonce-1234567890"))

	raw := make([]byte, 4+74)
	binary.BigEndian.PutUint32(raw[0:4], reflexin.ReflexMagic)
	copy(raw[4:36], pub[:])
	copy(raw[36:52], userID[:])
	binary.BigEndian.PutUint64(raw[52:60], uint64(time.Now().Unix()))
	copy(raw[60:76], nonce[:])
	binary.BigEndian.PutUint16(raw[76:78], 0)
	return raw
}

func TestReflexFallback(t *testing.T) {
	cfg := &reflex.InboundConfig{}
	in, err := reflexin.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := in.(*reflexin.Handler)
	conn := newMemConn([]byte("invalid traffic"))
	if err := h.Process(context.Background(), xnet.Network_TCP, conn, deadDispatcher{}); err == nil {
		t.Fatal("expected fallback error when no fallback is configured")
	}
}

func TestReflexHandshake(t *testing.T) {
	id := "11111111-1111-1111-1111-111111111111"
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: id, Policy: "mimic-http2-api"}},
	}
	in, err := reflexin.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := in.(*reflexin.Handler)

	uid, err := uuid.ParseString(id)
	if err != nil {
		t.Fatal(err)
	}
	var userID [16]byte
	copy(userID[:], uid.Bytes())

	conn := newMemConn(buildHandshakeBinary(t, userID))
	if err := h.Process(context.Background(), xnet.Network_TCP, conn, deadDispatcher{}); err != nil {
		t.Fatalf("unexpected process error: %v", err)
	}
	if !bytes.Contains(conn.w.Bytes(), []byte("200 OK")) && !bytes.Contains(conn.w.Bytes(), []byte("403 Forbidden")) {
		t.Fatalf("expected handshake response, got: %s", conn.w.String())
	}
}

func TestReflexEncryptionRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	writer, err := reflexin.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := reflexin.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("test data")
	var wire bytes.Buffer
	if err := writer.WriteFrame(&wire, reflexin.FrameTypeData, payload); err != nil {
		t.Fatal(err)
	}
	frame, err := reader.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, frame.Payload) {
		t.Fatalf("payload mismatch: got=%q want=%q", frame.Payload, payload)
	}
}
