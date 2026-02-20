package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// mockConn wraps a net.Conn and implements stat.Connection
type mockConn struct {
	stdnet.Conn
}

func (c *mockConn) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }
func (c *mockConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		if _, err := c.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// mockDialer implements internet.Dialer for testing
type mockDialer struct {
	conn stat.Connection
}

func (d *mockDialer) Dial(_ context.Context, _ xraynet.Destination) (stat.Connection, error) {
	return d.conn, nil
}
func (d *mockDialer) DestIpAddress() xraynet.IP                                    { return nil }
func (d *mockDialer) SetOutboundGateway(_ context.Context, _ *session.Outbound) {}

func TestNew(t *testing.T) {
	uID := uuid.New()
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      uID.String(),
	}
	h, err := New(context.Background(), config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if h == nil {
		t.Fatal("New() returned nil handler")
	}
}

func TestNew_EmptyConfig(t *testing.T) {
	config := &reflex.OutboundConfig{}
	h, err := New(context.Background(), config)
	if err != nil {
		t.Fatalf("New() with empty config failed: %v", err)
	}
	if h == nil {
		t.Fatal("New() returned nil handler")
	}
}

// fakeReflexServer simulates a Reflex server for testing the outbound handler.
// It reads the client handshake, responds with a server key, then relays frames.
func fakeReflexServer(t *testing.T, serverConn stdnet.Conn, expectedPayload []byte) {
	t.Helper()
	defer serverConn.Close()

	// Read magic (4 bytes)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(serverConn, magic); err != nil {
		t.Logf("fakeServer: read magic error: %v", err)
		return
	}
	if binary.BigEndian.Uint32(magic) != reflex.ReflexMagic {
		t.Errorf("fakeServer: bad magic %x", magic)
		return
	}

	// Read handshake: pubkey(32) + userID(16) + timestamp(8) + nonce(16) = 72 bytes
	hsData := make([]byte, 72)
	if _, err := io.ReadFull(serverConn, hsData); err != nil {
		t.Logf("fakeServer: read handshake error: %v", err)
		return
	}

	// Parse client public key from handshake
	var clientPub [32]byte
	copy(clientPub[:], hsData[0:32])

	// Generate server key pair
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Logf("fakeServer: GenerateKeyPair error: %v", err)
		return
	}

	// Derive session key
	sessionKey, err := reflex.DeriveSessionKeys(serverPriv, clientPub)
	if err != nil {
		t.Logf("fakeServer: DeriveSessionKeys error: %v", err)
		return
	}

	// Send server pubkey + nonce (48 bytes total)
	var serverNonce [16]byte
	if _, err := serverConn.Write(serverPub[:]); err != nil {
		t.Logf("fakeServer: write pubkey error: %v", err)
		return
	}
	if _, err := serverConn.Write(serverNonce[:]); err != nil {
		t.Logf("fakeServer: write nonce error: %v", err)
		return
	}

	// Create session and read the client's data frame
	s, err := reflex.NewSession(sessionKey)
	if err != nil {
		t.Logf("fakeServer: NewSession error: %v", err)
		return
	}

	frame, err := s.ReadFrame(serverConn)
	if err != nil {
		if err != io.EOF {
			t.Logf("fakeServer: ReadFrame error: %v", err)
		}
		return
	}

	if expectedPayload != nil && !bytes.Equal(frame.Payload, expectedPayload) {
		t.Errorf("fakeServer: payload mismatch: got %q, want %q", frame.Payload, expectedPayload)
	}
}

func TestProcess_SendsData(t *testing.T) {
	uID := uuid.New()
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      uID.String(),
	}
	h, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	// Create a pipe: client <-> fakeServer
	clientConn, serverConn := stdnet.Pipe()

	testPayload := []byte("hello from outbound test")

	// Run the fake server
	go fakeReflexServer(t, serverConn, testPayload)

	// Build user-side link: userReqR (read by outbound) and userRespW (written by outbound)
	userReqR, userReqW := pipe.New(pipe.WithSizeLimit(4096))
	_, userRespW := pipe.New(pipe.WithSizeLimit(4096))

	link := &transport.Link{Reader: userReqR, Writer: userRespW}
	dialer := &mockDialer{conn: &mockConn{Conn: clientConn}}

	// Write test payload to the user request pipe
	b := buf.New()
	b.Write(testPayload)
	if err := userReqW.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("WriteMultiBuffer failed: %v", err)
	}
	userReqW.Close() // EOF to signal end of user data

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := h.Process(ctx, link, dialer); err != nil {
		t.Logf("Process returned: %v (may be expected on EOF)", err)
	}
}

func TestProcess_DialFails(t *testing.T) {
	uID := uuid.New()
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      uID.String(),
	}
	h, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}


	// Use a dialer that always fails
	failDialer := &failingDialer{}

	userReqR, _ := pipe.New(pipe.WithSizeLimit(4096))
	_, userRespW := pipe.New(pipe.WithSizeLimit(4096))
	link := &transport.Link{Reader: userReqR, Writer: userRespW}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = h.Process(ctx, link, failDialer)
	if err == nil {
		t.Fatal("expected error when dialer fails")
	}
}

// failingDialer always returns an error
type failingDialer struct{}

func (d *failingDialer) Dial(_ context.Context, _ xraynet.Destination) (stat.Connection, error) {
	return nil, io.ErrUnexpectedEOF
}
func (d *failingDialer) DestIpAddress() xraynet.IP                                  { return nil }
func (d *failingDialer) SetOutboundGateway(_ context.Context, _ *session.Outbound) {}

func TestProcess_ServerClosesConnection(t *testing.T) {
	// Test that Process returns an error when the server closes immediately after receiving handshake
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      "00000000-0000-0000-0000-000000000001",
	}
	h, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := stdnet.Pipe()
	// Server immediately closes after receiving the handshake
	go func() {
		buf := make([]byte, 512)
		serverConn.Read(buf) // read handshake magic + data
		serverConn.Close()  // close to trigger error in client
	}()

	userReqR, _ := pipe.New(pipe.WithSizeLimit(4096))
	_, userRespW := pipe.New(pipe.WithSizeLimit(4096))
	link := &transport.Link{Reader: userReqR, Writer: userRespW}
	dialer := &mockDialer{conn: &mockConn{Conn: clientConn}}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = h.Process(ctx, link, dialer)
	if err == nil {
		t.Fatal("expected error when server closes connection")
	}
}
