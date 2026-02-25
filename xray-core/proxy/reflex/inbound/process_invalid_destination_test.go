package inbound

import (
	"context"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
	"github.com/xtls/xray-core/proxy/reflex/tunnel"
)

func TestProcess_ReflexHandshakeButInvalidDestination_NoFallback_NoDispatch(t *testing.T) {
	// Start a fallback listener to detect (wrong) fallback dialing.
	fbLn, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	defer fbLn.Close()
	fbPort := fbLn.Addr().(*stdnet.TCPAddr).Port

	acceptedCh := make(chan struct{}, 1)
	go func() {
		c, e := fbLn.Accept()
		if e == nil && c != nil {
			acceptedCh <- struct{}{}
			_ = c.Close()
		}
	}()

	// Arrange inbound config with one allowed user + fallback enabled.
	id, err := uuid.ParseString("d89d6641-3b1a-4f51-a194-9c9109fd21b6")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: id.String(), Policy: "default"},
		},
		Fallback: &reflex.Fallback{Dest: uint32(fbPort)},
	}

	h, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// stdnet.Pipe simulates client <-> inbound tcp conn.
	clientConn, inboundConn := stdnet.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	procErrCh := make(chan error, 1)
	go func() {
		procErrCh <- h.Process(ctx, net.Network_TCP, inboundConn, routing.Dispatcher(&panicDispatcher{}))
	}()

	// ---- Client: Step2 handshake (HTTP flavor) ----
	var userID [handshake.UserIDSize]byte
	copy(userID[:], id.Bytes())

	clientEngine := reflex.NewClientHandshakeEngine(userID, "example.com")
	siClient, err := clientEngine.DoHandshakeHTTP(clientConn)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	// ---- Client: Step3 send FIRST DATA frame with INVALID destination header ----
	sess, err := tunnel.NewSession(siClient.SessionKey[:])
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	// Invalid SOCKS-like destination header:
	// atypDomain=0x03, domain length=16 but only 1 byte of domain provided -> Decode must fail.
	invalidDestPayload := []byte{0x03, 0x10, 'a'} // need 1+1+16+2 bytes at least
	if err := sess.WriteFrame(clientConn, tunnel.FrameTypeData, invalidDestPayload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Close client side to unblock any pending reads (defensive).
	_ = clientConn.Close()

	// ---- Assert Process ends with an error and NOT via fallback ----
	var perr error
	select {
	case perr = <-procErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Process to return")
	}

	if perr == nil {
		t.Fatal("expected error, got nil")
	}
	// Ensure failure is specifically at destination stage (not handshake).
	if !strings.Contains(perr.Error(), "failed to read destination") {
		t.Fatalf("unexpected error: %v", perr)
	}

	// Ensure fallback was NOT dialed (no accept on fallback listener).
	select {
	case <-acceptedCh:
		t.Fatal("fallback was unexpectedly dialed")
	case <-time.After(200 * time.Millisecond):
		// ok
	}

	// Ensure no goroutine is stuck (best-effort): let background accept exit naturally on close.
	_, _ = io.WriteString(io.Discard, "")
}
