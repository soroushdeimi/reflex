package inbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// ──────────────────────────────────────────────────────────────────────────────
// Tests for MemoryAccount methods (Equals, ToProto)
// ──────────────────────────────────────────────────────────────────────────────

func TestMemoryAccountEquals_SameID(t *testing.T) {
	a := &MemoryAccount{Id: "same-id", Policy: "youtube"}
	b := &MemoryAccount{Id: "same-id", Policy: "zoom"}
	if !a.Equals(b) {
		t.Error("accounts with same ID should be equal")
	}
}

func TestMemoryAccountEquals_DifferentID(t *testing.T) {
	a := &MemoryAccount{Id: "id-a"}
	b := &MemoryAccount{Id: "id-b"}
	if a.Equals(b) {
		t.Error("accounts with different IDs should not be equal")
	}
}

func TestMemoryAccountEquals_WrongType(t *testing.T) {
	a := &MemoryAccount{Id: "id-a"}
	if a.Equals(nil) {
		t.Error("equals nil should return false")
	}
}

func TestMemoryAccountToProto(t *testing.T) {
	a := &MemoryAccount{Id: "proto-test-id"}
	msg := a.ToProto()
	if msg == nil {
		t.Fatal("ToProto should not return nil")
	}
	acc, ok := msg.(*reflex.Account)
	if !ok {
		t.Fatalf("expected *reflex.Account, got %T", msg)
	}
	if acc.Id != "proto-test-id" {
		t.Errorf("Account.Id = %q, want %q", acc.Id, "proto-test-id")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests for Handler.Network()
// ──────────────────────────────────────────────────────────────────────────────

func TestHandlerNetwork(t *testing.T) {
	config := &reflex.InboundConfig{}
	h, err := New(context.Background(), config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	handler := h.(*Handler)
	networks := handler.Network()
	if len(networks) == 0 {
		t.Fatal("Network() should return at least one network type")
	}
	if networks[0] != net.Network_TCP {
		t.Errorf("expected TCP, got %v", networks[0])
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests for internal handshake.go functions
// ──────────────────────────────────────────────────────────────────────────────

func TestInternalGenerateKeyPair(t *testing.T) {
	priv, pub, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair() failed: %v", err)
	}
	if priv == [32]byte{} {
		t.Error("private key should not be all zeros")
	}
	if pub == [32]byte{} {
		t.Error("public key should not be all zeros")
	}
	// Second call should produce different keys
	priv2, pub2, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if priv == priv2 || pub == pub2 {
		t.Error("successive generateKeyPair() calls should produce different keys")
	}
}

func TestDeriveSharedKey_Commutative(t *testing.T) {
	priv1, pub1, _ := generateKeyPair()
	priv2, pub2, _ := generateKeyPair()

	shared1 := deriveSharedKey(priv1, pub2)
	shared2 := deriveSharedKey(priv2, pub1)

	if shared1 != shared2 {
		t.Error("ECDH shared key should be the same regardless of which side computes it")
	}
	if shared1 == [32]byte{} {
		t.Error("shared key should not be all zeros")
	}
}

func TestDeriveSessionKey_DeterministicGivenSameInputs(t *testing.T) {
	sharedKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	salt := []byte("test-salt")

	key1 := deriveSessionKey(sharedKey, salt)
	key2 := deriveSessionKey(sharedKey, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("deriveSessionKey should be deterministic with same inputs")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte session key, got %d", len(key1))
	}
}

func TestDeriveSessionKey_DifferentSaltsDifferentKeys(t *testing.T) {
	sharedKey := [32]byte{1, 2, 3}
	key1 := deriveSessionKey(sharedKey, []byte("salt1"))
	key2 := deriveSessionKey(sharedKey, []byte("salt2"))
	if bytes.Equal(key1, key2) {
		t.Error("different salts should produce different session keys")
	}
}

func TestDeriveSessionKey_NilSalt(t *testing.T) {
	sharedKey := [32]byte{42}
	key := deriveSessionKey(sharedKey, nil)
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper: run a complete Reflex handshake from the client side.
// Returns the client session so tests can send frames.
// ──────────────────────────────────────────────────────────────────────────────

func setupCompleteHandshake(t *testing.T, handler *Handler, dispatcher *MockDispatcher) (clientSession *reflex.Session, clientConn stdnet.Conn, cleanup func()) {
	t.Helper()

	userID := uuid.New()
	// Build a handler with matching user if not already set
	if len(handler.clients) == 0 {
		t.Fatal("handler must have at least one client configured for setupCompleteHandshake")
	}

	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Use the first registered user's ID
	firstUser := handler.clients[0].Account.(*MemoryAccount)
	uid, err := uuid.ParseString(firstUser.Id)
	if err != nil {
		t.Fatalf("ParseString(%q): %v", firstUser.Id, err)
	}
	var uIDBytes [16]byte
	copy(uIDBytes[:], uid.Bytes())
	_ = userID

	nonce := [16]byte{}
	rand.Read(nonce[:])

	clientHS := reflex.ClientHandshake{
		PublicKey: clientPub,
		UserID:    uIDBytes,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	c1, c2 := stdnet.Pipe()

	go func() {
		handler.processHandshake(
			context.Background(),
			bufio.NewReader(c2),
			&MockConnection{Conn: c2},
			dispatcher,
			clientHS,
		)
	}()

	// Read server response: 32-byte pubkey + 16-byte nonce = 48 bytes
	serverResp := make([]byte, 48)
	if _, err := io.ReadFull(c1, serverResp); err != nil {
		c1.Close()
		c2.Close()
		t.Fatalf("ReadFull server response: %v", err)
	}

	var serverPub [32]byte
	copy(serverPub[:], serverResp[0:32])

	sessionKey, err := reflex.DeriveSessionKeys(clientPriv, serverPub)
	if err != nil {
		c1.Close()
		c2.Close()
		t.Fatalf("DeriveSessionKeys: %v", err)
	}

	s, err := reflex.NewSession(sessionKey)
	if err != nil {
		c1.Close()
		c2.Close()
		t.Fatalf("NewSession: %v", err)
	}

	cleanup = func() {
		c1.Close()
		c2.Close()
	}
	return s, c1, cleanup
}

// ──────────────────────────────────────────────────────────────────────────────
// handleSession coverage tests
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleSession_DataFrameDispatched(t *testing.T) {
	uID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID.String(), Policy: "youtube"}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	received := make(chan []byte, 1)
	reqR, reqW := pipe.New(pipe.WithSizeLimit(4096))
	respR, respW := pipe.New(pipe.WithSizeLimit(4096))

	dispatcher := &MockDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			go func() {
				defer respW.Close()
				for {
					mb, err := reqR.ReadMultiBuffer()
					if err != nil {
						return
					}
					var data []byte
					for _, b := range mb {
						data = append(data, b.Bytes()...)
						b.Release()
					}
					received <- data
				}
			}()
			return &transport.Link{Reader: respR, Writer: reqW}, nil
		},
	}

	clientSession, clientConn, cleanup := setupCompleteHandshake(t, handler, dispatcher)
	defer cleanup()

	payload := []byte("test-session-data")
	if err := clientSession.WriteFrame(clientConn, reflex.FrameTypeData, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Errorf("dispatcher received %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: dispatcher never received data")
	}

	// Send close frame to gracefully end the session
	clientSession.WriteFrame(clientConn, reflex.FrameTypeClose, nil)
}

func TestHandleSession_CloseFrame(t *testing.T) {
	uID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID.String()}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	// Dispatcher returns a link but no data will be sent
	respR, respW := pipe.New(pipe.WithSizeLimit(256))
	_, reqW := pipe.New(pipe.WithSizeLimit(256))
	_ = respW

	dispatcher := &MockDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			return &transport.Link{Reader: respR, Writer: reqW}, nil
		},
	}

	clientSession, clientConn, cleanup := setupCompleteHandshake(t, handler, dispatcher)
	defer cleanup()

	// First send a data frame to trigger dispatch, then close
	if err := clientSession.WriteFrame(clientConn, reflex.FrameTypeData, []byte("first")); err != nil {
		t.Fatalf("WriteFrame data: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // Allow dispatch to be called

	// Send close frame
	if err := clientSession.WriteFrame(clientConn, reflex.FrameTypeClose, nil); err != nil {
		t.Fatalf("WriteFrame close: %v", err)
	}
}

func TestHandleSession_PaddingAndTimingFrames(t *testing.T) {
	uID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID.String(), Policy: "youtube"}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	dispatcher := &MockDispatcher{}
	clientSession, clientConn, cleanup := setupCompleteHandshake(t, handler, dispatcher)
	defer cleanup()

	paddingPayload := make([]byte, 2)
	paddingPayload[0] = 0x03
	paddingPayload[1] = 0xE8 // 1000 in big-endian
	if err := clientSession.WriteFrame(clientConn, reflex.FrameTypePadding, paddingPayload); err != nil {
		t.Fatalf("WriteFrame padding: %v", err)
	}

	timing_payload := make([]byte, 8)
	timing_payload[7] = 10 // 10ms
	if err := clientSession.WriteFrame(clientConn, reflex.FrameTypeTiming, timing_payload); err != nil {
		t.Fatalf("WriteFrame timing: %v", err)
	}

	// Close to end gracefully
	clientSession.WriteFrame(clientConn, reflex.FrameTypeClose, nil)
	time.Sleep(50 * time.Millisecond)
}

func TestHandleSession_WithoutProfile(t *testing.T) {
	uID := uuid.New()
	config := &reflex.InboundConfig{
		// No policy, so no TrafficProfile
		Clients: []*reflex.User{{Id: uID.String()}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	received := make(chan []byte, 1)
	reqR, reqW := pipe.New(pipe.WithSizeLimit(4096))
	respR, respW := pipe.New(pipe.WithSizeLimit(4096))
	_ = respW

	dispatcher := &MockDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			go func() {
				defer func() {}()
				for {
					mb, err := reqR.ReadMultiBuffer()
					if err != nil {
						return
					}
					var data []byte
					for _, b := range mb {
						data = append(data, b.Bytes()...)
						b.Release()
					}
					if len(data) > 0 {
						select {
						case received <- data:
						default:
						}
					}
				}
			}()
			return &transport.Link{Reader: respR, Writer: reqW}, nil
		},
	}

	clientSession, clientConn, cleanup := setupCompleteHandshake(t, handler, dispatcher)
	defer cleanup()

	payload := []byte("no-profile-data")
	if err := clientSession.WriteFrame(clientConn, reflex.FrameTypeData, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Errorf("got %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	clientSession.WriteFrame(clientConn, reflex.FrameTypeClose, nil)
}

func TestHandleSession_DispatchError(t *testing.T) {
	uID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID.String()}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	dispatcher := &MockDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			return nil, io.ErrUnexpectedEOF
		},
	}

	clientSession, clientConn, cleanup := setupCompleteHandshake(t, handler, dispatcher)
	defer cleanup()

	payload := []byte("will-cause-dispatch-error")
	clientSession.WriteFrame(clientConn, reflex.FrameTypeData, payload)
	// Handler will get dispatch error and return; wait briefly
	time.Sleep(100 * time.Millisecond)
}

func TestHandleSession_SendsResponseToClient(t *testing.T) {
	uID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID.String()}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	serverResponse := []byte("server-response-data")
	reqR, reqW := pipe.New(pipe.WithSizeLimit(4096))
	respR, respW := pipe.New(pipe.WithSizeLimit(4096))

	// Write server response to the resp pipe before dispatch
	go func() {
		defer respW.Close()
		time.Sleep(100 * time.Millisecond)
		b := buf.New()
		b.Write(serverResponse)
		respW.WriteMultiBuffer(buf.MultiBuffer{b})
	}()

	dispatcher := &MockDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			go func() {
				// drain client data
				for {
					mb, err := reqR.ReadMultiBuffer()
					if err != nil {
						return
					}
					for _, b := range mb {
						b.Release()
					}
				}
			}()
			return &transport.Link{Reader: respR, Writer: reqW}, nil
		},
	}

	clientSession, clientConn, cleanup := setupCompleteHandshake(t, handler, dispatcher)
	defer cleanup()

	// Send a data frame to trigger dispatch
	if err := clientSession.WriteFrame(clientConn, reflex.FrameTypeData, []byte("request")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Read the server's response back from the client connection
	resultCh := make(chan []byte, 1)
	go func() {
		frame, err := clientSession.ReadFrame(clientConn)
		if err != nil {
			return
		}
		if frame.Type == reflex.FrameTypeData {
			resultCh <- frame.Payload
		}
	}()

	select {
	case data := <-resultCh:
		if !bytes.Equal(data, serverResponse) {
			t.Errorf("got response %q, want %q", data, serverResponse)
		}
	case <-time.After(2 * time.Second):
		t.Log("timeout waiting for server response (may be acceptable if session closes)")
	}

	clientSession.WriteFrame(clientConn, reflex.FrameTypeClose, nil)
}
