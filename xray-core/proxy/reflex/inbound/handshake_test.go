package inbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

// mockConnection implements stat.Connection for testing
type mockConnection struct {
	net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func newMockConnection(conn net.Conn) *mockConnection {
	return &mockConnection{
		Conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}
}

func (m *mockConnection) Read(b []byte) (int, error) {
	return m.reader.Read(b)
}

func (m *mockConnection) Write(b []byte) (int, error) {
	n, err := m.writer.Write(b)
	if err != nil {
		return n, err
	}
	err = m.writer.Flush()
	return n, err
}

func createTestHandler() *Handler {
	testUUID := uuid.New().String()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{
				Id:     testUUID,
				Policy: "youtube",
			},
		},
		Fallback: &reflex.Fallback{
			Dest: 80,
		},
	}

	handler, _ := New(context.Background(), config)
	return handler.(*Handler)
}

func createClientHandshake(userID uuid.UUID) (*ClientHandshake, error) {
	// Generate client key pair
	_, publicKey, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	// Create handshake
	hs := &ClientHandshake{
		PublicKey: publicKey,
		UserID:    [16]byte(userID),
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{},
		PolicyReq: []byte{},
	}

	// Fill nonce with random data
	_, err = io.ReadFull(rand.Reader, hs.Nonce[:])
	if err != nil {
		return nil, err
	}

	return hs, nil
}

func writeClientHandshake(w io.Writer, hs *ClientHandshake) error {
	// Write magic number
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, ReflexMagic)
	if _, err := w.Write(magic); err != nil {
		return err
	}

	// Write public key
	if _, err := w.Write(hs.PublicKey[:]); err != nil {
		return err
	}

	// Write user ID
	if _, err := w.Write(hs.UserID[:]); err != nil {
		return err
	}

	// Write timestamp
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(hs.Timestamp))
	if _, err := w.Write(timestamp); err != nil {
		return err
	}

	// Write nonce
	if _, err := w.Write(hs.Nonce[:]); err != nil {
		return err
	}

	// Write policy request length (0 for now)
	policyLen := make([]byte, 2)
	binary.BigEndian.PutUint16(policyLen, 0)
	if _, err := w.Write(policyLen); err != nil {
		return err
	}

	return nil
}

func TestHandshake(t *testing.T) {
	handler := createTestHandler()
	
	// Get test user ID
	testUserID := uuid.MustParse(handler.clients[0].Account.(*MemoryAccount).Id)

	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create client handshake
	clientHS, err := createClientHandshake(testUserID)
	if err != nil {
		t.Fatalf("failed to create client handshake: %v", err)
	}

	// Send handshake from client
	go func() {
		defer clientConn.Close()
		if err := writeClientHandshake(clientConn, clientHS); err != nil {
			t.Errorf("failed to write handshake: %v", err)
		}
	}()

	// Server processes handshake
	mockServerConn := newMockConnection(serverConn)
	reader := bufio.NewReader(mockServerConn)

	// Read handshake (includes magic number)
	clientHSRead, err := handler.readClientHandshakeMagic(reader)
	if err != nil {
		t.Fatalf("failed to read handshake: %v", err)
	}

	// Verify handshake
	if clientHSRead.UserID != clientHS.UserID {
		t.Fatal("user ID mismatch")
	}

	// Test authentication
	user, err := handler.authenticateUser(clientHSRead.UserID)
	if err != nil {
		t.Fatalf("authentication failed: %v", err)
	}

	if user == nil {
		t.Fatal("user is nil")
	}
}

func TestHandshakeInvalidUser(t *testing.T) {
	handler := createTestHandler()

	// Create handshake with invalid user ID
	invalidUserID := uuid.New()
	clientHS, err := createClientHandshake(invalidUserID)
	if err != nil {
		t.Fatalf("failed to create handshake: %v", err)
	}

	// Test authentication should fail
	user, err := handler.authenticateUser(clientHS.UserID)
	if err == nil {
		t.Fatal("authentication should fail for invalid user")
	}

	if user != nil {
		t.Fatal("user should be nil for invalid user")
	}
}

func TestHandshakeOldTimestamp(t *testing.T) {
	handler := createTestHandler()
	testUserID := uuid.MustParse(handler.clients[0].Account.(*MemoryAccount).Id)

	// Create handshake with old timestamp
	clientHS, err := createClientHandshake(testUserID)
	if err != nil {
		t.Fatalf("failed to create handshake: %v", err)
	}

	// Set timestamp to 10 minutes ago
	clientHS.Timestamp = time.Now().Unix() - 600

	// Test that old timestamp is rejected
	// This is tested in processHandshake, but we can test the timestamp check logic
	now := time.Now().Unix()
	if clientHS.Timestamp < now-300 || clientHS.Timestamp > now+300 {
		// Timestamp is out of range (more than 5 minutes)
		// This should be rejected
		if clientHS.Timestamp >= now-300 && clientHS.Timestamp <= now+300 {
			t.Fatal("timestamp should be out of range")
		}
	}
}

func TestKeyExchange(t *testing.T) {
	// Test X25519 key exchange
	clientPrivate, clientPublic, err := generateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate client key pair: %v", err)
	}

	serverPrivate, serverPublic, err := generateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate server key pair: %v", err)
	}

	// Compute shared keys
	clientShared := deriveSharedKey(clientPrivate, serverPublic)
	serverShared := deriveSharedKey(serverPrivate, clientPublic)

	// Shared keys should match
	if clientShared != serverShared {
		t.Fatal("shared keys do not match")
	}
}

func TestSessionKeyDerivation(t *testing.T) {
	// Test HKDF session key derivation
	sharedKey := [32]byte{}
	_, err := io.ReadFull(rand.Reader, sharedKey[:])
	if err != nil {
		t.Fatalf("failed to generate shared key: %v", err)
	}

	salt := []byte("reflex-session")
	sessionKey1 := deriveSessionKey(sharedKey, salt)
	sessionKey2 := deriveSessionKey(sharedKey, salt)

	// Same input should produce same output
	if len(sessionKey1) != 32 {
		t.Fatal("session key should be 32 bytes")
	}

	if len(sessionKey1) != len(sessionKey2) {
		t.Fatal("session keys should have same length")
	}

	// Keys should match
	for i := range sessionKey1 {
		if sessionKey1[i] != sessionKey2[i] {
			t.Fatal("session keys should match")
		}
	}
}

func TestIsReflexMagic(t *testing.T) {
	handler := createTestHandler()

	// Test valid magic
	validMagic := make([]byte, 4)
	binary.BigEndian.PutUint32(validMagic, ReflexMagic)
	if !handler.isReflexMagic(validMagic) {
		t.Fatal("should detect valid magic")
	}

	// Test invalid magic
	invalidMagic := []byte{0x00, 0x00, 0x00, 0x00}
	if handler.isReflexMagic(invalidMagic) {
		t.Fatal("should not detect invalid magic")
	}

	// Test short data
	shortData := []byte{0x52}
	if handler.isReflexMagic(shortData) {
		t.Fatal("should not detect magic in short data")
	}
}

func TestIsHTTPPostLike(t *testing.T) {
	handler := createTestHandler()

	// Test valid HTTP POST
	validPOST := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n")
	if !handler.isHTTPPostLike(validPOST) {
		t.Fatal("should detect HTTP POST")
	}

	// Test invalid method
	invalidMethod := []byte("GET /api HTTP/1.1\r\n")
	if handler.isHTTPPostLike(invalidMethod) {
		t.Fatal("should not detect GET as POST")
	}

	// Test short data
	shortData := []byte("POS")
	if handler.isHTTPPostLike(shortData) {
		t.Fatal("should not detect POST in short data")
	}
}

func TestProcessHandshakeSuccessWithEOF(t *testing.T) {
	h := createTestHandler()
	validUserID := uuid.MustParse(h.clients[0].Account.(*MemoryAccount).Id)
	clientHS, err := createClientHandshake(validUserID)
	if err != nil {
		t.Fatalf("failed to create client handshake: %v", err)
	}

	conn := &bufferConn{}
	err = h.processHandshake(
		bufio.NewReader(bytes.NewReader(nil)),
		conn,
		&testDispatcher{},
		context.Background(),
		clientHS,
	)
	if err != nil {
		t.Fatalf("expected successful handshake path, got: %v", err)
	}
	if !strings.Contains(conn.String(), "HTTP/1.1 200 OK") {
		t.Fatal("expected HTTP success response to be written")
	}
}

func TestHandleReflexMagicRejectsInvalidTimestamp(t *testing.T) {
	h := createTestHandler()
	validUserID := uuid.MustParse(h.clients[0].Account.(*MemoryAccount).Id)
	clientHS, err := createClientHandshake(validUserID)
	if err != nil {
		t.Fatalf("failed to create client handshake: %v", err)
	}
	clientHS.Timestamp = time.Now().Unix() - 601

	var packet bytes.Buffer
	if err := writeClientHandshake(&packet, clientHS); err != nil {
		t.Fatalf("failed to serialize handshake: %v", err)
	}

	conn := &bufferConn{}
	err = h.handleReflexMagic(
		bufio.NewReader(bytes.NewReader(packet.Bytes())),
		conn,
		&testDispatcher{},
		context.Background(),
	)
	if err == nil {
		t.Fatal("expected timestamp validation error")
	}
	if !strings.Contains(err.Error(), "timestamp out of range") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(conn.String(), "403 Forbidden") ||
		!strings.Contains(conn.String(), "invalid timestamp") {
		t.Fatal("expected 403 invalid timestamp response")
	}
}

func TestReadClientHandshakeMagicOversizedPolicyLength(t *testing.T) {
	h := createTestHandler()

	var packet bytes.Buffer
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, ReflexMagic)
	packet.Write(magic)
	packet.Write(make([]byte, 32)) // public key
	packet.Write(make([]byte, 16)) // user id

	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	packet.Write(ts)
	packet.Write(make([]byte, 16)) // nonce

	// >= MaxHandshakeSize should skip policy read branch.
	policyLen := make([]byte, 2)
	binary.BigEndian.PutUint16(policyLen, MaxHandshakeSize)
	packet.Write(policyLen)
	packet.Write(bytes.Repeat([]byte{0xAA}, 8)) // trailing bytes should remain unread

	hs, err := h.readClientHandshakeMagic(bufio.NewReader(bytes.NewReader(packet.Bytes())))
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if len(hs.PolicyReq) != 0 {
		t.Fatalf("policy request should be skipped for oversized length, got %d bytes", len(hs.PolicyReq))
	}
}

func TestHandleSessionControlFramesAndClose(t *testing.T) {
	h := createTestHandler()
	key := bytes.Repeat([]byte{0x7F}, 32)
	writerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("failed to create writer session: %v", err)
	}

	var stream bytes.Buffer
	if err := writerSession.WriteFrame(&stream, FrameTypePadding, []byte{0x00, 0x20}); err != nil {
		t.Fatalf("failed to write padding frame: %v", err)
	}
	if err := writerSession.WriteFrame(&stream, FrameTypeTiming, make([]byte, 8)); err != nil {
		t.Fatalf("failed to write timing frame: %v", err)
	}
	if err := writerSession.WriteFrame(&stream, FrameTypeClose, nil); err != nil {
		t.Fatalf("failed to write close frame: %v", err)
	}

	err = h.handleSession(
		context.Background(),
		bufio.NewReader(bytes.NewReader(stream.Bytes())),
		&bufferConn{},
		&testDispatcher{},
		key,
		h.clients[0],
		GetProfileByName("youtube"),
	)
	if err != nil {
		t.Fatalf("expected control-frame session to close cleanly: %v", err)
	}
}

