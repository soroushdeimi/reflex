package crypto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/protocol"
	"golang.org/x/crypto/curve25519"
)

//
// ===================== Test Utilities =====================
//

// resetNonceCache clears the global replay cache before each test
// to guarantee isolation between test cases.
func resetNonceCache() {
	nonceMutex.Lock()
	defer nonceMutex.Unlock()
	nonceCache = make(map[[16]byte]int64)
}

// drain prevents net.Pipe deadlock by continuously reading
// any server response written during handshake.
func drain(conn net.Conn) {
	go func() {
		io.Copy(io.Discard, conn)
	}()
}

//
// ===================== Handshake Encoding Helpers =====================
//

// encodeHandshake serializes a ClientHandshake into raw binary format.
func encodeHandshake(hs ClientHandshake) []byte {
	buf := new(bytes.Buffer)

	buf.Write(hs.PublicKey[:])
	buf.Write(hs.UserID[:])

	binary.Write(buf, binary.BigEndian, uint16(len(hs.PolicyReq)))
	buf.Write(hs.PolicyReq)

	binary.Write(buf, binary.BigEndian, hs.Timestamp)
	buf.Write(hs.Nonce[:])

	return buf.Bytes()
}

// createValidHandshake builds a complete HTTP POST-like handshake request.
func createValidHandshake(userUUID string, timestamp int64, nonce [16]byte) []byte {

	var priv [32]byte
	rand.Read(priv[:])

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	var userID [16]byte
	parsed, _ := uuid.Parse(userUUID)
	copy(userID[:], parsed[:])

	hs := ClientHandshake{
		PublicKey: pub,
		UserID:    userID,
		PolicyReq: []byte("policy"),
		Timestamp: timestamp,
		Nonce:     nonce,
	}

	raw := encodeHandshake(hs)
	encoded := base64.StdEncoding.EncodeToString(raw)

	body := fmt.Sprintf(`{"data":"%s"}`, encoded)

	request := fmt.Sprintf(
		"POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body),
		body,
	)

	return []byte(request)
}

//
// ===================== Handshake Tests =====================
//

// TestHandshakeSuccess verifies a valid handshake establishes a session.
func TestHandshakeSuccess(t *testing.T) {

	resetNonceCache()

	userUUID := "123e4567-e89b-12d3-a456-426614174000"

	client := &protocol.MemoryUser{Email: userUUID}
	clients := []*protocol.MemoryUser{client}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	drain(clientConn)

	var nonce [16]byte
	rand.Read(nonce[:])

	go func() {
		req := createValidHandshake(userUUID, time.Now().Unix(), nonce)
		clientConn.Write(req)
	}()

	reader := bufio.NewReader(serverConn)
	session, err := ServerHandshake(reader, serverConn, clients)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if session == nil {
		t.Fatal("session must not be nil")
	}
}

// TestInvalidUUID ensures authentication fails for unknown users.
func TestInvalidUUID(t *testing.T) {

	resetNonceCache()

	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	wrongUUID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	client := &protocol.MemoryUser{Email: validUUID}
	clients := []*protocol.MemoryUser{client}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	drain(clientConn)

	var nonce [16]byte
	rand.Read(nonce[:])

	go func() {
		req := createValidHandshake(wrongUUID, time.Now().Unix(), nonce)
		clientConn.Write(req)
	}()

	reader := bufio.NewReader(serverConn)
	_, err := ServerHandshake(reader, serverConn, clients)
	if err == nil {
		t.Fatal("expected authentication failure")
	}
}

// TestOldTimestamp verifies stale handshakes are rejected.
func TestOldTimestamp(t *testing.T) {

	resetNonceCache()

	userUUID := "123e4567-e89b-12d3-a456-426614174000"

	client := &protocol.MemoryUser{Email: userUUID}
	clients := []*protocol.MemoryUser{client}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	drain(clientConn)

	var nonce [16]byte
	rand.Read(nonce[:])

	oldTimestamp := time.Now().Unix() - 10000

	go func() {
		req := createValidHandshake(userUUID, oldTimestamp, nonce)
		clientConn.Write(req)
	}()

	reader := bufio.NewReader(serverConn)
	_, err := ServerHandshake(reader, serverConn, clients)
	if err == nil {
		t.Fatal("expected timestamp rejection")
	}
}

//
// ===================== Replay Protection Test =====================
//

// nilConn is a lightweight net.Conn mock used for direct
// processHandshake testing without full HTTP exchange.
type nilConn struct{}

func (n nilConn) Read(b []byte) (int, error)         { return 0, nil }
func (n nilConn) Write(b []byte) (int, error)        { return len(b), nil }
func (n nilConn) Close() error                       { return nil }
func (n nilConn) LocalAddr() net.Addr                { return nil }
func (n nilConn) RemoteAddr() net.Addr               { return nil }
func (n nilConn) SetDeadline(t time.Time) error      { return nil }
func (n nilConn) SetReadDeadline(t time.Time) error  { return nil }
func (n nilConn) SetWriteDeadline(t time.Time) error { return nil }

// TestReplay ensures nonce reuse is rejected.
func TestReplay(t *testing.T) {

	resetNonceCache()

	userUUID := "123e4567-e89b-12d3-a456-426614174000"

	client := &protocol.MemoryUser{Email: userUUID}
	clients := []*protocol.MemoryUser{client}

	var priv [32]byte
	rand.Read(priv[:])
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	var userID [16]byte
	parsed, _ := uuid.Parse(userUUID)
	copy(userID[:], parsed[:])

	var nonce [16]byte
	rand.Read(nonce[:])

	hs := ClientHandshake{
		PublicKey: pub,
		UserID:    userID,
		PolicyReq: []byte("policy"),
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	// First handshake should succeed
	_, err1 := processHandshake(nilConn{}, clients, hs)
	if err1 != nil {
		t.Fatal(err1)
	}

	// Second handshake with identical nonce must fail
	_, err2 := processHandshake(nilConn{}, clients, hs)
	if err2 == nil {
		t.Fatal("expected replay rejection")
	}
}
