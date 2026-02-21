package inbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type fakeConn struct {
	r bytes.Reader
	w bytes.Buffer
}

func newFakeConn(in []byte) *fakeConn {
	return &fakeConn{r: *bytes.NewReader(in)}
}

func (c *fakeConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)      { return c.w.Write(b) }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() stdnet.Addr           { return &stdnet.TCPAddr{} }
func (c *fakeConn) RemoteAddr() stdnet.Addr          { return &stdnet.TCPAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type noOpDispatcher struct{}

func (noOpDispatcher) Type() interface{} { return (*routing.Dispatcher)(nil) }
func (noOpDispatcher) Start() error      { return nil }
func (noOpDispatcher) Close() error      { return nil }
func (noOpDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, io.EOF
}
func (noOpDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return io.EOF
}

func buildClientHandshake(t *testing.T, id [16]byte, ts int64, nonce [16]byte, policy []byte) ClientHandshake {
	t.Helper()
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	var pub [32]byte
	copy(pub[:], priv.PublicKey().Bytes())
	return ClientHandshake{
		PublicKey: pub,
		UserID:    id,
		PolicyReq: policy,
		Timestamp: ts,
		Nonce:     nonce,
	}
}

func marshalClientHandshake(hs ClientHandshake) []byte {
	raw := make([]byte, 74+len(hs.PolicyReq))
	copy(raw[0:32], hs.PublicKey[:])
	copy(raw[32:48], hs.UserID[:])
	binary.BigEndian.PutUint64(raw[48:56], uint64(hs.Timestamp))
	copy(raw[56:72], hs.Nonce[:])
	binary.BigEndian.PutUint16(raw[72:74], uint16(len(hs.PolicyReq)))
	copy(raw[74:], hs.PolicyReq)
	return raw
}

func TestDetectionHelpers(t *testing.T) {
	h := &Handler{}
	if !h.isReflexMagic([]byte{0x52, 0x46, 0x58, 0x4c}) {
		t.Fatal("expected reflex magic detection")
	}
	if !h.isHTTPPostLike([]byte("POST /")) {
		t.Fatal("expected http post detection")
	}
	if !h.isReflexHandshake([]byte("POST /")) {
		t.Fatal("expected reflex handshake detection")
	}
}

func TestPeekForDetection(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("abc"))
	got, err := peekForDetection(reader, 8)
	if err != nil {
		t.Fatalf("peek should return available bytes: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("unexpected peeked data: %q", string(got))
	}
}

func TestBinaryHandshakeRoundTrip(t *testing.T) {
	var id [16]byte
	copy(id[:], []byte("0123456789abcdef"))
	var nonce [16]byte
	copy(nonce[:], []byte("fedcba9876543210"))

	hs := ClientHandshake{
		UserID:    id,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
		PolicyReq: []byte(`{"mode":"test"}`),
	}
	raw := marshalClientHandshake(hs)

	parsed, err := parseBinaryHandshake(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Timestamp != hs.Timestamp {
		t.Fatalf("timestamp mismatch: got=%d want=%d", parsed.Timestamp, hs.Timestamp)
	}

	readParsed, err := readBinaryHandshake(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(readParsed.PolicyReq, hs.PolicyReq) {
		t.Fatalf("policy mismatch: got=%q want=%q", string(readParsed.PolicyReq), string(hs.PolicyReq))
	}
}

func TestValidateHandshakeTimestamp(t *testing.T) {
	if err := validateHandshakeTimestamp(time.Now().Unix()); err != nil {
		t.Fatalf("expected valid timestamp: %v", err)
	}
	if err := validateHandshakeTimestamp(time.Now().Add(-10 * time.Minute).Unix()); err == nil {
		t.Fatal("expected timestamp out of range")
	}
}

func TestNonceStoreAndCleanup(t *testing.T) {
	h := &Handler{
		seenNonces:    make(map[[16]byte]int64),
		nonceLifetime: time.Second,
	}
	var nonce [16]byte
	nonce[0] = 1
	if !h.checkAndStoreNonce(nonce) {
		t.Fatal("first nonce insert should pass")
	}
	if h.checkAndStoreNonce(nonce) {
		t.Fatal("duplicate nonce should fail")
	}
	h.seenNonces[nonce] = time.Now().Add(-3 * time.Second).Unix()
	h.cleanupExpiredNonces(time.Now().Unix())
	if len(h.seenNonces) != 0 {
		t.Fatal("expected expired nonce cleanup")
	}
}

func TestAuthenticateUserAndPolicy(t *testing.T) {
	id := uuid.New()
	h := &Handler{
		clients: []*protocol.MemoryUser{
			{
				Email:   id.String(),
				Account: &MemoryAccount{ID: id.String(), Policy: "p"},
			},
		},
	}
	var userID [16]byte
	copy(userID[:], id.Bytes())

	user, err := h.authenticateUser(userID)
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if got := userPolicy(user); got != "p" {
		t.Fatalf("policy mismatch: got=%q want=%q", got, "p")
	}
}

func TestKeyDerivationAndPolicyEncrypt(t *testing.T) {
	privA, pubA, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privB, pubB, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sharedA, err := deriveSharedKey(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	sharedB, err := deriveSharedKey(privB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	if sharedA != sharedB {
		t.Fatal("shared keys should match")
	}

	sessionKey, err := deriveSessionKey(sharedA[:], []byte("1234567890123456"))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := encryptPolicyGrant(sessionKey, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if len(grant) <= 12 {
		t.Fatal("encrypted grant should include nonce and ciphertext")
	}
}

func TestHandshakeResponseAndHTTPError(t *testing.T) {
	var w bytes.Buffer
	hs := ServerHandshake{}
	copy(hs.PublicKey[:], []byte("12345678901234567890123456789012"))
	hs.PolicyGrant = []byte("abc")
	if err := writeHandshakeResponse(&w, hs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "200 OK") {
		t.Fatal("missing 200 response")
	}
	if err := writeHTTPError(&w, 403); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "403 Forbidden") {
		t.Fatal("missing 403 response")
	}
}

func TestHandleReflexHTTPFallbackOnBadBody(t *testing.T) {
	h := &Handler{}
	conn := newFakeConn([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbad!"))
	reader := bufio.NewReader(conn)
	err := h.handleReflexHTTP(context.Background(), reader, conn, noOpDispatcher{})
	if err == nil {
		t.Fatal("expected fallback error without configured fallback")
	}
}

func TestHandleReflexHTTPSuccessPathToSessionError(t *testing.T) {
	id := uuid.New()
	var userID [16]byte
	copy(userID[:], id.Bytes())
	var nonce [16]byte
	copy(nonce[:], []byte("nonce-1234567890"))

	h := &Handler{
		clients: []*protocol.MemoryUser{
			{Account: &MemoryAccount{ID: id.String(), Policy: "normal"}},
		},
		seenNonces:    make(map[[16]byte]int64),
		nonceLifetime: defaultNonceLifetime,
	}
	hs := buildClientHandshake(t, userID, time.Now().Unix(), nonce, nil)
	raw := marshalClientHandshake(hs)
	envelope, _ := json.Marshal(map[string]string{"data": base64.StdEncoding.EncodeToString(raw)})
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", len(envelope))
	conn := newFakeConn(append([]byte(req), envelope...))
	reader := bufio.NewReader(conn)

	_ = h.handleReflexHTTP(context.Background(), reader, conn, noOpDispatcher{})
	if !strings.Contains(conn.w.String(), "200 OK") && !strings.Contains(conn.w.String(), "403 Forbidden") {
		t.Fatal("expected handshake response or auth error to be written")
	}
}

func TestHandleFallbackWithoutConfig(t *testing.T) {
	h := &Handler{}
	conn := newFakeConn(nil)
	reader := bufio.NewReader(strings.NewReader("x"))
	if err := h.handleFallback(context.Background(), reader, conn); err == nil {
		t.Fatal("expected fallback config error")
	}
}
