package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

func TestNewHandlerAndNetwork(t *testing.T) {
	hin, err := New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: "u1", Policy: "youtube"}},
		Fallback: &reflex.Fallback{
			Dest: 10000,
		},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	h, ok := hin.(*Handler)
	if !ok {
		t.Fatalf("unexpected inbound type: %T", hin)
	}
	if len(h.clients) != 1 {
		t.Fatalf("unexpected clients len: %d", len(h.clients))
	}
	if h.fallback == nil || h.fallback.Dest != 10000 {
		t.Fatal("fallback config was not applied")
	}

	networks := h.Network()
	if len(networks) != 1 || networks[0] != xnet.Network_TCP {
		t.Fatalf("unexpected network list: %+v", networks)
	}
}

func TestAuthenticateUserAndReplay(t *testing.T) {
	// fake UUID
	id := "123e4567-e89b-12d3-a456-426614174000"
	h := &Handler{
		clients: []*protocol.MemoryUser{{
			Email:   id,
			Account: &MemoryAccount{Id: id},
		}},
		nonces: make(map[string]int64),
	}

	parsed, err := uuid.ParseString(id)
	if err != nil {
		t.Fatalf("parse uuid failed: %v", err)
	}
	var uid [16]byte
	copy(uid[:], parsed[:])

	user, err := h.authenticateUser(uid)
	if err != nil {
		t.Fatalf("authenticateUser returned error: %v", err)
	}
	if user.Email != id {
		t.Fatalf("unexpected user: %s", user.Email)
	}

	var nonce [16]byte
	// nonce apparently means number used once (n[once])
	nonce[0] = 1
	now := time.Now().Unix()
	if err := h.checkReplay(user, nonce, now); err != nil {
		t.Fatalf("first nonce check failed: %v", err)
	}
	if err := h.checkReplay(user, nonce, now); err == nil {
		t.Fatal("expected replay error on duplicate nonce")
	}

	oldKey := user.Email + ":" + strings.Repeat("ab", 16)
	h.nonces[oldKey] = now - AllowedClockSkewSec*3

	var nonce2 [16]byte
	nonce2[0] = 2
	if err := h.checkReplay(user, nonce2, now); err != nil {
		t.Fatalf("second nonce check failed: %v", err)
	}
	if _, exists := h.nonces[oldKey]; exists {
		t.Fatal("expected stale nonce to be cleaned up")
	}
}

func TestAuthenticateUserNotFound(t *testing.T) {
	h := &Handler{clients: []*protocol.MemoryUser{{Email: "bad-uuid", Account: &MemoryAccount{Id: "bad-uuid"}}}}
	_, err := h.authenticateUser([16]byte{})
	if err == nil {
		t.Fatal("expected user not found error")
	}
}

func TestParseDestinationAndPayload(t *testing.T) {
	payload := []byte("hello")
	addr := "example.com"
	// 1 and 2 bytes could for port/length
	data := make([]byte, 0, 1+len(addr)+2+len(payload))
	data = append(data, byte(len(addr)))
	data = append(data, []byte(addr)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 443)
	data = append(data, portBytes...)
	data = append(data, payload...)

	dest, body, err := ParseDestinationAndPayload(data)
	if err != nil {
		t.Fatalf("ParseDestinationAndPayload returned error: %v", err)
	}
	if dest.Address.String() != addr || dest.Port.Value() != 443 {
		t.Fatalf("unexpected destination: %+v", dest)
	}
	if string(body) != "hello" {
		t.Fatalf("unexpected payload: %q", body)
	}

	if _, _, err := ParseDestinationAndPayload([]byte{1, 'a'}); err == nil {
		t.Fatal("we want error for invalid short payload")
	}
	if _, _, err := ParseDestinationAndPayload([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("we want error for invalid destination")
	}
}

func TestClientHandshakeParsing(t *testing.T) {
	// 78 = 32+16+8+16+2+4
	// key(32) + userID(16) + timestamp(8) + nonce(16) + policyReqLen(2) + policyReqData(4) = 78
	raw := make([]byte, 78)
	for i := 0; i < 32; i++ {
		raw[i] = byte(i + 1)
	}
	offset := 32
	copy(raw[offset:offset+16], []byte("abcdefghijklmnop"))
	offset += 16
	binary.BigEndian.PutUint64(raw[offset:offset+8], uint64(123456789))
	offset += 8
	copy(raw[offset:offset+16], []byte("1234567890abcdef"))
	offset += 16
	binary.BigEndian.PutUint16(raw[offset:offset+2], 4)
	offset += 2
	copy(raw[offset:offset+4], []byte("test"))

	hs, err := ParseClientHandshakeBytes(raw)
	if err != nil {
		t.Fatalf("ParseClientHandshakeBytes returned error: %v", err)
	}
	if hs.Timestamp != 123456789 || string(hs.PolicyReq) != "test" {
		t.Fatalf("unexpected handshake values: %+v", hs)
	}

	tooLarge := make([]byte, 32+16+8+16+2)
	binary.BigEndian.PutUint16(tooLarge[len(tooLarge)-2:], MaxPolicyReqLen+1)
	if _, err := ParseClientHandshakeBytes(tooLarge); err == nil {
		t.Fatal("expected too-large policy error")
	}
	// fails while trying to read key, userID, timestamp, nonce, policyReqLen, or policyReqData (too short)
	if _, err := ReadClientHandshake(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("we want short read error")
	}
}

func TestKeyDerivationAndTimestamp(t *testing.T) {
	private, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair returned error: %v", err)
	}
	if private == ([32]byte{}) || pub == ([32]byte{}) {
		t.Fatal("generated keys should not be zero")
	}

	shared, err := DeriveSharedKey(private, pub)
	if err != nil {
		t.Fatalf("DeriveSharedKey returned error: %v", err)
	}
	sessionKeyA := DeriveSessionKey(shared, []byte("salt"))
	sessionKeyB := DeriveSessionKey(shared, []byte("salt"))
	if len(sessionKeyA) != 32 || !bytes.Equal(sessionKeyA, sessionKeyB) {
		t.Fatal("derived session key should be deterministic (and equal) with same inputs")
	}

	now := time.Now().Unix()
	if err := ValidateTimestamp(now); err != nil {
		t.Fatalf("timestamp should be valid: %v", err)
	}
	if err := ValidateTimestamp(now + AllowedClockSkewSec + 1); err == nil {
		t.Fatal("we want future timestamp error")
	}
	if err := ValidateTimestamp(now - AllowedClockSkewSec - 1); err == nil {
		t.Fatal("we want old timestamp error")
	}
}

func TestPolicyAndHTTPResponseHelpers(t *testing.T) {
	h := &Handler{userPolicies: map[string]string{"a@b": "zoom"}}
	if got := h.getUserPolicy(&protocol.MemoryUser{Email: "a@b"}); got != "zoom" {
		t.Fatalf("unexpected policy: %s", got)
	}
	if got := h.getUserPolicy(&protocol.MemoryUser{Email: "something"}); got != DefaultProfile.Name {
		t.Fatalf("unexpected default policy for unknown user: %s", got)
	}
	if got := h.getUserPolicy(nil); got != DefaultProfile.Name {
		t.Fatalf("unexpected default policy for nil user: %s", got)
	}

	sessionKey := []byte("0123456789abcdef")
	user := &protocol.MemoryUser{Email: "user@example.com"}
	enc := EncryptPolicyGrant(user, sessionKey)
	dec := EncryptPolicyGrant(&protocol.MemoryUser{Email: string(enc)}, sessionKey)
	// uses the fact that same XOR twice should get back original value, since policy grant is just XOR of email and session key
	if string(dec) != user.Email {
		t.Fatal("policy grant xor should be reversible")
	}

	var pub [32]byte
	copy(pub[:], []byte("0123456789abcdefghijklmnopqrstuv"))
	resp := FormatHTTPResponse(ServerHandshake{PublicKey: pub, PolicyGrant: []byte("grant")})
	if !bytes.Contains(resp, []byte("HTTP/1.1 200 OK")) {
		t.Fatal("http response does not contain status line")
	}

	parts := bytes.SplitN(resp, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		t.Fatal("invalid HTTP response format")
	}
	var payload map[string]string
	if err := json.Unmarshal(parts[1], &payload); err != nil {
		t.Fatalf("json parse failed: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status payload: %q", payload["status"])
	}
	if _, err := base64.StdEncoding.DecodeString(payload["publicKey"]); err != nil {
		t.Fatalf("invalid encoded publicKey: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(payload["policyGrant"]); err != nil {
		t.Fatalf("invalid encoded policyGrant: %v", err)
	}
}

func TestHandleFallbackAndProcessNonTCP(t *testing.T) {
	h := &Handler{}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := client.Read(buf)
		done <- buf[:n]
	}()

	if err := h.handleFallback(context.Background(), bufio.NewReader(server), server); err != nil {
		t.Fatalf("handleFallback returned error: %v", err)
	}
	respRaw := <-done
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respRaw)), nil)
	if err != nil {
		t.Fatalf("failed to parse fallback deny response: %v, raw=%q", err, string(respRaw))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("we want fallback deny status %d, got %d (status=%q)", http.StatusForbidden, resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed reading fallback deny response body: %v", err)
	}
	// because there's no rule for here we are not strict about body content
	if len(bytes.TrimSpace(body)) == 0 {
		t.Fatal("we want non-empty fallback deny body")
	}

	client2, server2 := net.Pipe()
	defer func() { _ = client2.Close() }()
	defer func() { _ = server2.Close() }()

	done2 := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := client2.Read(buf)
		done2 <- buf[:n]
	}()

	if err := h.Process(context.Background(), xnet.Network_UDP, server2, nil); err != nil {
		t.Fatalf("Process returned error for non-TCP: %v", err)
	}
	respRaw2 := <-done2
	resp2, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respRaw2)), nil)
	if err != nil {
		t.Fatalf("failed to parse process non-TCP deny response: %v, raw=%q", err, string(respRaw2))
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("we want process non-TCP deny status %d, got %d (status=%q)", http.StatusForbidden, resp2.StatusCode, resp2.Status)
	}

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("failed reading process non-TCP deny body: %v", err)
	}
	if len(bytes.TrimSpace(body2)) == 0 {
		t.Fatal("we want non-empty process non-TCP deny body")
	}
}

func TestHandleSessionCloseAndUnknownFrame(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)

	writeClose, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(writeClose) failed: %v", err)
	}
	bufClose := &bytes.Buffer{}
	if err := writeClose.WriteFrame(bufClose, FrameTypeClose, nil); err != nil {
		t.Fatalf("write close frame failed: %v", err)
	}
	if err := (&Handler{}).handleSession(context.Background(), bufio.NewReader(bytes.NewReader(bufClose.Bytes())), nil, nil, key, nil); err != nil {
		t.Fatalf("handleSession close frame should end cleanly and without any error: %v", err)
	}

	writeUnknown, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(writeUnknown) failed: %v", err)
	}
	bufUnknown := &bytes.Buffer{}
	if err := writeUnknown.WriteFrame(bufUnknown, 0x99, []byte("x")); err != nil {
		t.Fatalf("write unknown frame failed: %v", err)
	}
	err = (&Handler{}).handleSession(context.Background(), bufio.NewReader(bytes.NewReader(bufUnknown.Bytes())), nil, nil, key, nil)
	if err == nil || err.Error() != "unknown frame type" {
		t.Fatalf("we want unknown frame type error, got: %v", err)
	}
}

func TestHandleDataParseError(t *testing.T) {
	// data shoud be at least 1+len(addr)+2 bytes, so atleast 4 bytes, to avoid parse error
	err := (&Handler{}).handleData(context.Background(), []byte{1, 2, 3}, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("we want parse error for short data")
	}
}
