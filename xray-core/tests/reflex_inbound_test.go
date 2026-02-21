package tests

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
)

func TestAuthenticateUserUsesConstantTimeCompare(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "proxy", "reflex", "inbound", "inbound.go"))
	if err != nil {
		t.Fatalf("read inbound.go: %v", err)
	}
	if !strings.Contains(string(src), "subtle.ConstantTimeCompare") {
		t.Fatal("authenticateUser should use subtle.ConstantTimeCompare to reduce timing leaks")
	}
}

func TestNewHandlerAndNetwork(t *testing.T) {
	hin, err := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: "u1", Policy: "youtube"}},
		Fallback: &reflex.Fallback{
			Dest: 10000,
		},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	h := hin.(interface {
		Network() []xnet.Network
	})

	networks := h.Network()
	if len(networks) != 1 || networks[0] != xnet.Network_TCP {
		t.Fatalf("unexpected network list: %+v", networks)
	}
}

func TestParseDestinationAndPayload(t *testing.T) {
	payload := []byte("hello")
	addr := "example.com"
	data := make([]byte, 0, 1+len(addr)+2+len(payload))
	data = append(data, byte(len(addr)))
	data = append(data, []byte(addr)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 443)
	data = append(data, portBytes...)
	data = append(data, payload...)

	dest, body, err := inbound.ParseDestinationAndPayload(data)
	if err != nil {
		t.Fatalf("parseDestinationAndPayload returned error: %v", err)
	}
	if dest.Address.String() != addr || dest.Port.Value() != 443 {
		t.Fatalf("unexpected destination: %+v", dest)
	}
	if string(body) != "hello" {
		t.Fatalf("unexpected payload: %q", body)
	}

	if _, _, err := inbound.ParseDestinationAndPayload([]byte{1, 'a'}); err == nil {
		t.Fatal("we want error for invalid short payload")
	}
	if _, _, err := inbound.ParseDestinationAndPayload([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("we want error for invalid destination")
	}
}

func TestClientHandshakeParsing(t *testing.T) {
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

	hs, err := inbound.ParseClientHandshakeBytes(raw)
	if err != nil {
		t.Fatalf("parseClientHandshakeBytes returned error: %v", err)
	}
	if hs.Timestamp != 123456789 || string(hs.PolicyReq) != "test" {
		t.Fatalf("unexpected handshake values: %+v", hs)
	}

	tooLarge := make([]byte, 32+16+8+16+2)
	binary.BigEndian.PutUint16(tooLarge[len(tooLarge)-2:], inbound.MaxPolicyReqLen+1)
	if _, err := inbound.ParseClientHandshakeBytes(tooLarge); err == nil {
		t.Fatal("expected too-large policy error")
	}

	if _, err := inbound.ReadClientHandshake(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("we want short read error")
	}
}

func TestKeyDerivationAndTimestamp(t *testing.T) {
	private, pub, err := inbound.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair returned error: %v", err)
	}
	if private == ([32]byte{}) || pub == ([32]byte{}) {
		t.Fatal("generated keys should not be zero")
	}

	shared, err := inbound.DeriveSharedKey(private, pub)
	if err != nil {
		t.Fatalf("deriveSharedKey returned error: %v", err)
	}
	sessionKeyA := inbound.DeriveSessionKey(shared, []byte("salt"))
	sessionKeyB := inbound.DeriveSessionKey(shared, []byte("salt"))
	if len(sessionKeyA) != 32 || !bytes.Equal(sessionKeyA, sessionKeyB) {
		t.Fatal("derived session key should be deterministic (and equal) with same inputs")
	}

	now := time.Now().Unix()
	if err := inbound.ValidateTimestamp(now); err != nil {
		t.Fatalf("timestamp should be valid: %v", err)
	}
	if err := inbound.ValidateTimestamp(now + inbound.AllowedClockSkewSec + 1); err == nil {
		t.Fatal("we want future timestamp error")
	}
	if err := inbound.ValidateTimestamp(now - inbound.AllowedClockSkewSec - 1); err == nil {
		t.Fatal("we want old timestamp error")
	}
}

func TestPolicyAndHTTPResponseHelpers(t *testing.T) {
	sessionKey := []byte("0123456789abcdef")
	user := &protocol.MemoryUser{Email: "user@example.com"}
	enc := inbound.EncryptPolicyGrant(user, sessionKey)
	dec := inbound.EncryptPolicyGrant(&protocol.MemoryUser{Email: string(enc)}, sessionKey)
	if string(dec) != user.Email {
		t.Fatal("policy grant xor should be reversible")
	}

	var pub [32]byte
	copy(pub[:], []byte("0123456789abcdefghijklmnopqrstuv"))
	resp := inbound.FormatHTTPResponse(inbound.ServerHandshake{PublicKey: pub, PolicyGrant: []byte("grant")})
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

func TestHandleFallbackDenyResponse(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := client.Read(buf)
		done <- buf[:n]
	}()

	if err := inbound.HandleFallbackDeny(server); err != nil {
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
	if len(bytes.TrimSpace(body)) == 0 {
		t.Fatal("we want non-empty fallback deny body")
	}
}
