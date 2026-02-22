package reflex

import (
	"bufio"
	"bytes"
	"testing"
)

func TestReadClientHandshakeHTTPWithRaw_RoundTrip(t *testing.T) {
	userID, err := ParseUUID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}

	_, clientPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs, err := NewClientHandshake(clientPub, userID, []byte("http2-api"))
	if err != nil {
		t.Fatal(err)
	}

	req := EncodeClientHandshakeHTTP(hs, "example.com", "")

	br := bufio.NewReader(bytes.NewReader(req))
	got, raw, err := ReadClientHandshakeHTTPWithRaw(br)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(raw, req) {
		t.Fatalf("raw mismatch: got %d bytes want %d bytes", len(raw), len(req))
	}

	if got.UserID != hs.UserID {
		t.Fatalf("userID mismatch")
	}
	if got.ClientPubKey != hs.ClientPubKey {
		t.Fatalf("client pubkey mismatch")
	}
	if !bytes.Equal(got.PolicyReq, hs.PolicyReq) {
		t.Fatalf("policy req mismatch")
	}
}

func TestReadClientHandshakeHTTPWithRaw_InvalidContentLength(t *testing.T) {
	req := []byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\nxxxx")
	br := bufio.NewReader(bytes.NewReader(req))

	_, _, err := ReadClientHandshakeHTTPWithRaw(br)
	if err == nil {
		t.Fatalf("expected error for invalid content-length")
	}
}
