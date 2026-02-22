package reflex

import (
	"bufio"
	"bytes"
	"testing"
)

func TestHandshake_DeriveSecretAndSessionKey(t *testing.T) {
	cPriv, cPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(client) err: %v", err)
	}
	sPriv, sPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(server) err: %v", err)
	}

	sec1, err := DeriveSharedSecret(cPriv, sPub)
	if err != nil {
		t.Fatalf("DeriveSharedSecret(1) err: %v", err)
	}
	sec2, err := DeriveSharedSecret(sPriv, cPub)
	if err != nil {
		t.Fatalf("DeriveSharedSecret(2) err: %v", err)
	}
	if sec1 != sec2 {
		t.Fatalf("shared secrets must match")
	}

	salt := []byte("0123456789abcdef")
	key1 := DeriveSessionKey(sec1, salt)
	key2 := DeriveSessionKey(sec2, salt)
	if key1 != key2 {
		t.Fatalf("session keys must match")
	}
	if key1 == ([32]byte{}) {
		t.Fatalf("session key must not be zero")
	}
}

func TestServerHandshake_EncodeDecode_RoundTrip(t *testing.T) {
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	hs := ServerHandshake{
		ServerPubKey: pub,
		PolicyGrant:  []byte("grant-bytes"),
	}

	b := EncodeServerHandshake(hs)
	got, err := DecodeServerHandshake(b)
	if err != nil {
		t.Fatalf("DecodeServerHandshake err: %v", err)
	}

	if got.ServerPubKey != hs.ServerPubKey {
		t.Fatalf("server pubkey mismatch")
	}
	if !bytes.Equal(got.PolicyGrant, hs.PolicyGrant) {
		t.Fatalf("policy grant mismatch")
	}
}

func TestServerHandshakeHTTP_ReadWrite(t *testing.T) {
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(0xA0 + i)
	}
	hs := ServerHandshake{
		ServerPubKey: pub,
		PolicyGrant:  []byte("http-grant"),
	}

	resp := EncodeServerHandshakeHTTP(hs)
	br := bufio.NewReader(bytes.NewReader(resp))

	got, err := ReadServerHandshakeHTTP(br)
	if err != nil {
		t.Fatalf("ReadServerHandshakeHTTP err: %v", err)
	}
	if got.ServerPubKey != hs.ServerPubKey {
		t.Fatalf("server pubkey mismatch")
	}
	if !bytes.Equal(got.PolicyGrant, hs.PolicyGrant) {
		t.Fatalf("policy grant mismatch")
	}
}

func TestReadClientHandshakeHTTP_RoundTrip(t *testing.T) {
	userID, err := ParseUUID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	_, clientPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs, err := NewClientHandshake(clientPub, userID, []byte("policy-req"))
	if err != nil {
		t.Fatal(err)
	}

	req := EncodeClientHandshakeHTTP(hs, "example.com", "")
	br := bufio.NewReader(bytes.NewReader(req))

	got, err := ReadClientHandshakeHTTP(br)
	if err != nil {
		t.Fatalf("ReadClientHandshakeHTTP err: %v", err)
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
