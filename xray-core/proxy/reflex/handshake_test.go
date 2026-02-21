package reflex

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
)

func TestGenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	var zero [32]byte
	if privKey == zero {
		t.Fatal("private key is all zeros")
	}
	if pubKey == zero {
		t.Fatal("public key is all zeros")
	}
	if privKey == pubKey {
		t.Fatal("private and public keys should differ")
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	_, pub1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if pub1 == pub2 {
		t.Fatal("two keypairs generated identical public keys")
	}
}

func TestDeriveSharedSecret(t *testing.T) {
	priv1, pub1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Both sides should derive the same shared secret
	secret1, err := DeriveSharedSecret(priv1, pub2)
	if err != nil {
		t.Fatalf("DeriveSharedSecret(1->2) failed: %v", err)
	}
	secret2, err := DeriveSharedSecret(priv2, pub1)
	if err != nil {
		t.Fatalf("DeriveSharedSecret(2->1) failed: %v", err)
	}

	if secret1 != secret2 {
		t.Fatal("shared secrets do not match")
	}

	var zero [32]byte
	if secret1 == zero {
		t.Fatal("shared secret is all zeros")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	priv1, pub1, _ := GenerateKeyPair()
	priv2, pub2, _ := GenerateKeyPair()

	secret1, _ := DeriveSharedSecret(priv1, pub2)
	secret2, _ := DeriveSharedSecret(priv2, pub1)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	key1, err := DeriveSessionKey(secret1, nonce)
	if err != nil {
		t.Fatalf("DeriveSessionKey failed: %v", err)
	}
	key2, err := DeriveSessionKey(secret2, nonce)
	if err != nil {
		t.Fatalf("DeriveSessionKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("session keys derived from same shared secret and nonce differ")
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte session key, got %d", len(key1))
	}
}

func TestDeriveSessionKeyDifferentNonce(t *testing.T) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}

	key1, _ := DeriveSessionKey(secret, []byte("nonce-a"))
	key2, _ := DeriveSessionKey(secret, []byte("nonce-b"))

	if bytes.Equal(key1, key2) {
		t.Fatal("different nonces should produce different session keys")
	}
}

func TestMarshalUnmarshalClientHandshake(t *testing.T) {
	_, pubKey, _ := GenerateKeyPair()
	uid, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}

	original := &ClientHandshake{
		PublicKey: pubKey,
		UserID:    uid,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	data := MarshalClientHandshake(original)
	if len(data) != HandshakeHeaderSize {
		t.Fatalf("expected %d bytes, got %d", HandshakeHeaderSize, len(data))
	}

	parsed, err := UnmarshalClientHandshake(data)
	if err != nil {
		t.Fatalf("UnmarshalClientHandshake failed: %v", err)
	}

	if parsed.PublicKey != original.PublicKey {
		t.Fatal("public keys do not match")
	}
	if parsed.UserID != original.UserID {
		t.Fatal("user IDs do not match")
	}
	if parsed.Timestamp != original.Timestamp {
		t.Fatal("timestamps do not match")
	}
	if parsed.Nonce != original.Nonce {
		t.Fatal("nonces do not match")
	}
}

func TestUnmarshalClientHandshakeTooShort(t *testing.T) {
	_, err := UnmarshalClientHandshake([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestUnmarshalClientHandshakeInvalidMagic(t *testing.T) {
	data := make([]byte, HandshakeHeaderSize)
	// Write wrong magic
	data[0] = 0xFF
	data[1] = 0xFF
	data[2] = 0xFF
	data[3] = 0xFF

	_, err := UnmarshalClientHandshake(data)
	if err == nil {
		t.Fatal("expected error for invalid magic number")
	}
}

func TestMarshalUnmarshalServerHandshake(t *testing.T) {
	_, pubKey, _ := GenerateKeyPair()
	var policyGrant [32]byte
	if _, err := rand.Read(policyGrant[:]); err != nil {
		t.Fatal(err)
	}

	original := &ServerHandshake{
		PublicKey:   pubKey,
		PolicyGrant: policyGrant,
	}

	data := MarshalServerHandshake(original)
	if len(data) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(data))
	}

	parsed, err := UnmarshalServerHandshake(data)
	if err != nil {
		t.Fatalf("UnmarshalServerHandshake failed: %v", err)
	}

	if parsed.PublicKey != original.PublicKey {
		t.Fatal("public keys do not match")
	}
	if parsed.PolicyGrant != original.PolicyGrant {
		t.Fatal("policy grants do not match")
	}
}

func TestUnmarshalServerHandshakeTooShort(t *testing.T) {
	_, err := UnmarshalServerHandshake(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestValidateTimestamp(t *testing.T) {
	if !ValidateTimestamp(time.Now().Unix()) {
		t.Fatal("current timestamp should be valid")
	}

	if !ValidateTimestamp(time.Now().Unix() - 60) {
		t.Fatal("timestamp 60s ago should be valid (within 120s drift)")
	}

	if !ValidateTimestamp(time.Now().Unix() + 60) {
		t.Fatal("timestamp 60s in the future should be valid")
	}
}

func TestValidateTimestampExpired(t *testing.T) {
	if ValidateTimestamp(time.Now().Unix() - 300) {
		t.Fatal("timestamp 300s ago should be invalid")
	}

	if ValidateTimestamp(time.Now().Unix() + 300) {
		t.Fatal("timestamp 300s in the future should be invalid")
	}
}

func TestValidateTimestampBoundary(t *testing.T) {
	if !ValidateTimestamp(time.Now().Unix() - MaxTimestampDrift) {
		t.Fatal("timestamp at exact max drift should be valid")
	}

	if ValidateTimestamp(time.Now().Unix() - MaxTimestampDrift - 10) {
		t.Fatal("timestamp beyond max drift should be invalid")
	}
}

func TestAuthenticateUser(t *testing.T) {
	uid, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	clients := []*ClientEntry{
		{ID: "b831381d-6324-4d53-ad4f-8cda48b30811", Policy: "youtube"},
		{ID: "a1111111-2222-3333-4444-555555555555", Policy: "zoom"},
	}

	entry := AuthenticateUser(uid, clients)
	if entry == nil {
		t.Fatal("expected to find matching client")
	}
	if entry.Policy != "youtube" {
		t.Fatalf("expected policy 'youtube', got '%s'", entry.Policy)
	}
}

func TestAuthenticateUserNotFound(t *testing.T) {
	uid, _ := uuid.ParseString("00000000-0000-0000-0000-000000000000")
	clients := []*ClientEntry{
		{ID: "b831381d-6324-4d53-ad4f-8cda48b30811", Policy: "youtube"},
	}

	entry := AuthenticateUser(uid, clients)
	if entry != nil {
		t.Fatal("expected nil for unknown UUID")
	}
}

func TestAuthenticateUserEmptyList(t *testing.T) {
	uid, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	entry := AuthenticateUser(uid, nil)
	if entry != nil {
		t.Fatal("expected nil for empty client list")
	}
}

func TestAuthenticateUserInvalidClientID(t *testing.T) {
	uid, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	clients := []*ClientEntry{
		{ID: "not-a-valid-uuid", Policy: "youtube"},
	}

	entry := AuthenticateUser(uid, clients)
	if entry != nil {
		t.Fatal("expected nil when client has invalid UUID")
	}
}

func TestHandshakeRoundTripConstantsConsistency(t *testing.T) {
	// Verify HandshakeHeaderSize matches the actual layout
	// magic(4) + pubkey(32) + uuid(16) + timestamp(8) + nonce(16) = 76
	expected := 4 + 32 + 16 + 8 + 16
	if HandshakeHeaderSize != expected {
		t.Fatalf("HandshakeHeaderSize is %d, expected %d", HandshakeHeaderSize, expected)
	}
}

func TestReflexMagicValue(t *testing.T) {
	// "RFXL" in hex: R=0x52, F=0x46, X=0x58, L=0x4C
	expected := uint32(0x5246584C)
	if ReflexMagic != expected {
		t.Fatalf("ReflexMagic is 0x%08X, expected 0x%08X", ReflexMagic, expected)
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = GenerateKeyPair()
	}
}

func BenchmarkDeriveSharedSecret(b *testing.B) {
	priv1, _, _ := GenerateKeyPair()
	_, pub2, _ := GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeriveSharedSecret(priv1, pub2)
	}
}

func BenchmarkDeriveSessionKey(b *testing.B) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeriveSessionKey(secret, nonce)
	}
}
