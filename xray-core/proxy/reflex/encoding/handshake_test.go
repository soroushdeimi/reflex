package encoding

import (
	"bytes"
	"testing"
	"time"
)

// TestGenerateKeyPair tests ephemeral key pair generation
func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Check key sizes
	if len(priv) != 32 {
		t.Fatalf("private key should be 32 bytes, got %d", len(priv))
	}
	if len(pub) != 32 {
		t.Fatalf("public key should be 32 bytes, got %d", len(pub))
	}

	// Keys should be different
	if bytes.Equal(priv[:], pub[:]) {
		t.Fatal("private key and public key should be different")
	}

	// Keys should be non-zero
	var zero [32]byte
	if bytes.Equal(priv[:], zero[:]) {
		t.Fatal("private key should not be all zeros")
	}
	if bytes.Equal(pub[:], zero[:]) {
		t.Fatal("public key should not be all zeros")
	}
}

// TestGenerateKeyPairDeterminism verifies key pairs are unique
func TestGenerateKeyPairDeterminism(t *testing.T) {
	priv1, pub1, _ := GenerateKeyPair()
	priv2, pub2, _ := GenerateKeyPair()

	// Keys should be different each time
	if bytes.Equal(priv1[:], priv2[:]) {
		t.Fatal("generated private keys should be different")
	}
	if bytes.Equal(pub1[:], pub2[:]) {
		t.Fatal("generated public keys should be different")
	}
}

// TestDeriveSharedKey tests ECDH shared secret derivation
func TestDeriveSharedKey(t *testing.T) {
	// Generate two key pairs
	alicePriv, alicePub, _ := GenerateKeyPair()
	bobPriv, bobPub, _ := GenerateKeyPair()

	// Derive shared secrets from both sides
	aliceShared := DeriveSharedKey(alicePriv, bobPub)
	bobShared := DeriveSharedKey(bobPriv, alicePub)

	// Shared secrets should match (ECDH property)
	if !bytes.Equal(aliceShared[:], bobShared[:]) {
		t.Fatal("shared secrets should match from both sides (ECDH)")
	}

	// Shared secret should be 32 bytes
	if len(aliceShared) != 32 {
		t.Fatalf("shared secret should be 32 bytes, got %d", len(aliceShared))
	}

	// Should not be zero
	var zero [32]byte
	if bytes.Equal(aliceShared[:], zero[:]) {
		t.Fatal("shared secret should not be all zeros")
	}
}

// TestDeriveSharedKeySymmetry verifies ECDH is symmetric
func TestDeriveSharedKeySymmetry(t *testing.T) {
	alice1Priv, alice1Pub, _ := GenerateKeyPair()
	bob1Priv, bob1Pub, _ := GenerateKeyPair()

	alice2Priv, alice2Pub, _ := GenerateKeyPair()
	bob2Priv, bob2Pub, _ := GenerateKeyPair()

	// Alice with Bob 1
	aliceShared1 := DeriveSharedKey(alice1Priv, bob1Pub)
	bobShared1 := DeriveSharedKey(bob1Priv, alice1Pub)

	// Alice with Bob 2
	aliceShared2 := DeriveSharedKey(alice2Priv, bob2Pub)
	bobShared2 := DeriveSharedKey(bob2Priv, alice2Pub)

	// Verify symmetry
	if !bytes.Equal(aliceShared1[:], bobShared1[:]) {
		t.Fatal("ECDH not symmetric: alice1 != bob1")
	}
	if !bytes.Equal(aliceShared2[:], bobShared2[:]) {
		t.Fatal("ECDH not symmetric: alice2 != bob2")
	}

	// Different pairs should have different shared secrets
	if bytes.Equal(aliceShared1[:], aliceShared2[:]) {
		t.Fatal("different key pairs should produce different shared secrets")
	}
}

// TestDeriveSessionKey tests HKDF key derivation
func TestDeriveSessionKey(t *testing.T) {
	// Create a test shared key
	var sharedKey [32]byte
	for i := 0; i < 32; i++ {
		sharedKey[i] = byte(i)
	}

	// Derive session key
	salt := []byte("test-salt")
	sessionKey, err := DeriveSessionKey(sharedKey, salt)
	if err != nil {
		t.Fatalf("DeriveSessionKey failed: %v", err)
	}

	// Should produce 32-byte key for ChaCha20-Poly1305
	if len(sessionKey) != 32 {
		t.Fatalf("session key should be 32 bytes, got %d", len(sessionKey))
	}

	// Should not be zero
	var zero [32]byte
	if bytes.Equal(sessionKey, zero[:]) {
		t.Fatal("session key should not be all zeros")
	}
}

// TestDeriveSessionKeyDeterminism verifies same input produces same output
func TestDeriveSessionKeyDeterminism(t *testing.T) {
	var sharedKey [32]byte
	for i := 0; i < 32; i++ {
		sharedKey[i] = byte(i)
	}

	salt := []byte("test-salt")

	key1, _ := DeriveSessionKey(sharedKey, salt)
	key2, _ := DeriveSessionKey(sharedKey, salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same input should produce same session key")
	}
}

// TestDeriveSessionKeyDifferentSalts verifies salt affects output
func TestDeriveSessionKeyDifferentSalts(t *testing.T) {
	var sharedKey [32]byte
	for i := 0; i < 32; i++ {
		sharedKey[i] = byte(i)
	}

	salt1 := []byte("salt-1")
	salt2 := []byte("salt-2")

	key1, _ := DeriveSessionKey(sharedKey, salt1)
	key2, _ := DeriveSessionKey(sharedKey, salt2)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different session keys")
	}
}

// TestValidateTimestamp tests timestamp validation logic
func TestValidateTimestamp(t *testing.T) {
	now := time.Now().Unix()

	// Current timestamp should be valid
	if !ValidateTimestamp(now) {
		t.Fatal("current timestamp should be valid")
	}

	// Recent timestamp should be valid
	recentTimestamp := now - 30 // 30 seconds ago
	if !ValidateTimestamp(recentTimestamp) {
		t.Fatal("recent timestamp (30s ago) should be valid")
	}

	// Timestamp within tolerance should be valid
	maxOld := now - 120 // exactly at tolerance boundary
	if !ValidateTimestamp(maxOld) {
		t.Fatal("timestamp at tolerance boundary should be valid")
	}

	// Timestamp beyond tolerance should be invalid
	tooOld := now - 121 // 1 second beyond tolerance
	if ValidateTimestamp(tooOld) {
		t.Fatal("timestamp beyond tolerance should be invalid")
	}

	// Future timestamp slightly in future should be valid (clock skew tolerance)
	slightlyFuture := now + 30
	if !ValidateTimestamp(slightlyFuture) {
		t.Fatal("slightly future timestamp should be valid (clock skew)")
	}

	// Far future timestamp should be invalid
	farFuture := now + 200
	if ValidateTimestamp(farFuture) {
		t.Fatal("far future timestamp should be invalid")
	}
}

// TestEncodeDecodeClientHandshake tests handshake encoding/decoding
func TestEncodeDecodeClientHandshake(t *testing.T) {
	// Create a test handshake
	_, pub, _ := GenerateKeyPair()
	var userID [16]byte
	copy(userID[:], []byte("test-user-id---"))

	hs := ClientHandshake{
		PublicKey: pub,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	// Encode
	encoded := EncodeClientHandshake(&hs)

	// Decode
	decoded, err := DecodeClientHandshake(encoded)
	if err != nil {
		t.Fatalf("DecodeClientHandshake failed: %v", err)
	}

	// Verify all fields match
	if decoded.PublicKey != hs.PublicKey {
		t.Fatal("public key mismatch")
	}
	if decoded.UserID != hs.UserID {
		t.Fatal("user ID mismatch")
	}
	if decoded.Timestamp != hs.Timestamp {
		t.Fatal("timestamp mismatch")
	}
	if decoded.Nonce != hs.Nonce {
		t.Fatal("nonce mismatch")
	}
}

// TestEncodeDecodeServerHandshake tests server handshake encoding/decoding
func TestEncodeDecodeServerHandshake(t *testing.T) {
	_, pub, _ := GenerateKeyPair()

	hs := ServerHandshake{
		PublicKey: pub,
		Timestamp: time.Now().Unix(),
	}

	// Encode
	encoded := EncodeServerHandshake(&hs)

	// Decode
	decoded, err := DecodeServerHandshake(encoded)
	if err != nil {
		t.Fatalf("DecodeServerHandshake failed: %v", err)
	}

	// Verify fields match
	if decoded.PublicKey != hs.PublicKey {
		t.Fatal("public key mismatch")
	}
	if decoded.Timestamp != hs.Timestamp {
		t.Fatal("timestamp mismatch")
	}
}

// TestClientHandshakeSize verifies handshake has correct size
func TestClientHandshakeSize(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	var userID [16]byte

	hs := ClientHandshake{
		PublicKey: pub,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{},
	}

	encoded := EncodeClientHandshake(&hs)

	// Client handshake should be exactly 76 bytes
	// Magic (4) + PublicKey (32) + UserID (16) + Timestamp (8) + Nonce (16) = 76
	if len(encoded) != 76 {
		t.Fatalf("client handshake should be 76 bytes, got %d", len(encoded))
	}
}

// TestServerHandshakeSize verifies server handshake has correct size
func TestServerHandshakeSize(t *testing.T) {
	_, pub, _ := GenerateKeyPair()

	hs := ServerHandshake{
		PublicKey: pub,
		Timestamp: time.Now().Unix(),
	}

	encoded := EncodeServerHandshake(&hs)

	// Server handshake should be exactly 40 bytes
	// PublicKey (32) + Timestamp (8) = 40
	if len(encoded) != 40 {
		t.Fatalf("server handshake should be 40 bytes, got %d", len(encoded))
	}
}

// TestMagicNumberDetection verifies magic number is correctly set
func TestMagicNumberDetection(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	var userID [16]byte

	hs := ClientHandshake{
		PublicKey: pub,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{},
	}

	encoded := EncodeClientHandshake(&hs)

	// First 4 bytes should be magic number (0x5246584C = "REFX")
	expectedMagic := [4]byte{0x52, 0x46, 0x58, 0x4C}
	if !bytes.Equal(encoded[:4], expectedMagic[:]) {
		t.Fatalf("magic number mismatch: expected %v, got %v", expectedMagic, encoded[:4])
	}
}

// TestHandshakeWithInvalidData verifies error handling on invalid data
func TestHandshakeWithInvalidData(t *testing.T) {
	// Try to decode invalid data
	invalidData := []byte("invalid handshake data")
	_, err := DecodeClientHandshake(invalidData)
	if err == nil {
		t.Fatal("should return error for invalid handshake data")
	}

	// Try to decode data that's too short
	shortData := []byte{0x52, 0x46, 0x58, 0x4C} // just magic number
	_, err = DecodeClientHandshake(shortData)
	if err == nil {
		t.Fatal("should return error for truncated handshake")
	}
}

// TestKeyExchangeWithDifferentPartners verifies ECDH with multiple partners
func TestKeyExchangeWithDifferentPartners(t *testing.T) {
	// Create multiple parties
	alice1, _, _ := GenerateKeyPair()
	alice2, alicePub2, _ := GenerateKeyPair()
	_, bobPub, _ := GenerateKeyPair()

	// Alice1 and Bob
	sharedSecret1 := DeriveSharedKey(alice1, bobPub)

	// Alice2 and Bob (different alice)
	sharedSecret2 := DeriveSharedKey(alice2, bobPub)

	// Alice1 with different partner keys
	sharedSecret3 := DeriveSharedKey(alice1, alicePub2)

	// All should be different
	if bytes.Equal(sharedSecret1[:], sharedSecret2[:]) {
		t.Fatal("different alice keys should produce different shared secrets")
	}
	if bytes.Equal(sharedSecret1[:], sharedSecret3[:]) {
		t.Fatal("different bob keys should produce different shared secrets")
	}
	if bytes.Equal(sharedSecret2[:], sharedSecret3[:]) {
		t.Fatal("all combinations should be unique")
	}
}
