package reflex_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

// var testUserUUID = "00000000-0000-0000-0000-000000000000"
var testSecret, _ = reflex.GetSharedSecret(testUserUUID)

func TestEncodeDecodeClientHandshake(t *testing.T) {
	userID, _ := reflex.UserIDToBytes(testUserUUID)
	var nonce [16]byte
	rand.Read(nonce[:])

	clientHS := &reflex.ClientHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: [32]byte{1, 2, 3},
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}
	clientHS.HMAC = reflex.ComputeClientHMAC(testSecret, clientHS.Version, clientHS.PublicKey, clientHS.UserID, clientHS.Timestamp, clientHS.Nonce)

	encoded := reflex.EncodeClientHandshake(clientHS)
	if len(encoded) != reflex.HandshakeSize {
		t.Fatalf("encoded size mismatch: got %d, want %d", len(encoded), reflex.HandshakeSize)
	}

	decoded, err := reflex.DecodeClientHandshake(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Version != clientHS.Version {
		t.Errorf("version mismatch: got %d, want %d", decoded.Version, clientHS.Version)
	}
	if !bytes.Equal(decoded.PublicKey[:], clientHS.PublicKey[:]) {
		t.Error("public key mismatch")
	}
	if !bytes.Equal(decoded.UserID[:], clientHS.UserID[:]) {
		t.Error("user ID mismatch")
	}
	if decoded.Timestamp != clientHS.Timestamp {
		t.Errorf("timestamp mismatch: got %d, want %d", decoded.Timestamp, clientHS.Timestamp)
	}
	if !bytes.Equal(decoded.Nonce[:], clientHS.Nonce[:]) {
		t.Error("nonce mismatch")
	}
	if !bytes.Equal(decoded.HMAC[:], clientHS.HMAC[:]) {
		t.Error("HMAC mismatch")
	}
}

func TestEncodeDecodeServerHandshake(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])

	serverHS := &reflex.ServerHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: pubKey,
		HMAC:      reflex.ComputeServerHMAC(testSecret, reflex.HandshakeVersion, pubKey),
	}

	encoded := reflex.EncodeServerHandshake(serverHS)
	if len(encoded) != 65 {
		t.Fatalf("encoded size mismatch: got %d, want 65", len(encoded))
	}

	decoded, err := reflex.DecodeServerHandshake(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Version != serverHS.Version {
		t.Errorf("version mismatch: got %d, want %d", decoded.Version, serverHS.Version)
	}
	if !bytes.Equal(decoded.PublicKey[:], serverHS.PublicKey[:]) {
		t.Error("public key mismatch")
	}
	if !bytes.Equal(decoded.HMAC[:], serverHS.HMAC[:]) {
		t.Error("HMAC mismatch")
	}
}

func TestInvalidHandshakeMagic(t *testing.T) {
	data := make([]byte, reflex.HandshakeSize)
	rand.Read(data)
	data[0] = 0xFF // Invalid magic

	_, err := reflex.DecodeClientHandshake(data)
	if err == nil {
		t.Fatal("should reject invalid magic number")
	}
}

func TestInvalidHandshakeVersion(t *testing.T) {
	userID, _ := reflex.UserIDToBytes(testUserUUID)
	clientHS := &reflex.ClientHandshake{
		Version:   99, // Invalid version
		PublicKey: [32]byte{},
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{},
	}
	clientHS.HMAC = reflex.ComputeClientHMAC(testSecret, clientHS.Version, clientHS.PublicKey, clientHS.UserID, clientHS.Timestamp, clientHS.Nonce)

	encoded := reflex.EncodeClientHandshake(clientHS)
	encoded[4] = 99 // Override version

	_, err := reflex.DecodeClientHandshake(encoded)
	if err == nil {
		t.Fatal("should reject unsupported version")
	}
}

func TestInvalidHandshakeSize(t *testing.T) {
	data := make([]byte, reflex.HandshakeSize-1)
	_, err := reflex.DecodeClientHandshake(data)
	if err == nil {
		t.Fatal("should reject too short handshake")
	}
}

func TestVerifyTimestamp(t *testing.T) {
	now := time.Now().Unix()

	if !reflex.VerifyTimestamp(now) {
		t.Error("current timestamp should be valid")
	}

	if !reflex.VerifyTimestamp(now - 60) {
		t.Error("recent timestamp should be valid")
	}

	if reflex.VerifyTimestamp(now - 400) {
		t.Error("old timestamp should be invalid")
	}

	if reflex.VerifyTimestamp(now + 400) {
		t.Error("future timestamp should be invalid")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	priv1, pub1, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}

	priv2, pub2, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}

	if bytes.Equal(pub1[:], pub2[:]) {
		t.Error("public keys should be different")
	}

	if bytes.Equal(priv1[:], priv2[:]) {
		t.Error("private keys should be different")
	}
}

func TestDeriveSharedKey(t *testing.T) {
	priv1, pub1, _ := reflex.GenerateKeyPair()
	priv2, pub2, _ := reflex.GenerateKeyPair()

	shared1 := reflex.DeriveSharedKey(priv1, pub2)
	shared2 := reflex.DeriveSharedKey(priv2, pub1)

	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Error("shared keys should match")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	priv1, _, _ := reflex.GenerateKeyPair()
	_, pub2, _ := reflex.GenerateKeyPair()
	shared := reflex.DeriveSharedKey(priv1, pub2)

	sessionKey1 := reflex.DeriveSessionKey(shared, []byte("reflex-session"))
	sessionKey2 := reflex.DeriveSessionKey(shared, []byte("reflex-session"))

	if !bytes.Equal(sessionKey1, sessionKey2) {
		t.Error("session keys should match")
	}

	if len(sessionKey1) != 32 {
		t.Errorf("session key length mismatch: got %d, want 32", len(sessionKey1))
	}
}

func TestComputeClientHMAC(t *testing.T) {
	userID, _ := reflex.UserIDToBytes(testUserUUID)
	var pubKey [32]byte
	rand.Read(pubKey[:])
	var nonce [16]byte
	rand.Read(nonce[:])

	hmac1 := reflex.ComputeClientHMAC(testSecret, reflex.HandshakeVersion, pubKey, userID, time.Now().Unix(), nonce)
	hmac2 := reflex.ComputeClientHMAC(testSecret, reflex.HandshakeVersion, pubKey, userID, time.Now().Unix(), nonce)

	if !bytes.Equal(hmac1[:], hmac2[:]) {
		t.Error("HMAC should be deterministic")
	}

	if len(hmac1) != 32 {
		t.Errorf("HMAC length mismatch: got %d, want 32", len(hmac1))
	}
}

func TestComputeServerHMAC(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])

	hmac1 := reflex.ComputeServerHMAC(testSecret, reflex.HandshakeVersion, pubKey)
	hmac2 := reflex.ComputeServerHMAC(testSecret, reflex.HandshakeVersion, pubKey)

	if !bytes.Equal(hmac1[:], hmac2[:]) {
		t.Error("HMAC should be deterministic")
	}

	if len(hmac1) != 32 {
		t.Errorf("HMAC length mismatch: got %d, want 32", len(hmac1))
	}
}
