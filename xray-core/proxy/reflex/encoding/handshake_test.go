package encoding

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.PrivateKey == [32]byte{} {
		t.Error("private key is zero")
	}

	if kp.PublicKey == [32]byte{} {
		t.Error("public key is zero")
	}
}

func TestDeriveSharedSecret(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	secret1, err := DeriveSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSharedSecret failed: %v", err)
	}

	secret2, err := DeriveSharedSecret(kp2.PrivateKey, kp1.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSharedSecret failed: %v", err)
	}

	if secret1 != secret2 {
		t.Error("shared secrets do not match")
	}
}

func TestMarshalUnmarshalClientHandshake(t *testing.T) {
	kp, _ := GenerateKeyPair()
	var userID [16]byte
	copy(userID[:], []byte("test-user-id-1"))

	hs := NewClientHandshake(userID, kp.PublicKey)
	data := MarshalClientHandshake(hs)

	hs2, err := UnmarshalClientHandshake(data)
	if err != nil {
		t.Fatalf("UnmarshalClientHandshake failed: %v", err)
	}

	if hs2.PublicKey != hs.PublicKey {
		t.Error("public key mismatch")
	}

	if hs2.UserID != hs.UserID {
		t.Error("user ID mismatch")
	}

	if hs2.Timestamp != hs.Timestamp {
		t.Error("timestamp mismatch")
	}

	if hs2.Nonce != hs.Nonce {
		t.Error("nonce mismatch")
	}
}

func TestMarshalUnmarshalServerHandshake(t *testing.T) {
	kp, _ := GenerateKeyPair()
	hs := NewServerHandshake(kp.PublicKey)
	data := MarshalServerHandshake(hs)

	hs2, err := UnmarshalServerHandshake(data)
	if err != nil {
		t.Fatalf("UnmarshalServerHandshake failed: %v", err)
	}

	if hs2.PublicKey != hs.PublicKey {
		t.Error("public key mismatch")
	}
}
