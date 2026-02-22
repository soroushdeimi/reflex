package encoding

import (
	"testing"
)

func TestDeriveSessionKey(t *testing.T) {
	var sharedSecret [32]byte
	copy(sharedSecret[:], []byte("test-shared-secret-123456789012"))

	salt := []byte("test-salt")
	info := []byte("reflex")

	key, err := DeriveSessionKey(sharedSecret, salt, info)
	if err != nil {
		t.Fatalf("DeriveSessionKey failed: %v", err)
	}

	if key == [32]byte{} {
		t.Error("derived key is zero")
	}
}

func TestDeriveSessionKeyDeterministic(t *testing.T) {
	var sharedSecret [32]byte
	copy(sharedSecret[:], []byte("test-shared-secret-123456789012"))

	salt := []byte("test-salt")
	info := []byte("reflex")

	key1, _ := DeriveSessionKey(sharedSecret, salt, info)
	key2, _ := DeriveSessionKey(sharedSecret, salt, info)

	if key1 != key2 {
		t.Error("derived keys are not deterministic")
	}
}

func TestDeriveKeys(t *testing.T) {
	var sharedSecret [32]byte
	copy(sharedSecret[:], []byte("test-shared-secret-123456789012"))

	salt := []byte("test-salt")

	encKey, macKey, err := DeriveKeys(sharedSecret, salt)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	if encKey == [32]byte{} {
		t.Error("encryption key is zero")
	}

	if macKey == [32]byte{} {
		t.Error("MAC key is zero")
	}

	if encKey == macKey {
		t.Error("encryption key and MAC key are the same")
	}
}
