package reflex

import (
	"bytes"
	"testing"
)

func TestCrypto(t *testing.T) {
	// 1. Test X25519 Key Exchange
	priv1, pub1, _ := GenerateKeyPair()
	priv2, pub2, _ := GenerateKeyPair()

	shared1, _ := DeriveSharedKey(priv1, pub2)
	shared2, _ := DeriveSharedKey(priv2, pub1)

	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Fatal("shared keys do not match")
	}

	// 2. Test HKDF Session Key Derivation
	salt := []byte("test-salt")
	info := "test-info"
	key1, err := DeriveSessionKey(shared1, salt, info)
	if err != nil || len(key1) != 32 {
		t.Fatal("failed to derive session key")
	}

	key2, _ := DeriveSessionKey(shared1, salt, info)
	if !bytes.Equal(key1, key2) {
		t.Fatal("hkdf results not deterministic")
	}

	// 3. Test AES-GCM Encrypt/Decrypt
	aesKey := key1
	plaintext := []byte("hello reflex protocol")

	ciphertext, err := EncryptAESGCM(aesKey, plaintext)
	if err != nil {
		t.Fatal("encryption failed:", err)
	}

	decrypted, err := DecryptAESGCM(aesKey, ciphertext)
	if err != nil {
		t.Fatal("decryption failed:", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted data mismatch")
	}

	// 4. Test Pre-Shared Key from UUID
	uuid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	psk1 := DerivePreSharedKey(uuid)
	psk2 := DerivePreSharedKey(uuid)

	if len(psk1) != 32 || !bytes.Equal(psk1, psk2) {
		t.Fatal("psk derivation error")
	}

	// 5. Test Bidirectional Session Keys
	cNonce, _ := GenerateNonce()
	sNonce, _ := GenerateNonce()
	sKeys, err := DeriveSessionKeys(shared1, cNonce, sNonce)
	if err != nil {
		t.Fatal("derive session keys failed")
	}

	if bytes.Equal(sKeys.ClientToServer, sKeys.ServerToClient) {
		t.Fatal("directional keys should be different")
	}
}

func TestAESGCMErrors(t *testing.T) {
	key := make([]byte, 32)

	// Test too short ciphertext
	_, err := DecryptAESGCM(key, []byte("short"))
	if err == nil {
		t.Error("should fail on short ciphertext")
	}

	// Test wrong key
	ciphertext, _ := EncryptAESGCM(key, []byte("data"))
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	_, err = DecryptAESGCM(wrongKey, ciphertext)
	if err == nil {
		t.Error("should fail with wrong key")
	}
}
