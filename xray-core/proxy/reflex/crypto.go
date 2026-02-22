package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func GenerateKeyPair() ([32]byte, [32]byte, error) {
	var privateKey [32]byte
	var publicKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return privateKey, publicKey, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

func DeriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

// DeriveSessionKey uses HKDF-SHA256 to generate a 32-byte session key.
// The salt consists of the client's nonce and UserID to ensure uniqueness.
func DeriveSessionKey(sharedKey [32]byte, salt []byte) ([]byte, error) {
	hash := sha256.New
	kdf := hkdf.New(hash, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

func NewCipher(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// Generates two independent 32-byte keys for bidirectional AEAD encryption to ensure traffic isolation.
func DeriveDirectionalKeys(sessionKey []byte) (c2sKey []byte, s2cKey []byte, err error) {
	c2sKey = make([]byte, 32)
	s2cKey = make([]byte, 32)

	// Client -> Server
	kdfC2S := hkdf.New(sha256.New, sessionKey, nil, []byte("reflex-c2s"))
	if _, err := io.ReadFull(kdfC2S, c2sKey); err != nil {
		return nil, nil, err
	}

	// Server -> Client
	kdfS2C := hkdf.New(sha256.New, sessionKey, nil, []byte("reflex-s2c"))
	if _, err := io.ReadFull(kdfS2C, s2cKey); err != nil {
		return nil, nil, err
	}

	return c2sKey, s2cKey, nil
}
