package reflex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DeriveSharedKey derives shared key using X25519
func DeriveSharedKey(privateKey, peerPublicKey [32]byte) ([32]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared, nil
}

// DeriveSessionKey derives session key from shared key using HKDF
func DeriveSessionKey(sharedKey [32]byte, salt []byte, info string) ([]byte, error) {
	h := hkdf.New(sha256.New, sharedKey[:], salt, []byte(info))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(h, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

// DerivePreSharedKey derives pre-shared key from UUID
func DerivePreSharedKey(userID [16]byte) []byte {
	hash := sha256.Sum256(userID[:])
	return hash[:]
}

// EncryptAESGCM encrypts data using AES-GCM
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts data using AES-GCM
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, newError("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SessionKeys holds encryption keys for a session
type SessionKeys struct {
	ClientToServer []byte
	ServerToClient []byte
}

// DeriveSessionKeys derives both direction keys
func DeriveSessionKeys(sharedKey [32]byte, clientNonce, serverNonce [16]byte) (*SessionKeys, error) {
	salt := make([]byte, 32)
	copy(salt[0:16], clientNonce[:])
	copy(salt[16:32], serverNonce[:])

	c2s, err := DeriveSessionKey(sharedKey, salt, "reflex-c2s")
	if err != nil {
		return nil, err
	}

	s2c, err := DeriveSessionKey(sharedKey, salt, "reflex-s2c")
	if err != nil {
		return nil, err
	}

	return &SessionKeys{
		ClientToServer: c2s,
		ServerToClient: s2c,
	}, nil
}
