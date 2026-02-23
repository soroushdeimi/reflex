package inbound

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	hkdf := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	hkdf.Read(sessionKey)
	return sessionKey
}
func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

func generateKeyPair() (privateKey [32]byte, publicKey [32]byte) {
	// Random private key
	if _, err := rand.Read(privateKey[:]); err != nil {
		panic(err)
	}

	// generate public key using x25519
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return
}

func (h *Handler) encryptPolicyGrant(user *protocol.MemoryUser, sessionKey []byte) []byte {
	// policy
	policy := map[string]any{
		"level":  user.Level,
		"expire": time.Now().Add(10 * time.Minute).Unix(),
	}

	plain, err := json.Marshal(policy)
	if err != nil {
		return nil
	}

	// AEAD
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil
	}

	// random nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}

	// encrypt
	ciphertext := aead.Seal(nil, nonce, plain, nil)

	// nonce || ciphertext
	return append(nonce, ciphertext...)
}

// wrapper
func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	return deriveSessionKey(sharedKey, salt)
}
