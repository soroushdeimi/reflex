package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

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

func DeriveSessionKey(sharedKey [32]byte, salt []byte) ([]byte, error) {
	hash := sha256.New
	kdf := hkdf.New(hash, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}
