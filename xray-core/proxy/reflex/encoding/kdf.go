package encoding

import (
	"crypto/sha256"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveSessionKey derives a session key from a shared secret using HKDF
// The shared secret is the result of X25519 key agreement
func DeriveSessionKey(sharedSecret [32]byte, salt []byte, info []byte) ([32]byte, error) {
	var key [32]byte

	// Use HKDF with SHA-256
	h := hkdf.New(sha256.New, sharedSecret[:], salt, info)
	if _, err := io.ReadFull(h, key[:]); err != nil {
		return [32]byte{}, err
	}

	return key, nil
}

// DeriveKeys derives encryption and MAC keys from a shared secret
func DeriveKeys(sharedSecret [32]byte, salt []byte) ([32]byte, [32]byte, error) {
	// Derive first key for encryption
	encKey, err := DeriveSessionKey(sharedSecret, salt, []byte("reflex-enc"))
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	// Derive second key for MAC
	macKey, err := DeriveSessionKey(sharedSecret, salt, []byte("reflex-mac"))
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	return encKey, macKey, nil
}

// HKDF is a helper function that implements RFC 5869 HKDF
func HKDF(hash func() hash.Hash, ikm, salt, info []byte, length int) ([]byte, error) {
	h := hkdf.New(hash, ikm, salt, info)
	result := make([]byte, length)
	_, err := io.ReadFull(h, result)
	return result, err
}
