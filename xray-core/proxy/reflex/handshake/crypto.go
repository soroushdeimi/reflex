package handshake

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/hkdf"
)

const (
	SharedKeySize  = 32
	SessionKeySize = 32

	// HKDF info label (per Step2 spec).
	ReflexSessionInfo = "reflex-session"
)

// KeyPair holds an ephemeral X25519 keypair.
type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  [PublicKeySize]byte
}

// GenerateX25519KeyPair creates an ephemeral X25519 key pair.
func GenerateX25519KeyPair() (KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, errors.New("reflex handshake: generate x25519 key").Base(err)
	}

	var pub [PublicKeySize]byte
	copy(pub[:], priv.PublicKey().Bytes())

	return KeyPair{
		Private: priv,
		Public:  pub,
	}, nil
}

// ParseX25519PublicKey parses a 32-byte X25519 public key.
func ParseX25519PublicKey(pub [PublicKeySize]byte) (*ecdh.PublicKey, error) {
	pk, err := ecdh.X25519().NewPublicKey(pub[:])
	if err != nil {
		return nil, errors.New("reflex handshake: invalid x25519 public key").Base(err)
	}
	return pk, nil
}

// ComputeSharedKey performs X25519 ECDH and returns a 32-byte shared key.
func ComputeSharedKey(priv *ecdh.PrivateKey, peerPub [PublicKeySize]byte) ([SharedKeySize]byte, error) {
	if priv == nil {
		return [SharedKeySize]byte{}, errors.New("reflex handshake: nil private key")
	}
	peer, err := ParseX25519PublicKey(peerPub)
	if err != nil {
		return [SharedKeySize]byte{}, err
	}

	sharedBytes, err := priv.ECDH(peer)
	if err != nil {
		return [SharedKeySize]byte{}, errors.New("reflex handshake: ecdh failed").Base(err)
	}
	if len(sharedBytes) != SharedKeySize {
		return [SharedKeySize]byte{}, errors.New("reflex handshake: unexpected shared key length")
	}

	var shared [SharedKeySize]byte
	copy(shared[:], sharedBytes)
	return shared, nil
}

// DeriveHKDF32 derives 32 bytes using HKDF-SHA256.
func DeriveHKDF32(ikm []byte, salt []byte, info []byte) ([SessionKeySize]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	var out [SessionKeySize]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return [SessionKeySize]byte{}, errors.New("reflex handshake: hkdf read").Base(err)
	}
	return out, nil
}

// DeriveSessionKey derives the session key from shared key + salt (recommended: nonce).
func DeriveSessionKey(shared [SharedKeySize]byte, salt []byte) ([SessionKeySize]byte, error) {
	return DeriveHKDF32(shared[:], salt, []byte(ReflexSessionInfo))
}

// DeriveSessionKeyWithNonce is a convenience wrapper using nonce as salt.
func DeriveSessionKeyWithNonce(shared [SharedKeySize]byte, nonce [NonceSize]byte) ([SessionKeySize]byte, error) {
	return DeriveSessionKey(shared, nonce[:])
}
