package inbound

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const ReflexMagic = 0x5246584C // "REFX"

// ClientHandshake contains the initial handshake data sent by the client.
type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

// ClientHandshakePacket matches the wire format of the initial handshake.
type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

// ServerHandshake contains the server's response to the client's handshake.
type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

// generateKeyPair creates a new X25519 key pair for the handshake.
func generateKeyPair() ([32]byte, [32]byte, error) {
	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return priv, pub, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

// deriveSharedKey computes the X25519 shared secret between the server's private key
// and the client's public key.
func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

// deriveSessionKey uses HKDF to derive a 32-byte session key from the shared secret.
func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	hkdf := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	hkdf.Read(sessionKey)
	return sessionKey
}
