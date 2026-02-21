package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
)

const (
	ReflexMagic            uint32 = 0x5246584C // "RFXL"
	HandshakeHeaderSize           = 4 + 32 + 16 + 8 + 16 // magic + pubkey + uuid + timestamp + nonce
	MaxTimestampDrift             = 120 // seconds
)

// ClientHandshake contains the client-side handshake data.
type ClientHandshake struct {
	PublicKey [32]byte
	UserID    uuid.UUID
	Timestamp int64
	Nonce     [16]byte
}

// ServerHandshake contains the server-side handshake response.
type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant [32]byte
}

// GenerateKeyPair creates a new Curve25519 keypair for ephemeral key exchange.
func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	if _, err = rand.Read(privateKey[:]); err != nil {
		return privateKey, publicKey, errors.New("failed to generate random key").Base(err)
	}
	// Clamp private key per Curve25519 spec
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	pub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return privateKey, publicKey, errors.New("Curve25519 base multiply failed").Base(err)
	}
	copy(publicKey[:], pub)
	return
}

// DeriveSharedSecret computes the Curve25519 shared secret.
func DeriveSharedSecret(privateKey [32]byte, peerPublicKey [32]byte) ([32]byte, error) {
	var shared [32]byte
	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return shared, errors.New("Curve25519 key exchange failed").Base(err)
	}
	copy(shared[:], result)
	return shared, nil
}

// DeriveSessionKey uses HKDF-SHA256 to derive a session key from the shared secret.
func DeriveSessionKey(sharedSecret [32]byte, nonce []byte) ([]byte, error) {
	salt := make([]byte, 32)
	if len(nonce) > 0 {
		copy(salt, nonce)
	}
	hkdfReader := hkdf.New(sha256.New, sharedSecret[:], salt, []byte("reflex-session-key"))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, errors.New("HKDF key derivation failed").Base(err)
	}
	return sessionKey, nil
}

// MarshalClientHandshake serializes a ClientHandshake into bytes.
func MarshalClientHandshake(hs *ClientHandshake) []byte {
	data := make([]byte, HandshakeHeaderSize)
	binary.BigEndian.PutUint32(data[0:4], ReflexMagic)
	copy(data[4:36], hs.PublicKey[:])
	copy(data[36:52], hs.UserID[:])
	binary.BigEndian.PutUint64(data[52:60], uint64(hs.Timestamp))
	copy(data[60:76], hs.Nonce[:])
	return data
}

// UnmarshalClientHandshake deserializes bytes into a ClientHandshake.
func UnmarshalClientHandshake(data []byte) (*ClientHandshake, error) {
	if len(data) < HandshakeHeaderSize {
		return nil, errors.New("handshake data too short")
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != ReflexMagic {
		return nil, errors.New("invalid magic number")
	}
	hs := &ClientHandshake{
		Timestamp: int64(binary.BigEndian.Uint64(data[52:60])),
	}
	copy(hs.PublicKey[:], data[4:36])
	copy(hs.UserID[:], data[36:52])
	copy(hs.Nonce[:], data[60:76])
	return hs, nil
}

// MarshalServerHandshake serializes a ServerHandshake into bytes.
func MarshalServerHandshake(hs *ServerHandshake) []byte {
	data := make([]byte, 64)
	copy(data[0:32], hs.PublicKey[:])
	copy(data[32:64], hs.PolicyGrant[:])
	return data
}

// UnmarshalServerHandshake deserializes bytes into a ServerHandshake.
func UnmarshalServerHandshake(data []byte) (*ServerHandshake, error) {
	if len(data) < 64 {
		return nil, errors.New("server handshake data too short")
	}
	hs := &ServerHandshake{}
	copy(hs.PublicKey[:], data[0:32])
	copy(hs.PolicyGrant[:], data[32:64])
	return hs, nil
}

// ValidateTimestamp checks that the handshake timestamp is within acceptable drift.
func ValidateTimestamp(timestamp int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= MaxTimestampDrift
}

// AuthenticateUser looks up a user by UUID from the client list.
func AuthenticateUser(userID uuid.UUID, clients []*ClientEntry) *ClientEntry {
	for _, client := range clients {
		parsedID, err := uuid.ParseString(client.ID)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(userID[:], parsedID[:]) == 1 {
			return client
		}
	}
	return nil
}

// ClientEntry holds a validated client reference for authentication lookup.
type ClientEntry struct {
	ID     string
	Policy string
}
