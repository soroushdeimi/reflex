package encoding

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/xtls/xray-core/common/protocol"
)

const (
	// ReflexMagic is the magic number for Reflex protocol
	ReflexMagic = 0x5246584C // "REFX" in ASCII
)

// ClientHandshake represents the client's initial handshake packet
type ClientHandshake struct {
	PublicKey [32]byte // X25519 public key
	UserID    [16]byte // UUID (16 bytes)
	Timestamp int64    // Unix timestamp
	Nonce     [16]byte // Nonce for replay protection
}

// ServerHandshake represents the server's handshake response
type ServerHandshake struct {
	PublicKey [32]byte // X25519 public key
	Timestamp int64    // Unix timestamp
}

// GenerateKeyPair generates an X25519 key pair
func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// DeriveSharedKey derives the shared secret using X25519
func DeriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

// DeriveSessionKey derives the session key using HKDF-SHA256
func DeriveSessionKey(sharedKey [32]byte, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session-v1"))
	sessionKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

// EncodeClientHandshake encodes a client handshake with magic number
// NOTE: Uses pooled buffer (76 bytes). Caller must use immediately or copy,
// then call PutClientHandshakeBuffer to return it to the pool.
func EncodeClientHandshake(hs *ClientHandshake) []byte {
	buf := GetClientHandshakeBuffer()
	binary.BigEndian.PutUint32(buf[0:4], ReflexMagic)
	copy(buf[4:36], hs.PublicKey[:])
	copy(buf[36:52], hs.UserID[:])
	binary.BigEndian.PutUint64(buf[52:60], uint64(hs.Timestamp))
	copy(buf[60:76], hs.Nonce[:])
	return buf
}

// DecodeClientHandshake decodes a client handshake packet
func DecodeClientHandshake(data []byte) (*ClientHandshake, error) {
	if len(data) < 76 {
		return nil, errors.New("handshake packet too short")
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

// EncodeServerHandshake encodes a server handshake response
// NOTE: Uses pooled buffer (40 bytes). Caller must use immediately or copy,
// then call PutServerHandshakeBuffer to return it to the pool.
func EncodeServerHandshake(hs *ServerHandshake) []byte {
	buf := GetServerHandshakeBuffer()
	copy(buf[0:32], hs.PublicKey[:])
	binary.BigEndian.PutUint64(buf[32:40], uint64(hs.Timestamp))
	return buf
}

// DecodeServerHandshake decodes a server handshake response
func DecodeServerHandshake(data []byte) (*ServerHandshake, error) {
	if len(data) < 40 {
		return nil, errors.New("handshake response too short")
	}

	hs := &ServerHandshake{
		Timestamp: int64(binary.BigEndian.Uint64(data[32:40])),
	}
	copy(hs.PublicKey[:], data[0:32])

	return hs, nil
}

// ValidateTimestamp checks if the timestamp is within acceptable range (±120 seconds)
func ValidateTimestamp(timestamp int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= 120 // 2 minutes tolerance
}

// UUIDToBytes converts a protocol.ID to [16]byte array
func UUIDToBytes(id *protocol.ID) [16]byte {
	var result [16]byte
	copy(result[:], id.Bytes())
	return result
}
