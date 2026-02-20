package reflex

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

const (
	ReflexMagic        = 0x5246584C // "REFX" in ASCII
	HandshakeTimeout   = 30 * time.Second
	MaxClockDifference = 120 * time.Second
)

// ClientHandshake represents client's initial handshake packet
type ClientHandshake struct {
	PublicKey [32]byte // X25519 public key
	UserID    [16]byte // UUID (16 bytes)
	PolicyReq []byte   // Policy request (encrypted with pre-shared key)
	Timestamp int64    // Unix timestamp
	Nonce     [16]byte // Anti-replay nonce
}

// ServerHandshake represents server's handshake response
type ServerHandshake struct {
	PublicKey   [32]byte // Server's X25519 public key
	PolicyGrant []byte   // Policy grant (encrypted)
	Timestamp   int64    // Server timestamp
}

// ClientHandshakePacket is the complete initial packet
type ClientHandshakePacket struct {
	Magic     uint32          // ReflexMagic
	Handshake ClientHandshake // Handshake data
}

// ServerHandshakePacket is the complete response packet
type ServerHandshakePacket struct {
	Magic     uint32          // ReflexMagic
	Handshake ServerHandshake // Response data
}

// GenerateKeyPair generates X25519 key pair
func GenerateKeyPair() (privateKey, publicKey [32]byte, err error) {
	if _, err = rand.Read(privateKey[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// GenerateNonce generates random nonce
func GenerateNonce() ([16]byte, error) {
	var nonce [16]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// ValidateTimestamp checks if timestamp is within acceptable range
func ValidateTimestamp(ts int64) bool {
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	return time.Duration(diff)*time.Second <= MaxClockDifference
}

// ParseUUID converts [16]byte to UUID string
func ParseUUID(id [16]byte) string {
	return uuid.UUID(id).String()
}

// UUIDToBytes converts UUID string to [16]byte
func UUIDToBytes(id string) ([16]byte, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return [16]byte{}, err
	}
	var result [16]byte
	copy(result[:], parsed[:])
	return result, nil
}

// MarshalClientHandshake serializes client handshake
func MarshalClientHandshake(hs *ClientHandshake) []byte {
	buf := make([]byte, 32+16+len(hs.PolicyReq)+8+16)
	offset := 0

	copy(buf[offset:], hs.PublicKey[:])
	offset += 32

	copy(buf[offset:], hs.UserID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:], uint64(hs.Timestamp))
	offset += 8

	copy(buf[offset:], hs.Nonce[:])
	offset += 16

	copy(buf[offset:], hs.PolicyReq)

	return buf
}

// UnmarshalClientHandshake deserializes client handshake
func UnmarshalClientHandshake(data []byte) (*ClientHandshake, error) {
	if len(data) < 72 { // 32+16+8+16
		return nil, newError("handshake data too short")
	}

	hs := &ClientHandshake{}
	offset := 0

	copy(hs.PublicKey[:], data[offset:offset+32])
	offset += 32

	copy(hs.UserID[:], data[offset:offset+16])
	offset += 16

	hs.Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	copy(hs.Nonce[:], data[offset:offset+16])
	offset += 16

	if len(data) > offset {
		hs.PolicyReq = make([]byte, len(data)-offset)
		copy(hs.PolicyReq, data[offset:])
	}

	return hs, nil
}

// MarshalServerHandshake serializes server handshake
func MarshalServerHandshake(hs *ServerHandshake) []byte {
	buf := make([]byte, 32+8+len(hs.PolicyGrant))
	offset := 0

	copy(buf[offset:], hs.PublicKey[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], uint64(hs.Timestamp))
	offset += 8

	copy(buf[offset:], hs.PolicyGrant)

	return buf
}

// UnmarshalServerHandshake deserializes server handshake
func UnmarshalServerHandshake(data []byte) (*ServerHandshake, error) {
	if len(data) < 40 { // 32+8
		return nil, newError("server handshake data too short")
	}

	hs := &ServerHandshake{}
	offset := 0

	copy(hs.PublicKey[:], data[offset:offset+32])
	offset += 32

	hs.Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	if len(data) > offset {
		hs.PolicyGrant = make([]byte, len(data)-offset)
		copy(hs.PolicyGrant, data[offset:])
	}

	return hs, nil
}
