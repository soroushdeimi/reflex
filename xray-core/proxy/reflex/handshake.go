package reflex

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// ReflexMagic is the magic number for quick protocol detection
	ReflexMagic = 0x5246584C // "REFX" in ASCII

	// HandshakeVersion is the current handshake protocol version
	HandshakeVersion = 1

	// HandshakeSize is the total size of client handshake packet
	HandshakeSize = 4 + 1 + 32 + 16 + 8 + 16 + 32 // magic + version + pubkey + uuid + timestamp + nonce + hmac
)

// ClientHandshake represents the client's handshake message
type ClientHandshake struct {
	Version   uint8     // Protocol version
	PublicKey [32]byte  // X25519 public key
	UserID    [16]byte  // User UUID (16 bytes)
	Timestamp int64     // Unix timestamp
	Nonce     [16]byte  // Random nonce for replay protection
	HMAC      [32]byte  // HMAC-SHA256 authentication
}

// ServerHandshake represents the server's handshake response
type ServerHandshake struct {
	Version   uint8    // Protocol version
	PublicKey [32]byte // X25519 public key
	HMAC      [32]byte // HMAC-SHA256 authentication
}

// EncodeClientHandshake encodes client handshake into binary format
func EncodeClientHandshake(hs *ClientHandshake) []byte {
	buf := make([]byte, HandshakeSize)
	offset := 0

	// Magic number
	binary.BigEndian.PutUint32(buf[offset:], ReflexMagic)
	offset += 4

	// Version
	buf[offset] = hs.Version
	offset++

	// Public key
	copy(buf[offset:], hs.PublicKey[:])
	offset += 32

	// User ID
	copy(buf[offset:], hs.UserID[:])
	offset += 16

	// Timestamp
	binary.BigEndian.PutUint64(buf[offset:], uint64(hs.Timestamp))
	offset += 8

	// Nonce
	copy(buf[offset:], hs.Nonce[:])
	offset += 16

	// HMAC (last 32 bytes)
	copy(buf[offset:], hs.HMAC[:])

	return buf
}

// DecodeClientHandshake decodes binary data into ClientHandshake
func DecodeClientHandshake(data []byte) (*ClientHandshake, error) {
	if len(data) < HandshakeSize {
		return nil, errors.New("handshake packet too short")
	}

	offset := 0

	// Verify magic number
	magic := binary.BigEndian.Uint32(data[offset:])
	if magic != ReflexMagic {
		return nil, errors.New("invalid magic number")
	}
	offset += 4

	hs := &ClientHandshake{}

	// Version
	hs.Version = data[offset]
	if hs.Version != HandshakeVersion {
		return nil, errors.New("unsupported handshake version")
	}
	offset++

	// Public key
	copy(hs.PublicKey[:], data[offset:offset+32])
	offset += 32

	// User ID
	copy(hs.UserID[:], data[offset:offset+16])
	offset += 16

	// Timestamp
	hs.Timestamp = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	// Nonce
	copy(hs.Nonce[:], data[offset:offset+16])
	offset += 16

	// HMAC
	copy(hs.HMAC[:], data[offset:offset+32])

	return hs, nil
}

// EncodeServerHandshake encodes server handshake into binary format
func EncodeServerHandshake(hs *ServerHandshake) []byte {
	buf := make([]byte, 1+32+32) // version + pubkey + hmac
	offset := 0

	buf[offset] = hs.Version
	offset++

	copy(buf[offset:], hs.PublicKey[:])
	offset += 32

	copy(buf[offset:], hs.HMAC[:])

	return buf
}

// DecodeServerHandshake decodes binary data into ServerHandshake
func DecodeServerHandshake(data []byte) (*ServerHandshake, error) {
	if len(data) < 65 {
		return nil, errors.New("server handshake packet too short")
	}

	hs := &ServerHandshake{}
	hs.Version = data[0]
	if hs.Version != HandshakeVersion {
		return nil, errors.New("unsupported handshake version")
	}

	copy(hs.PublicKey[:], data[1:33])
	copy(hs.HMAC[:], data[33:65])

	return hs, nil
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	if _, err := rand.Read(privateKey[:]); err != nil {
		return privateKey, publicKey, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

// DeriveSharedKey computes shared secret from private and peer public key
func DeriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

// DeriveSessionKey derives session key from shared secret using HKDF
func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	hkdf := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	hkdf.Read(sessionKey)
	return sessionKey
}

// ComputeClientHMAC computes HMAC-SHA256 for client handshake
func ComputeClientHMAC(secret []byte, version uint8, publicKey [32]byte, userID [16]byte, timestamp int64, nonce [16]byte) [32]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte{version})
	mac.Write(publicKey[:])
	mac.Write(userID[:])
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	mac.Write(timestampBytes)
	mac.Write(nonce[:])
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// ComputeServerHMAC computes HMAC-SHA256 for server handshake
func ComputeServerHMAC(secret []byte, version uint8, publicKey [32]byte) [32]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte{version})
	mac.Write(publicKey[:])
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// VerifyTimestamp checks if timestamp is within acceptable range (5 minutes)
func VerifyTimestamp(timestamp int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff < 300 // 5 minutes
}
