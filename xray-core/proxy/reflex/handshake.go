package reflex

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ReflexMagic is an optional magic number used for fast detection
// of Reflex traffic when not using HTTP POST-like disguise.
// "REFX" in ASCII.
const ReflexMagic uint32 = 0x5246584c

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// ClientHandshake carries the logical client handshake fields before
// any outer encoding (HTTP, base64, etc.).
type ClientHandshake struct {
	PublicKey [32]byte // Ephemeral X25519 public key
	UserID    [16]byte // Raw UUID bytes
	PolicyReq []byte   // Encrypted policy request (not used in Step 2)
	Timestamp int64    // Unix timestamp
	Nonce     [16]byte // Replay protection
}

// ClientHandshakePacket is the binary on-wire form used with the magic
// number fast path.
type ClientHandshakePacket struct {
	Magic     uint32
	Handshake ClientHandshake
}

// ServerHandshake is the logical server response for the handshake.
type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte // Encrypted policy grant (not used in Step 2)
}

// GenerateKeyPair creates a new X25519 key pair.
func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	_, err = io.ReadFull(rand.Reader, privateKey[:])
	if err != nil {
		return
	}
	// X25519 uses scalar multiplication with the base point.
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// DeriveSharedKey performs an X25519 Diffie-Hellman to derive a shared key.
func DeriveSharedKey(privateKey, peerPublicKey [32]byte) (shared [32]byte) {
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return
}

// DeriveSessionKey expands the shared key into a session key using HKDF-SHA256.
func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	h := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(h, sessionKey); err != nil {
		return nil
	}
	return sessionKey
}

// Frame is a logical Reflex data unit after decryption.
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// Session holds encryption state for a Reflex connection.
type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

// NewSession builds a ChaCha20-Poly1305 based session from a 32-byte key.
func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		key:        sessionKey,
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

// ReadFrame reads, decrypts, and returns the next frame from reader.
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	encrypted := make([]byte, length)
	if _, err := io.ReadFull(reader, encrypted); err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++

	payload, err := s.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a frame with the given type and payload.
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, data, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}
	return nil
}

// EncodeClientHandshakePacket serializes a ClientHandshakePacket into bytes.
// This is a simple binary encoding for the magic-number fast path.
func EncodeClientHandshakePacket(p *ClientHandshakePacket) []byte {
	// Layout:
	// 4  bytes magic
	// 32 bytes client public key
	// 16 bytes user id
	// 8  bytes timestamp (int64, big-endian)
	// 16 bytes nonce
	// 4  bytes length of PolicyReq
	// N  bytes PolicyReq
	policyLen := len(p.Handshake.PolicyReq)
	size := 4 + 32 + 16 + 8 + 16 + 4 + policyLen
	out := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(out[offset:], p.Magic)
	offset += 4

	copy(out[offset:], p.Handshake.PublicKey[:])
	offset += 32

	copy(out[offset:], p.Handshake.UserID[:])
	offset += 16

	binary.BigEndian.PutUint64(out[offset:], uint64(p.Handshake.Timestamp))
	offset += 8

	copy(out[offset:], p.Handshake.Nonce[:])
	offset += 16

	binary.BigEndian.PutUint32(out[offset:], uint32(policyLen))
	offset += 4

	copy(out[offset:], p.Handshake.PolicyReq)

	return out
}

// DecodeClientHandshakePacket parses a ClientHandshakePacket from the given bytes.
func DecodeClientHandshakePacket(data []byte) (*ClientHandshakePacket, error) {
	const fixed = 4 + 32 + 16 + 8 + 16 + 4
	if len(data) < fixed {
		return nil, io.ErrUnexpectedEOF
	}
	offset := 0

	var pkt ClientHandshakePacket
	pkt.Magic = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	copy(pkt.Handshake.PublicKey[:], data[offset:offset+32])
	offset += 32

	copy(pkt.Handshake.UserID[:], data[offset:offset+16])
	offset += 16

	pkt.Handshake.Timestamp = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	copy(pkt.Handshake.Nonce[:], data[offset:offset+16])
	offset += 16

	policyLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	if policyLen > 0 {
		if len(data[offset:]) < policyLen {
			return nil, io.ErrUnexpectedEOF
		}
		pkt.Handshake.PolicyReq = make([]byte, policyLen)
		copy(pkt.Handshake.PolicyReq, data[offset:offset+policyLen])
	}

	return &pkt, nil
}

