package reflex

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

var (
	ReflexMagic = uint32(0x5245464C) // "REFL"
)

// Frame represents a single protocol unit.
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// Session represents an encrypted Reflex session.
type Session struct {
	Key        []byte
	AEAD       cipher.AEAD
	ReadNonce  uint64
	WriteNonce uint64
}

// NewSession creates a new Reflex session.
func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		Key:        sessionKey,
		AEAD:       aead,
		ReadNonce:  0,
		WriteNonce: 0,
	}, nil
}

func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	// Encrypt
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.WriteNonce)
	s.WriteNonce++

	encrypted := s.AEAD.Seal(nil, nonce, data, nil)

	// Write header
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}

	// Write payload
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	return nil
}

func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	// Read header (3 bytes)
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	// Read payload
	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	// Decrypt
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.ReadNonce)
	s.ReadNonce++

	payload, err := s.AEAD.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	if profile == nil {
		return s.WriteFrame(writer, frameType, data)
	}

	targetSize := profile.GetPacketSize()

	if len(data) > targetSize {
		firstChunk := data[:targetSize]
		if err := s.writeFrameChunk(writer, frameType, firstChunk, profile); err != nil {
			return err
		}
		remaining := data[targetSize:]
		return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
	}

	// Add padding
	morphedData := data
	if len(data) < targetSize {
		padding := make([]byte, targetSize-len(data))
		rand.Read(padding)
		morphedData = append(morphedData, padding...)
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.WriteNonce)
	s.WriteNonce++

	encrypted := s.AEAD.Seal(nil, nonce, morphedData, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	delay := profile.GetDelay()
	time.Sleep(delay)

	return nil
}

func (s *Session) writeFrameChunk(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	return s.WriteFrameWithMorphing(writer, frameType, data, profile)
}

func GenerateKeyPair() ([32]byte, [32]byte, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return priv, priv, err
	}
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

func DeriveSessionKeys(priv [32]byte, pub [32]byte) ([]byte, error) {
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return nil, err
	}
	
	reader := hkdf.New(sha256.New, shared, nil, []byte("reflex-session-key"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	Timestamp int64
	Nonce     [16]byte
}

func (h *ClientHandshake) Serialize() []byte {
	buf := make([]byte, 32+16+8+16)
	copy(buf[0:32], h.PublicKey[:])
	copy(buf[32:48], h.UserID[:])
	binary.BigEndian.PutUint64(buf[48:56], uint64(h.Timestamp))
	copy(buf[56:72], h.Nonce[:])
	return buf
}

func ParseClientHandshake(data []byte) (*ClientHandshake, error) {
	if len(data) < 72 {
		return nil, errors.New("insufficient handshake data")
	}
	h := &ClientHandshake{}
	copy(h.PublicKey[:], data[0:32])
	copy(h.UserID[:], data[32:48])
	h.Timestamp = int64(binary.BigEndian.Uint64(data[48:56]))
	copy(h.Nonce[:], data[56:72])
	return h, nil
}

type ServerHandshake struct {
	PublicKey [32]byte
	Nonce     [16]byte
}

func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil {
		return
	}

	profile.mu.Lock()
	defer profile.mu.Unlock()

	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			size := int(binary.BigEndian.Uint16(frame.Payload))
			profile.nextPacketSize = size
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			millis := binary.BigEndian.Uint64(frame.Payload)
			profile.nextDelay = time.Duration(millis) * time.Millisecond
		}
	}
}
