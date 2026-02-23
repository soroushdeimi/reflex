package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// Frame represents a decrypted Reflex frame.
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// Session handles AEAD encryption/decryption and
// frame encoding/decoding for an established connection.
type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

// NewSession initializes a new encrypted session using
// a 32-byte session key.
func NewSession(sessionKey []byte) (*Session, error) {

	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid session key length")
	}

	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

// buildNonce creates a 12-byte nonce from a uint64 counter.
// First 4 bytes are zero, last 8 bytes are the counter.
func buildNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// WriteFrame encrypts and writes a frame to the writer.
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {

	nonce := buildNonce(s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, data, nil)

	if len(encrypted) > 65535 {
		return errors.New("frame too large")
	}

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

// ReadFrame reads, decrypts and returns a frame.
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {

	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	if length == 0 {
		return nil, errors.New("invalid frame length")
	}

	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	nonce := buildNonce(s.readNonce)
	s.readNonce++

	payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}
