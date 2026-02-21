package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session manages encrypted frame communication
type Session struct {
	aead          cipher.AEAD
	readNonce     uint64
	writeNonce    uint64
	morphingConfig *MorphingConfig
}

// NewSession creates a new encryption session with ChaCha20-Poly1305
func NewSession(sessionKey []byte) (*Session, error) {
	return NewSessionWithMorphing(sessionKey, DefaultMorphingConfig())
}

// NewSessionWithMorphing creates a new encryption session with morphing config
func NewSessionWithMorphing(sessionKey []byte, morphingConfig *MorphingConfig) (*Session, error) {
	if len(sessionKey) != 32 {
		return nil, errors.New("session key must be 32 bytes")
	}

	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		aead:          aead,
		readNonce:     0,
		writeNonce:    0,
		morphingConfig: morphingConfig,
	}, nil
}

// ReadFrame reads and decrypts a frame from reader
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	// Read header (3 bytes: length + type)
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	// Validate frame size
	if length > MaxFrameSize {
		return nil, errors.New("frame too large")
	}
	if length == 0 {
		return nil, errors.New("invalid frame length")
	}

	// Read encrypted payload
	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	// Prepare nonce (12 bytes for ChaCha20-Poly1305)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++

	// Decrypt payload
	payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	// Validate packet size (morphing validation) - check decrypted payload size
	if !ValidatePacketSize(len(payload), s.morphingConfig) {
		return nil, errors.New("suspicious packet size")
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a frame to writer
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	// Validate frame type
	if frameType < FrameTypeData || frameType > FrameTypeClose {
		return errors.New("invalid frame type")
	}

	// Apply traffic morphing (padding/randomization)
	morphedData := ApplyMorphing(data, s.morphingConfig)

	// Prepare nonce (12 bytes for ChaCha20-Poly1305)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	// Encrypt payload
	encrypted := s.aead.Seal(nil, nonce, morphedData, nil)

	// Validate encrypted size
	if len(encrypted) > MaxFrameSize {
		return errors.New("encrypted payload too large")
	}

	// Write header
	header := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}

	// Write encrypted payload
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	return nil
}

// GetMorphingConfig returns the morphing configuration
func (s *Session) GetMorphingConfig() *MorphingConfig {
	return s.morphingConfig
}
