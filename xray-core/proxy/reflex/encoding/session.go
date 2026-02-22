package encoding

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session represents an encrypted Reflex session
type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	mu         sync.Mutex
}

// Frame represents a Reflex protocol frame
type Frame struct {
	Type    uint8  // FrameTypeData, FrameTypePadding, etc.
	Payload []byte // Decrypted payload
}

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

const (
	nonceSize = 12 // ChaCha20-Poly1305 nonce size
	tagSize   = 16 // Poly1305 authentication tag size
)

// NewSession creates a new encrypted session
func NewSession(key [32]byte) (*Session, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}

	return &Session{
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

// makeNonce creates a nonce from a counter
func makeNonce(counter uint64) [nonceSize]byte {
	var nonce [nonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// ReadFrame reads and decrypts a frame from the reader
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	// Read frame header (1 byte type + 2 bytes length)
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frameType := header[0]
	encPayloadLen := binary.BigEndian.Uint16(header[1:3])

	// Read encrypted payload
	encPayload := make([]byte, encPayloadLen)
	if _, err := io.ReadFull(r, encPayload); err != nil {
		return nil, err
	}

	// Decrypt the payload
	nonce := makeNonce(s.readNonce)
	s.readNonce++

	payload, err := s.aead.Open(nil, nonce[:], encPayload, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt frame")
	}

	return &Frame{
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a frame to the writer
func (s *Session) WriteFrame(w io.Writer, frameType uint8, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt the payload
	nonce := makeNonce(s.writeNonce)
	s.writeNonce++

	encPayload := s.aead.Seal(nil, nonce[:], payload, nil)

	// Write frame header
	header := make([]byte, 3)
	header[0] = frameType
	binary.BigEndian.PutUint16(header[1:3], uint16(len(encPayload)))

	if _, err := w.Write(header); err != nil {
		return err
	}

	// Write encrypted payload
	if _, err := w.Write(encPayload); err != nil {
		return err
	}

	return nil
}

// WriteFrames writes multiple frames (for batch operations)
func (s *Session) WriteFrames(w io.Writer, frames []*Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	buffer := make([]byte, 0, 4096)

	for _, frame := range frames {
		// Encrypt the payload
		nonce := makeNonce(s.writeNonce)
		s.writeNonce++

		encPayload := s.aead.Seal(nil, nonce[:], frame.Payload, nil)

		// Create frame header
		header := make([]byte, 3)
		header[0] = frame.Type
		binary.BigEndian.PutUint16(header[1:3], uint16(len(encPayload)))

		buffer = append(buffer, header...)
		buffer = append(buffer, encPayload...)
	}

	_, err := w.Write(buffer)
	return err
}

// ResetNonce resets the nonce counter (for testing)
func (s *Session) ResetNonce() {
	s.readNonce = 0
	s.writeNonce = 0
}
