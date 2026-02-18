package inbound

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Frame types (protocol.md).
const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// Frame is a decrypted Reflex frame.
type Frame struct {
	Length uint16
	Type   uint8
	Payload []byte
}

// Session encrypts/decrypts frames with ChaCha20-Poly1305 and per-direction nonces.
type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	mu         sync.Mutex
}

// NewSession creates a session with the given 32-byte key.
func NewSession(key []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

// ReadFrame reads and decrypts one frame from r. Replay: nonces must increase (AEAD rejects reuse).
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(r, encrypted); err != nil {
		return nil, err
	}

	s.mu.Lock()
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++
	s.mu.Unlock()

	payload, err := s.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}
	return &Frame{Length: length, Type: frameType, Payload: payload}, nil
}

// WriteFrame encrypts and writes one frame to w.
func (s *Session) WriteFrame(w io.Writer, frameType uint8, data []byte) error {
	s.mu.Lock()
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++
	s.mu.Unlock()

	encrypted := s.aead.Seal(nil, nonce, data, nil)
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(encrypted)
	return err
}
