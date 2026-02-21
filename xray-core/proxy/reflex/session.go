package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Frame type constants for Reflex protocol.
const (
	FrameTypeData        uint8 = 0x00
	FrameTypePaddingCtrl uint8 = 0x01
	FrameTypeTimingCtrl  uint8 = 0x02
)

// Session provides encrypted frame read/write with ChaCha20-Poly1305 and replay protection.
type Session struct {
	aead cipher.AEAD

	mu              sync.Mutex
	writeNonceCount uint64
	readNonceCount  uint64 // last accepted read counter for replay check
	readSeen        bool   // true after first frame accepted
}

// NewSession creates a new Reflex session with the given 32-byte session key.
func NewSession(sessionKey []byte) (*Session, error) {
	if len(sessionKey) != 32 {
		return nil, errors.New("reflex: session key must be 32 bytes")
	}
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

// makeNonce writes 12-byte nonce: 4 zero bytes + 8-byte big-endian counter.
func makeNonce(nonceOut []byte, counter uint64) {
	if len(nonceOut) < 12 {
		return
	}
	binary.BigEndian.PutUint64(nonceOut[4:12], counter)
}

// WriteFrame encrypts and writes one frame: length (2) + nonce (12) + ciphertext.
// Plaintext is frameType (1 byte) + payload. Replay is avoided by monotonic write nonce.
func (s *Session) WriteFrame(w io.Writer, frameType uint8, payload []byte) error {
	s.mu.Lock()
	nonceCount := s.writeNonceCount
	s.writeNonceCount++
	s.mu.Unlock()

	plaintext := make([]byte, 1+len(payload))
	plaintext[0] = frameType
	copy(plaintext[1:], payload)

	nonce := make([]byte, s.aead.NonceSize())
	makeNonce(nonce, nonceCount)
	ciphertext := s.aead.Seal(nil, nonce, plaintext, nil)

	// Wire: 2-byte length (nonce + ciphertext), then nonce, then ciphertext.
	totalLen := len(nonce) + len(ciphertext)
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(totalLen))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	_, err := w.Write(ciphertext)
	return err
}

// Frame holds a decoded frame.
type Frame struct {
	Type    uint8
	Payload []byte
}

// ReadFrame reads and decrypts one frame. Returns error on replay (duplicate nonce) or auth failure.
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	totalLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	nonceSize := s.aead.NonceSize()
	if totalLen < nonceSize {
		return nil, errors.New("reflex: frame too short")
	}
	cipherLen := totalLen - nonceSize
	if cipherLen < s.aead.Overhead() {
		return nil, errors.New("reflex: ciphertext too short")
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, cipherLen)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	if len(plaintext) < 1 {
		return nil, errors.New("reflex: empty plaintext")
	}

	// Replay protection: require strictly increasing read counter (nonce last 8 bytes).
	readCounter := binary.BigEndian.Uint64(nonce[4:12])
	s.mu.Lock()
	if s.readSeen && readCounter <= s.readNonceCount {
		s.mu.Unlock()
		return nil, errors.New("reflex: replay detected")
	}
	s.readSeen = true
	s.readNonceCount = readCounter
	s.mu.Unlock()

	return &Frame{
		Type:    plaintext[0],
		Payload: plaintext[1:],
	}, nil
}
