package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/xtls/xray-core/common/errors"
)

const (
	FrameTypeData    uint8 = 0x01
	FrameTypePadding uint8 = 0x02
	FrameTypeTiming  uint8 = 0x03
	FrameTypeClose   uint8 = 0x04

	FrameHeaderSize = 3 // 2 bytes length + 1 byte type
	MaxFramePayload = 16384
)

// Frame represents an encrypted protocol frame.
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// Session manages AEAD encryption state for a Reflex connection.
type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	readMu     sync.Mutex
	writeMu    sync.Mutex
}

// NewSession creates a new encrypted session using ChaCha20-Poly1305.
func NewSession(sessionKey []byte) (*Session, error) {
	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid session key length, expected 32 bytes")
	}

	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, errors.New("failed to create ChaCha20Poly1305 AEAD").Base(err)
	}

	return &Session{
		key:  sessionKey,
		aead: aead,
	}, nil
}

func (s *Session) nextReadNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++
	return nonce
}

func (s *Session) nextWriteNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++
	return nonce
}

// ReadFrame reads and decrypts a single frame from the reader.
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	if length == 0 {
		return &Frame{Type: frameType}, nil
	}

	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, errors.New("failed to read frame payload").Base(err)
	}

	nonce := s.nextReadNonce()
	payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, errors.New("AEAD decryption failed").Base(err)
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a frame to the writer.
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	nonce := s.nextWriteNonce()
	encrypted := s.aead.Seal(nil, nonce, data, nil)

	header := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return errors.New("failed to write frame header").Base(err)
	}
	if _, err := writer.Write(encrypted); err != nil {
		return errors.New("failed to write frame payload").Base(err)
	}
	return nil
}

// WriteCloseFrame sends a CLOSE frame to signal end of connection.
func (s *Session) WriteCloseFrame(writer io.Writer) error {
	return s.WriteFrame(writer, FrameTypeClose, []byte{})
}

// WritePaddingFrame sends a PADDING_CTRL frame with random-length padding.
func (s *Session) WritePaddingFrame(writer io.Writer, padding []byte) error {
	return s.WriteFrame(writer, FrameTypePadding, padding)
}

// SendPaddingControl instructs the peer to use a specific packet size for
// the next frame via a PADDING_CTRL control frame.
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	return s.WriteFrame(writer, FrameTypePadding, EncodePaddingControl(targetSize))
}

// SendTimingControl instructs the peer to apply a specific delay before the
// next frame via a TIMING_CTRL control frame.
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	return s.WriteFrame(writer, FrameTypeTiming, EncodeTimingControl(delay))
}

// NonceTracker tracks seen nonces to detect replay attacks.
type NonceTracker struct {
	mu   sync.Mutex
	seen map[uint64]struct{}
	max  int
}

// NewNonceTracker creates a tracker that remembers up to maxEntries nonces.
func NewNonceTracker(maxEntries int) *NonceTracker {
	return &NonceTracker{
		seen: make(map[uint64]struct{}, maxEntries),
		max:  maxEntries,
	}
}

// Check returns true if this nonce has not been seen before.
func (nt *NonceTracker) Check(nonce uint64) bool {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	if _, exists := nt.seen[nonce]; exists {
		return false
	}

	if len(nt.seen) >= nt.max {
		// Evict oldest entries (simple reset for bounded memory)
		nt.seen = make(map[uint64]struct{}, nt.max)
	}
	nt.seen[nonce] = struct{}{}
	return true
}
