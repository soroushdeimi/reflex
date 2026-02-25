package tunnel

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// nonceSize is the AEAD nonce size for chacha20poly1305.
	nonceSize = 12
	// noncePrefixSize is the leading bytes kept as zero per Step3 doc example.
	noncePrefixSize = 4
)

// Limits (defensive). The on-wire Length field is uint16, so ciphertext is capped at 65535.
// We keep the default cap at the maximum allowed by the wire format.
const (
	MaxCiphertextLen = uint16(^uint16(0)) // 65535
)

// MaxPlaintextLen is the maximum plaintext size that can fit into one frame.
// (Ciphertext adds AEAD overhead.)
const (
	MaxPlaintextLen = int(MaxCiphertextLen) - chacha20poly1305.Overhead
)

// Session implements Step3 encrypted framing using ChaCha20-Poly1305.
//
// Concurrency:
//  - ReadFrame may be called in one goroutine while WriteFrame is called in another.
//  - readNonce and writeNonce counters are independent and atomic.
type Session struct {
	aead cipher.AEAD

	readNonce  atomic.Uint64
	writeNonce atomic.Uint64

	maxCiphertextLen uint16
}

// NewSession creates a new encrypted session from the 32-byte session key derived in Step2.
func NewSession(sessionKey []byte) (*Session, error) {
	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, errors.New("reflex tunnel: invalid session key length")
	}

	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, errors.New("reflex tunnel: chacha20poly1305 init").Base(err)
	}

	s := &Session{
		aead:             aead,
		maxCiphertextLen: MaxCiphertextLen,
	}
	return s, nil
}

// SetMaxCiphertextLen overrides the maximum allowed ciphertext length for a frame.
// This is mainly useful for tests or future traffic-morphing policies.
func (s *Session) SetMaxCiphertextLen(n uint16) {
	if s == nil {
		return
	}
	if n == 0 {
		// Keep current value.
		return
	}
	s.maxCiphertextLen = n
}

// ReadFrame reads and decrypts one frame from r.
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	if s == nil {
		return nil, errors.New("reflex tunnel: nil session")
	}
	if r == nil {
		return nil, errors.New("reflex tunnel: nil reader")
	}

	var hdr [FrameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(hdr[0:2])
	ft := hdr[2]

	if length > s.maxCiphertextLen {
		return nil, errors.New("reflex tunnel: frame too large")
	}
	if int(length) < s.aead.Overhead() {
		return nil, errors.New("reflex tunnel: frame too small")
	}

	ciphertext := make([]byte, int(length))
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	nonce := s.nextReadNonce()
	plaintext, err := s.aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, errors.New("reflex tunnel: decrypt failed").Base(err)
	}

	return &Frame{Length: length, Type: ft, Payload: plaintext}, nil
}

// WriteFrame encrypts payload and writes a frame to w.
func (s *Session) WriteFrame(w io.Writer, frameType uint8, payload []byte) error {
	if s == nil {
		return errors.New("reflex tunnel: nil session")
	}
	if w == nil {
		return errors.New("reflex tunnel: nil writer")
	}
	if len(payload) > MaxPlaintextLen {
		return errors.New("reflex tunnel: payload too large")
	}

	nonce := s.nextWriteNonce()
	ciphertext := s.aead.Seal(nil, nonce[:], payload, nil)
	if len(ciphertext) > int(s.maxCiphertextLen) {
		return errors.New("reflex tunnel: ciphertext too large")
	}

	var hdr [FrameHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(len(ciphertext)))
	hdr[2] = frameType

	if err := writeAll(w, hdr[:]); err != nil {
		return err
	}
	return writeAll(w, ciphertext)
}

func (s *Session) nextReadNonce() [nonceSize]byte {
	// First nonce used is 0.
	n := s.readNonce.Add(1) - 1
	return makeNonce(n)
}

func (s *Session) nextWriteNonce() [nonceSize]byte {
	// First nonce used is 0.
	n := s.writeNonce.Add(1) - 1
	return makeNonce(n)
}

func makeNonce(counter uint64) [nonceSize]byte {
	var nonce [nonceSize]byte
	// Keep first 4 bytes as 0, write counter into last 8 bytes.
	binary.BigEndian.PutUint64(nonce[noncePrefixSize:], counter)
	return nonce
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
