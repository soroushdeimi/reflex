package reflex

import (
	crand "crypto/rand"

	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	FrameTypeData    uint8 = 0x01
	FrameTypePadding uint8 = 0x02
	FrameTypeTiming  uint8 = 0x03
	FrameTypeClose   uint8 = 0x04
)

const (
	// MaxEncryptedFrameSize is limited by the 2-byte length field.
	MaxEncryptedFrameSize = 0xFFFF
)

// Frame is a decoded Reflex frame.
type Frame struct {
	Type    uint8
	Payload []byte
}

// Session maintains per-connection crypto state.
type Session struct {
	aead cipherAEAD

	readNonce  uint64
	writeNonce uint64
}

// cipherAEAD is the subset of cipher.AEAD we need.
// (Using a local interface makes the package easier to keep self-contained.)
type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewSession creates a new Reflex session with the given 32-byte key.
func NewSession(sessionKey [32]byte) (*Session, error) {
	aead, err := NewChaCha20Poly1305(sessionKey[:])
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

func makeNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// encodePlaintext prefixes the payload length and pads with zeros to reach a target payload size.
// targetPayloadSize refers to the size of the *payload* (excluding the 2-byte length prefix).
func encodePlaintext(payload []byte, targetPayloadSize int) []byte {
	if targetPayloadSize < len(payload) {
		targetPayloadSize = len(payload)
	}
	pt := make([]byte, 2+targetPayloadSize)
	binary.BigEndian.PutUint16(pt[0:2], uint16(len(payload)))
	copy(pt[2:], payload)
	padStart := 2 + len(payload)
	if padStart < len(pt) {
		_, _ = crand.Read(pt[padStart:])
	}
	return pt
}

// decodePlaintext strips the 2-byte length prefix.
func decodePlaintext(plaintext []byte) ([]byte, error) {
	if len(plaintext) < 2 {
		return nil, errors.New("reflex: plaintext too short")
	}
	l := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if l < 0 || l > len(plaintext)-2 {
		return nil, errors.New("reflex: invalid payload length")
	}
	return plaintext[2 : 2+l], nil
}

// WriteFrame encrypts and writes one frame (no morphing).
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, payload []byte) error {
	return s.WriteFrameWithMorphing(writer, frameType, payload, nil)
}

// WriteFrameWithMorphing encrypts and writes a frame, applying morphing if profile != nil.
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, payload []byte, profile *TrafficProfile) error {
	// Determine target payload size.
	target := len(payload)
	if profile != nil {
		if sz := profile.GetPacketSize(); sz > 0 {
			target = sz
		}
	}

	// Split if needed.
	if target > 0 && len(payload) > target {
		// Send first chunk then recurse.
		if err := s.WriteFrameWithMorphing(writer, frameType, payload[:target], profile); err != nil {
			return err
		}
		return s.WriteFrameWithMorphing(writer, frameType, payload[target:], profile)
	}

	pt := encodePlaintext(payload, target)
	nonce := makeNonce(s.writeNonce)
	s.writeNonce++
	var aad [1]byte
	aad[0] = frameType
	ct := s.aead.Seal(nil, nonce, pt, aad[:])
	if len(ct) > MaxEncryptedFrameSize {
		return errors.New("reflex: encrypted frame too large")
	}

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(ct)))
	header[2] = frameType
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(ct); err != nil {
		return err
	}

	if profile != nil {
		d := profile.GetDelay()
		if d > 0 {
			time.Sleep(d)
		}
	}
	return nil
}

// ReadFrame reads, decrypts, and returns one frame.
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[0:2]))
	frameType := header[2]
	if length <= 0 || length > MaxEncryptedFrameSize {
		return nil, errors.New("reflex: invalid frame length")
	}
	ct := make([]byte, length)
	if _, err := io.ReadFull(reader, ct); err != nil {
		return nil, err
	}
	nonce := makeNonce(s.readNonce)
	s.readNonce++
	var aad [1]byte
	aad[0] = frameType
	pt, err := s.aead.Open(nil, nonce, ct, aad[:])
	if err != nil {
		return nil, err
	}
	payload, err := decodePlaintext(pt)
	if err != nil {
		return nil, err
	}
	return &Frame{Type: frameType, Payload: payload}, nil
}

// SendPaddingControl sends a one-shot packet-size override to the peer.
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	ctrl := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrl, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, ctrl)
}

// SendTimingControl sends a one-shot delay override to the peer.
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	ctrl := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrl, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, ctrl)
}

// HandleControlFrame applies padding/timing control frames to a profile.
func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil || frame == nil {
		return
	}
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			sz := int(binary.BigEndian.Uint16(frame.Payload[:2]))
			profile.SetNextPacketSize(sz)
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			ms := binary.BigEndian.Uint64(frame.Payload[:8])
			profile.SetNextDelay(time.Duration(ms) * time.Millisecond)
		}
	}
}
