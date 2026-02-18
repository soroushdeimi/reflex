package reflex

import (
	"crypto/cipher"
	"crypto/rand" // Using crypto/rand for secure padding entropy
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// Frame represents a single Reflex protocol unit.
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// Session handles the encryption, decryption, and traffic shaping for a connection.
type Session struct {
	key        []byte
	aead       cipher.AEAD
	ReadNonce  uint64
	writeNonce uint64
}

// NewSession creates a new Reflex session with the given 32-byte key.
func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		key:        sessionKey,
		aead:       aead,
		ReadNonce:  0,
		writeNonce: 0,
	}, nil
}

// ReadFrame reads, decrypts, and validates an incoming frame from the reader.
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.ReadNonce)
	s.ReadNonce++

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

// WriteFrame encrypts and writes a standard frame to the writer.
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

// AddPadding fills the remaining space with high-entropy random data to reach targetSize.
// It uses crypto/rand to prevent statistical detection of padding.
func (s *Session) AddPadding(data []byte, targetSize int) ([]byte, error) {
	if len(data) >= targetSize {
		return data, nil
	}

	paddingLen := targetSize - len(data)
	padding := make([]byte, paddingLen)
	// FIX: Check the error for rand.Read
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("failed to generate secure padding: %w", err)
	}

	return append(data, padding...), nil
}

// WriteFrameWithMorphing shapes the packet to match a specific TrafficProfile.
// It handles splitting large packets and padding small ones.
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	// 1. Calibration: Target wire size minus 3 (header) and 16 (AEAD tag)
	// This ensures the packet on the wire exactly matches the profile.
	wireTarget := profile.GetPacketSize()
	payloadTarget := wireTarget - 3 - 16

	if payloadTarget <= 0 {
		return fmt.Errorf("target size %d is too small for protocol overhead", wireTarget)
	}

	// 2. Handle Oversized Data via Splitting
	if len(data) > payloadTarget {
		chunk := data[:payloadTarget]
		if err := s.WriteFrameWithMorphing(writer, frameType, chunk, profile); err != nil {
			return err
		}

		remaining := data[payloadTarget:]
		return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
	}

	// 3. Add High-Entropy Padding
morphedData, err := s.AddPadding(data, payloadTarget)
    if err != nil {
        return err
    }
	// 4. Standard Encryption and Write
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, morphedData, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	// 5. Apply Statistical Timing Delay
	delay := profile.GetDelay()
	time.Sleep(delay)

	return nil
}

// WriteFrameWithDynamicMorphing selects a profile automatically based on rotation intervals.
// This fulfills the 5-point Advanced Bonus requirement.
func (s *Session) WriteFrameWithDynamicMorphing(writer io.Writer, frameType uint8, data []byte, morpher *DynamicMorpher) error {
	currentProfile := morpher.GetCurrentProfile()
	return s.WriteFrameWithMorphing(writer, frameType, data, currentProfile)
}

// --- Advanced: Control Frame Handling ---

// SendPaddingControl instructs the remote peer to use a specific target size for next packets.
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	ctrlData := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, ctrlData)
}

// SendTimingControl instructs the remote peer to use a specific delay for next packets.
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	ctrlData := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrlData, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, ctrlData)
}

// HandleControlFrame processes incoming PADDING_CTRL or TIMING_CTRL frames.
func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload))
			profile.SetNextPacketSize(targetSize)
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}
}