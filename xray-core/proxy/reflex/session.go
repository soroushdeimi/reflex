package reflex

import (
	"crypto/cipher"
	"crypto/rand"
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

// ReadFrame reads, decrypts, and extracts the true payload (discarding padding).
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

	// FIX: If it's a data frame, extract the 2-byte true length and slice off the padding.
	if frameType == FrameTypeData {
		if len(payload) < 2 {
			return nil, fmt.Errorf("malformed data frame: missing length prefix")
		}
		trueLen := binary.BigEndian.Uint16(payload[0:2])
		if int(trueLen) > len(payload)-2 {
			return nil, fmt.Errorf("malformed data frame: true length exceeds payload bounds")
		}
		payload = payload[2 : 2+trueLen] // Discard the padding
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a standard frame, adding the true length prefix for data.
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	var payloadToEncrypt []byte

	// FIX: Inject the 2-byte true length prefix for standard data frames.
	if frameType == FrameTypeData {
		payloadToEncrypt = make([]byte, 2+len(data))
		binary.BigEndian.PutUint16(payloadToEncrypt[0:2], uint16(len(data)))
		copy(payloadToEncrypt[2:], data)
	} else {
		payloadToEncrypt = data
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, payloadToEncrypt, nil)

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

// WriteFrameWithMorphing shapes the packet to match a specific TrafficProfile using inline padding.
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	if frameType != FrameTypeData {
		return s.WriteFrame(writer, frameType, data)
	}

	wireTarget := profile.GetPacketSize()
	payloadTarget := wireTarget
	maxDataLen := payloadTarget - 2 // Account for the 2-byte true length prefix

	if maxDataLen <= 0 {
		return fmt.Errorf("target size %d is too small for protocol overhead", wireTarget)
	}

	// 1. Handle Oversized Data via Splitting
	if len(data) > maxDataLen {
		chunk := data[:maxDataLen]
		if err := s.WriteFrameWithMorphing(writer, frameType, chunk, profile); err != nil {
			return err
		}
		remaining := data[maxDataLen:]
		return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
	}

	// 2. Construct Payload: [2-byte TrueLength] + [Real Data] + [High-Entropy Padding]
	morphedData := make([]byte, payloadTarget)
	binary.BigEndian.PutUint16(morphedData[0:2], uint16(len(data)))
	copy(morphedData[2:], data)

	paddingLen := payloadTarget - 2 - len(data)
	if paddingLen > 0 {
		if _, err := rand.Read(morphedData[2+len(data):]); err != nil {
			return fmt.Errorf("failed to generate secure padding: %w", err)
		}
	}

	// 3. Encrypt and Write
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

	// 4. Apply Statistical Timing Delay
	delay := profile.GetDelay()
	time.Sleep(delay)

	return nil
}

// WriteFrameWithDynamicMorphing selects a profile automatically based on rotation intervals.
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
