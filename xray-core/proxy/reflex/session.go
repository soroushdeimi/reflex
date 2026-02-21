package reflex

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session manages encrypted frame communication
type Session struct {
	aead          cipher.AEAD
	readNonce     uint64
	writeNonce    uint64
	morphingConfig *MorphingConfig
	trafficProfile *TrafficProfile // Advanced traffic morphing profile
	morphingEnabled bool            // Whether advanced morphing is enabled
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
		aead:           aead,
		readNonce:      0,
		writeNonce:     0,
		morphingConfig: morphingConfig,
		morphingEnabled: false,
	}, nil
}

// NewSessionWithProfile creates a new session with traffic profile
func NewSessionWithProfile(sessionKey []byte, morphingConfig *MorphingConfig, profile *TrafficProfile) (*Session, error) {
	session, err := NewSessionWithMorphing(sessionKey, morphingConfig)
	if err != nil {
		return nil, err
	}
	session.trafficProfile = profile
	session.morphingEnabled = profile != nil
	return session, nil
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
	// Use advanced morphing if enabled
	if s.morphingEnabled && s.trafficProfile != nil {
		return s.WriteFrameWithMorphing(writer, frameType, data)
	}

	// Fallback to basic morphing
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

// WriteFrameWithMorphing encrypts and writes a frame with advanced traffic morphing
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte) error {
	if s.trafficProfile == nil {
		return s.WriteFrame(writer, frameType, data)
	}

	// Select target size based on profile
	targetSize := s.trafficProfile.GetPacketSize()

	// If data is larger than target size, split it
	// Only pad chunks that are smaller than targetSize
	if len(data) > targetSize {
		// Send first chunk (exactly targetSize, no padding needed)
		firstChunk := data[:targetSize]
		if err := s.writeFrameChunkWithoutPadding(writer, frameType, firstChunk); err != nil {
			return err
		}

		// Send remaining data recursively
		remaining := data[targetSize:]
		return s.WriteFrameWithMorphing(writer, frameType, remaining)
	}

	// Add padding to reach target size (only for small chunks)
	morphedData := s.addPadding(data, targetSize)

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

	// Apply delay based on profile
	delay := s.trafficProfile.GetDelay()
	if delay > 0 {
		time.Sleep(delay)
	}

	return nil
}

// writeFrameChunk writes a single chunk of data
func (s *Session) writeFrameChunk(writer io.Writer, frameType uint8, data []byte) error {
	return s.WriteFrameWithMorphing(writer, frameType, data)
}

// writeFrameChunkWithoutPadding writes a chunk without adding padding (for split chunks)
func (s *Session) writeFrameChunkWithoutPadding(writer io.Writer, frameType uint8, data []byte) error {
	// Prepare nonce (12 bytes for ChaCha20-Poly1305)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	// Encrypt payload (no padding)
	encrypted := s.aead.Seal(nil, nonce, data, nil)

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

	// Apply delay based on profile
	if s.trafficProfile != nil {
		delay := s.trafficProfile.GetDelay()
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	return nil
}

// addPadding adds padding to data to reach target size
func (s *Session) addPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		// If larger, truncate
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	padding := make([]byte, paddingSize)
	rand.Read(padding)

	return append(data, padding...)
}

// GetMorphingConfig returns the morphing configuration
func (s *Session) GetMorphingConfig() *MorphingConfig {
	return s.morphingConfig
}

// GetTrafficProfile returns the traffic profile
func (s *Session) GetTrafficProfile() *TrafficProfile {
	return s.trafficProfile
}

// SetTrafficProfile sets the traffic profile
func (s *Session) SetTrafficProfile(profile *TrafficProfile) {
	s.trafficProfile = profile
	s.morphingEnabled = profile != nil
}

// HandleControlFrame processes PADDING_CTRL and TIMING_CTRL frames
func (s *Session) HandleControlFrame(frame *Frame) error {
	if s.trafficProfile == nil {
		return nil // Ignore if no profile
	}

	switch frame.Type {
	case FrameTypePadding:
		// Remote side wants us to add padding
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload[0:2]))
			s.trafficProfile.SetNextPacketSize(targetSize)
		}

	case FrameTypeTiming:
		// Remote side wants us to add delay
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload[0:8])
			s.trafficProfile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}

	return nil
}

// SendPaddingControl sends a PADDING_CTRL frame
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	ctrlData := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, ctrlData)
}

// SendTimingControl sends a TIMING_CTRL frame
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	ctrlData := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrlData, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, ctrlData)
}
