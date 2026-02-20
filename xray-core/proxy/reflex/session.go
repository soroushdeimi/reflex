package reflex

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session manages encrypted communication with morphing support
type Session struct {
	clientToServer cipher.AEAD
	serverToClient cipher.AEAD

	readNonce  uint64
	writeNonce uint64

	nonceCache *NonceCache
	mu         sync.Mutex

	// Morphing support
	morphingProfile *TrafficProfile
	morphingEnabled bool
}

// NewServerSession creates server-side session
func NewServerSession(keys *SessionKeys) (*Session, error) {
	c2s, err := chacha20poly1305.New(keys.ClientToServer)
	if err != nil {
		return nil, newError("failed to create c2s cipher").Base(err)
	}

	s2c, err := chacha20poly1305.New(keys.ServerToClient)
	if err != nil {
		return nil, newError("failed to create s2c cipher").Base(err)
	}

	return &Session{
		clientToServer:  c2s,
		serverToClient:  s2c,
		readNonce:       0,
		writeNonce:      0,
		nonceCache:      NewNonceCache(1000),
		morphingEnabled: false,
	}, nil
}

// NewServerSessionWithMorphing creates server-side session with traffic morphing
func NewServerSessionWithMorphing(keys *SessionKeys, profile *TrafficProfile) (*Session, error) {
	sess, err := NewServerSession(keys)
	if err != nil {
		return nil, err
	}

	if profile != nil {
		sess.morphingProfile = profile
		sess.morphingEnabled = true
	}

	return sess, nil
}

// NewClientSession creates client-side session
func NewClientSession(keys *SessionKeys) (*Session, error) {
	c2s, err := chacha20poly1305.New(keys.ClientToServer)
	if err != nil {
		return nil, newError("failed to create c2s cipher").Base(err)
	}

	s2c, err := chacha20poly1305.New(keys.ServerToClient)
	if err != nil {
		return nil, newError("failed to create s2c cipher").Base(err)
	}

	return &Session{
		clientToServer:  c2s,
		serverToClient:  s2c,
		readNonce:       0,
		writeNonce:      0,
		nonceCache:      NewNonceCache(1000),
		morphingEnabled: false,
	}, nil
}

// NewClientSessionWithMorphing creates client-side session with traffic morphing
func NewClientSessionWithMorphing(keys *SessionKeys, profile *TrafficProfile) (*Session, error) {
	sess, err := NewClientSession(keys)
	if err != nil {
		return nil, err
	}

	if profile != nil {
		sess.morphingProfile = profile
		sess.morphingEnabled = true
	}

	return sess, nil
}

// ReadFrame reads and decrypts a frame
func (s *Session) ReadFrame(reader io.Reader, isServer bool) (*Frame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Read frame header
	length, frameType, err := ReadFrameHeader(reader)
	if err != nil {
		return nil, err
	}

	if !ValidateFrameType(frameType) {
		return nil, newError("invalid frame type: ", frameType)
	}

	// Read encrypted payload
	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, newError("failed to read frame payload").Base(err)
	}

	// Prepare nonce
	nonce := make([]byte, 12)
	currentNonce := atomic.LoadUint64(&s.readNonce)
	binary.BigEndian.PutUint64(nonce[4:], currentNonce)

	// Check for replay
	if !s.nonceCache.Check(currentNonce) {
		return nil, newError("replay attack detected, nonce: ", currentNonce)
	}

	// Select AEAD cipher
	var aead cipher.AEAD
	if isServer {
		aead = s.clientToServer // Server reads from client
	} else {
		aead = s.serverToClient // Client reads from server
	}

	// Decrypt
	payload, err := aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, newError("failed to decrypt frame").Base(err)
	}

	// Increment nonce
	atomic.AddUint64(&s.readNonce, 1)

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a frame without morphing
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte, isServer bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prepare nonce
	nonce := make([]byte, 12)
	currentNonce := atomic.LoadUint64(&s.writeNonce)
	binary.BigEndian.PutUint64(nonce[4:], currentNonce)

	// Select AEAD cipher
	var aead cipher.AEAD
	if isServer {
		aead = s.serverToClient // Server writes to client
	} else {
		aead = s.clientToServer // Client writes to server
	}

	// Encrypt
	encrypted := aead.Seal(nil, nonce, data, nil)

	// Write frame header
	if err := WriteFrameHeader(writer, uint16(len(encrypted)), frameType); err != nil {
		return err
	}

	// Write encrypted payload
	if _, err := writer.Write(encrypted); err != nil {
		return newError("failed to write frame payload").Base(err)
	}

	// Increment nonce
	atomic.AddUint64(&s.writeNonce, 1)

	return nil
}

// WriteFrameWithMorphing encrypts and writes frame with traffic morphing
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, isServer bool) error {
	if !s.morphingEnabled || s.morphingProfile == nil {
		return s.WriteFrame(writer, frameType, data, isServer)
	}

	// Split data into chunks based on morphing profile
	offset := 0

	for offset < len(data) {
		// Get target packet size from profile
		targetSize := s.morphingProfile.GetPacketSize()

		// Take chunk from data
		var chunk []byte
		if offset+targetSize > len(data) {
			chunk = data[offset:]
			offset = len(data)
		} else {
			chunk = data[offset : offset+targetSize]
			offset += targetSize
		}

		// Add padding to reach target size
		plaintext := s.addPadding(chunk, targetSize)

		// Encrypt and write
		if err := s.writeEncryptedFrame(writer, frameType, plaintext, isServer); err != nil {
			return err
		}

		// Apply delay between frames if more data pending
		if offset < len(data) {
			delay := s.morphingProfile.GetDelay()
			time.Sleep(delay)
		}
	}

	return nil
}

// writeEncryptedFrame is internal method to encrypt and write a single frame
func (s *Session) writeEncryptedFrame(writer io.Writer, frameType uint8, plaintext []byte, isServer bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prepare nonce
	nonce := make([]byte, 12)
	currentNonce := atomic.LoadUint64(&s.writeNonce)
	binary.BigEndian.PutUint64(nonce[4:], currentNonce)

	// Select AEAD cipher
	var aead cipher.AEAD
	if isServer {
		aead = s.serverToClient
	} else {
		aead = s.clientToServer
	}

	// Encrypt
	encrypted := aead.Seal(nil, nonce, plaintext, nil)

	// Write frame header
	if err := WriteFrameHeader(writer, uint16(len(encrypted)), frameType); err != nil {
		return err
	}

	// Write encrypted payload
	if _, err := writer.Write(encrypted); err != nil {
		return newError("failed to write morphed frame payload").Base(err)
	}

	// Increment nonce
	atomic.AddUint64(&s.writeNonce, 1)

	return nil
}

// addPadding adds random padding to reach target size
func (s *Session) addPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	padding := make([]byte, paddingSize)

	// Fill padding with random bytes
	if _, err := rand.Read(padding); err != nil {
		// Fallback: use zeros if rand fails (shouldn't happen in practice)
		for i := range padding {
			padding[i] = 0
		}
	}

	return append(data, padding...)
}

// SetMorphingProfile sets traffic morphing profile
func (s *Session) SetMorphingProfile(profile *TrafficProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.morphingProfile = profile
	s.morphingEnabled = profile != nil
}

// SetMorphingEnabled enables/disables morphing
func (s *Session) SetMorphingEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.morphingEnabled = enabled && s.morphingProfile != nil
}

// IsMorphingEnabled returns whether morphing is enabled
func (s *Session) IsMorphingEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.morphingEnabled
}

// GetMorphingProfile returns current morphing profile
func (s *Session) GetMorphingProfile() *TrafficProfile {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.morphingProfile
}

// HandleControlFrame processes control frames for dynamic morphing
func (s *Session) HandleControlFrame(frame *Frame) error {
	if frame == nil {
		return newError("nil frame")
	}

	switch frame.Type {
	case FrameTypePadding:
		// Frame payload: target packet size (2 bytes)
		if len(frame.Payload) >= 2 {
			targetSize := binary.BigEndian.Uint16(frame.Payload)
			if s.morphingProfile != nil {
				s.morphingProfile.SetNextSize(int(targetSize))
			}
		}
		return nil

	case FrameTypeTiming:
		// Frame payload: delay in milliseconds (8 bytes)
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			if s.morphingProfile != nil {
				s.morphingProfile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
			}
		}
		return nil

	default:
		return newError("unknown control frame type: ", frame.Type)
	}
}

// SendPaddingControl sends padding control command
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int, isServer bool) error {
	controlData := make([]byte, 2)
	binary.BigEndian.PutUint16(controlData, uint16(targetSize))

	return s.WriteFrame(writer, FrameTypePadding, controlData, isServer)
}

// SendTimingControl sends timing control command
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration, isServer bool) error {
	controlData := make([]byte, 8)
	binary.BigEndian.PutUint64(controlData, uint64(delay.Milliseconds()))

	return s.WriteFrame(writer, FrameTypeTiming, controlData, isServer)
}

// GetReadNonce returns current read nonce (for testing/debugging)
func (s *Session) GetReadNonce() uint64 {
	return atomic.LoadUint64(&s.readNonce)
}

// GetWriteNonce returns current write nonce (for testing/debugging)
func (s *Session) GetWriteNonce() uint64 {
	return atomic.LoadUint64(&s.writeNonce)
}

// ResetNonces resets nonce counters (use with caution - for testing only)
func (s *Session) ResetNonces() {
	atomic.StoreUint64(&s.readNonce, 0)
	atomic.StoreUint64(&s.writeNonce, 0)
}
