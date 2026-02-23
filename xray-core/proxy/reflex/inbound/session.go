package inbound

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

// Frame types
const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// Frame represents a Reflex protocol frame
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// Session manages encryption/decryption for a Reflex connection
type Session struct {
	key            []byte
	aead           cipher.AEAD
	readNonce      uint64
	writeNonce     uint64
	readNonceMu    sync.Mutex
	writeNonceMu   sync.Mutex
	profile        *TrafficProfile
	morphingEnabled bool
}

// NewSession creates a new Reflex session with the given session key
func NewSession(sessionKey []byte) (*Session, error) {
	if len(sessionKey) != 32 {
		return nil, errors.New("session key must be 32 bytes")
	}

	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, errors.New("failed to create AEAD").Base(err)
	}

	return &Session{
		key:       sessionKey,
		aead:      aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

// ReadFrame reads and decrypts a frame from the reader
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	// Read header (3 bytes: 2 bytes length + 1 byte type)
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	// Validate frame type
	if frameType != FrameTypeData && frameType != FrameTypePadding &&
		frameType != FrameTypeTiming && frameType != FrameTypeClose {
		return nil, errors.New("invalid frame type: ", frameType)
	}

	// Read encrypted payload
	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	// Decrypt
	s.readNonceMu.Lock()
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++
	s.readNonceMu.Unlock()

	payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, errors.New("decryption failed").Base(err)
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a frame to the writer
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	// Encrypt
	s.writeNonceMu.Lock()
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++
	s.writeNonceMu.Unlock()

	encrypted := s.aead.Seal(nil, nonce, data, nil)

	// Validate encrypted size
	if len(encrypted) > 65535 {
		return errors.New("encrypted frame too large")
	}

	// Write header
	header := make([]byte, 3)
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

