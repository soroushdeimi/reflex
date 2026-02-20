package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session manages encryption/decryption for a Reflex connection
type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	readMutex  sync.Mutex
	writeMutex sync.Mutex
}

// NewSession creates a new Reflex session with the given key
func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	
	return &Session{
		key:        sessionKey,
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

// ReadFrame reads and decrypts a frame from the reader
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	s.readMutex.Lock()
	defer s.readMutex.Unlock()
	
	// Read header (3 bytes: length + type)
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	
	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]
	
	// Read encrypted payload
	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}
	
	// Construct nonce (12 bytes, with counter in the last 8 bytes)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++
	
	// Decrypt payload
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

// WriteFrame encrypts and writes a frame to the writer
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()
	
	// Construct nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++
	
	// Encrypt payload
	encrypted := s.aead.Seal(nil, nonce, data, nil)
	
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
