package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session manages encrypted communication
type Session struct {
	clientToServer cipher.AEAD
	serverToClient cipher.AEAD

	readNonce  uint64
	writeNonce uint64

	nonceCache *NonceCache
	mu         sync.Mutex
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
		clientToServer: c2s,
		serverToClient: s2c,
		readNonce:      0,
		writeNonce:     0,
		nonceCache:     NewNonceCache(1000),
	}, nil
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
		clientToServer: c2s,
		serverToClient: s2c,
		readNonce:      0,
		writeNonce:     0,
		nonceCache:     NewNonceCache(1000),
	}, nil
}

// ReadFrame reads and decrypts a frame (server reads from client)
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

	// Decrypt
	var aead cipher.AEAD
	if isServer {
		aead = s.clientToServer // Server reads from client
	} else {
		aead = s.serverToClient // Client reads from server
	}

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

// WriteFrame encrypts and writes a frame (server writes to client)
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte, isServer bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prepare nonce
	nonce := make([]byte, 12)
	currentNonce := atomic.LoadUint64(&s.writeNonce)
	binary.BigEndian.PutUint64(nonce[4:], currentNonce)

	// Encrypt
	var aead cipher.AEAD
	if isServer {
		aead = s.serverToClient // Server writes to client
	} else {
		aead = s.clientToServer // Client writes to server
	}

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
