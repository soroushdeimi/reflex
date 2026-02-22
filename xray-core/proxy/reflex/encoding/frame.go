package encoding

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Frame types
const (
	FrameTypeData       byte = 0x01  // DATA frame
	FrameTypePadding    byte = 0x02  // PADDING_CTRL frame
	FrameTypeTiming     byte = 0x03  // TIMING_CTRL frame
	FrameTypeClose      byte = 0x04  // CLOSE frame
	MaxFramePayloadSize int  = 16384 // Maximum payload size (16KB)
)

// Frame represents a Reflex protocol frame
type Frame struct {
	Type    byte
	Payload []byte
}

// FrameEncoder encodes and encrypts frames
type FrameEncoder struct {
	aead    cipher.AEAD
	nonce   []byte
	counter uint64
	mu      sync.Mutex // Protects nonce and counter access
}

// NewFrameEncoder creates a new frame encoder with the session key
func NewFrameEncoder(sessionKey []byte) (*FrameEncoder, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &FrameEncoder{
		aead:    aead,
		nonce:   make([]byte, aead.NonceSize()),
		counter: 0,
	}, nil
}

// Encode encodes and encrypts a frame
// NOTE: The returned buffer is pooled. Caller must use immediately or copy,
// then call PutFrameBuffer to return it to the pool.
func (e *FrameEncoder) Encode(frame *Frame) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Increment counter for nonce
	e.counter++

	// Create local nonce for this operation (prevent nonce reuse across concurrent calls)
	nonce := make([]byte, e.aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, e.counter)

	// Get pooled buffer for plaintext: [type(1)] + [payload]
	plaintextSize := 1 + len(frame.Payload)
	plaintext := GetFrameBuffer(plaintextSize)
	defer PutFrameBuffer(plaintext)

	plaintext[0] = frame.Type
	copy(plaintext[1:], frame.Payload)

	// Get pooled buffer for ciphertext (plaintext + 16-byte authentication tag)
	ciphertextCapacity := plaintextSize + 16
	ciphertextBuf := GetFrameBuffer(ciphertextCapacity)
	defer PutFrameBuffer(ciphertextBuf)

	// Encrypt directly into pooled buffer (all under lock to prevent AEAD race)
	ciphertext := e.aead.Seal(ciphertextBuf[:0], nonce, plaintext[:plaintextSize], nil)

	// Get pooled buffer for final frame: [length(2)] + [ciphertext]
	frameDataSize := 2 + len(ciphertext)
	frameData := GetFrameBuffer(frameDataSize)

	binary.BigEndian.PutUint16(frameData[0:2], uint16(len(ciphertext)))
	copy(frameData[2:], ciphertext)

	return frameData[:frameDataSize], nil
}

// EncodeToWriter encodes and writes directly to writer (zero-copy optimized)
// This method handles buffer pooling internally, avoiding an extra allocation.
func (e *FrameEncoder) EncodeToWriter(w io.Writer, frame *Frame) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Increment counter for nonce
	e.counter++

	// Create local nonce for this operation (prevent nonce reuse across concurrent calls)
	nonce := make([]byte, e.aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, e.counter)

	// Get pooled buffer for plaintext: [type(1)] + [payload]
	plaintextSize := 1 + len(frame.Payload)
	plaintext := GetFrameBuffer(plaintextSize)
	defer PutFrameBuffer(plaintext)

	plaintext[0] = frame.Type
	copy(plaintext[1:], frame.Payload)

	// Get pooled buffer for ciphertext (plaintext + 16-byte authentication tag)
	ciphertextCapacity := plaintextSize + 16
	ciphertextBuf := GetFrameBuffer(ciphertextCapacity)
	defer PutFrameBuffer(ciphertextBuf)

	// Encrypt directly into pooled buffer (all under lock to prevent AEAD race)
	ciphertext := e.aead.Seal(ciphertextBuf[:0], nonce, plaintext[:plaintextSize], nil)

	// Get pooled buffer for final frame: [length(2)] + [ciphertext]
	frameDataSize := 2 + len(ciphertext)
	frameData := GetFrameBuffer(frameDataSize)
	defer PutFrameBuffer(frameData)

	binary.BigEndian.PutUint16(frameData[0:2], uint16(len(ciphertext)))
	copy(frameData[2:], ciphertext)

	// Write directly from pooled buffer
	_, err := w.Write(frameData[:frameDataSize])
	return err
}

// WriteFrame writes an encoded frame to a writer
func (e *FrameEncoder) WriteFrame(w io.Writer, frame *Frame) error {
	return e.EncodeToWriter(w, frame)
}

// FrameDecoder decodes and decrypts frames
type FrameDecoder struct {
	aead    cipher.AEAD
	nonce   []byte
	counter uint64
	mu      sync.Mutex // Protects nonce and counter access
}

// NewFrameDecoder creates a new frame decoder with the session key
func NewFrameDecoder(sessionKey []byte) (*FrameDecoder, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &FrameDecoder{
		aead:    aead,
		nonce:   make([]byte, aead.NonceSize()),
		counter: 0,
	}, nil
}

// Decode decodes and decrypts a frame
func (d *FrameDecoder) Decode(data []byte) (*Frame, error) {
	if len(data) < 2 {
		return nil, newError("frame too short")
	}

	// Read length
	length := binary.BigEndian.Uint16(data[0:2])
	if len(data) < int(2+length) {
		return nil, newError("incomplete frame")
	}

	ciphertext := data[2 : 2+length]

	d.mu.Lock()
	defer d.mu.Unlock()

	// Increment counter for nonce
	d.counter++

	// Create local nonce for this operation (prevent nonce reuse across concurrent calls)
	nonce := make([]byte, d.aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, d.counter)

	// Get pooled buffer for plaintext decryption
	plaintextBuf := GetFrameBuffer(len(ciphertext))
	defer PutFrameBuffer(plaintextBuf)

	// Decrypt directly into pooled buffer (all under lock to prevent AEAD race)
	plaintext, err := d.aead.Open(plaintextBuf[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	if len(plaintext) < 1 {
		return nil, newError("invalid plaintext")
	}

	// Get pooled Frame struct
	frame := GetFrame()

	frame.Type = plaintext[0]

	// CRITICAL: Copy payload data since plaintext buffer will be returned to pool
	payloadSize := len(plaintext) - 1
	if payloadSize > 0 {
		frame.Payload = make([]byte, payloadSize)
		copy(frame.Payload, plaintext[1:])
	} else {
		frame.Payload = nil
	}

	return frame, nil
}

// ReadFrame reads and decodes a frame from a reader
func (d *FrameDecoder) ReadFrame(r io.Reader) (*Frame, error) {
	// Get pooled buffer for length header (2 bytes)
	lengthBufPooled := GetFrameBuffer(2)
	defer PutFrameBuffer(lengthBufPooled)

	if _, err := io.ReadFull(r, lengthBufPooled[:2]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lengthBufPooled[:2])
	if length == 0 {
		return nil, newError("zero-length frame")
	}

	// Get pooled buffer for combined data: [length(2)] + [ciphertext(length)]
	totalSize := 2 + int(length)
	dataBuf := GetFrameBuffer(totalSize)
	defer PutFrameBuffer(dataBuf)

	// Copy length header to pooled buffer
	copy(dataBuf[0:2], lengthBufPooled[:2])

	// Read ciphertext directly into pooled buffer
	if _, err := io.ReadFull(r, dataBuf[2:totalSize]); err != nil {
		return nil, err
	}

	return d.Decode(dataBuf[:totalSize])
}

// SetMorphing enables traffic morphing with a profile
func (e *FrameEncoder) SetMorphing(config *MorphingConfig) {
	// This would be stored if FrameEncoder had a morphingConfig field
	// For now, we'll pass morphing config separately in write operations
}

// WriteFrameWithMorphing writes a frame with traffic morphing applied
func (e *FrameEncoder) WriteFrameWithMorphing(w io.Writer, frame *Frame, config *MorphingConfig) error {
	if config == nil || !config.Enabled || config.Profile == nil {
		// No morphing - write frame normally
		return e.WriteFrame(w, frame)
	}

	// Get target size from profile
	targetSize := config.Profile.GetPacketSize()

	// If payload is larger than target, we need to split
	if len(frame.Payload) > targetSize {
		// Write first chunk
		firstChunk := frame.Payload[:targetSize]
		firstFrame := &Frame{
			Type:    frame.Type,
			Payload: firstChunk,
		}
		if err := e.WriteFrame(w, firstFrame); err != nil {
			return err
		}

		// Apply delay
		delay := config.Profile.GetDelay()
		if delay > 0 {
			time.Sleep(delay)
		}

		// Write remaining data
		remaining := frame.Payload[targetSize:]
		remainingFrame := &Frame{
			Type:    frame.Type,
			Payload: remaining,
		}
		return e.WriteFrameWithMorphing(w, remainingFrame, config)
	}

	// Add padding to reach target size
	paddedPayload := AddPadding(frame.Payload, targetSize)

	// Create morphed frame
	morphedFrame := &Frame{
		Type:    frame.Type,
		Payload: paddedPayload,
	}

	// Write the morphed frame
	if err := e.WriteFrame(w, morphedFrame); err != nil {
		return err
	}

	// Apply delay from profile
	delay := config.Profile.GetDelay()
	if delay > 0 {
		time.Sleep(delay)
	}

	return nil
}

func newError(msg string) error {
	return errors.New(msg)
}
