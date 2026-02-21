package reflex

import (
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// FrameTypeData indicates a data payload frame.
	FrameTypeData = 0x01
	// FrameTypePadding indicates a padding control frame.
	FrameTypePadding = 0x02
	// FrameTypeTiming indicates a timing control frame.
	FrameTypeTiming = 0x03
	// FrameTypeClose indicates a connection termination frame.
	FrameTypeClose = 0x04
)

// Frame represents a decrypted Reflex frame.
// یک فریم رمزگشایی شده پروتکل رفلکس.
type Frame struct {
	Length  uint16 // Total length of the encrypted payload including headers.
	Type    uint8  // Type of the frame (Data, Padding, etc).
	Payload []byte // Decrypted and unpadded payload.
}

// Session represents an established Reflex protocol session with bidirectional encryption.
// نشست برقرار شده پروتکل رفلکس با رمزنگاری دوطرفه را مدیریت می‌کند.
type Session struct {
	readAEAD   cipher.AEAD
	writeAEAD  cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

// NewSession creates a new Reflex session with separate read and write keys.
// یک نشست جدید رفلکس با کلیدهای مجزا برای خواندن و نوشتن ایجاد می‌کند.
func NewSession(readKey, writeKey []byte) (*Session, error) {
	readAEAD, err := chacha20poly1305.New(readKey)
	if err != nil {
		return nil, err
	}

	writeAEAD, err := chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		readAEAD:   readAEAD,
		writeAEAD:  writeAEAD,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

func (s *Session) ResetReadNonce() {
	s.readNonce = 0
}

func (s *Session) ResetWriteNonce() {
	s.writeNonce = 0
}

// ReadFrame reads and decrypts a single frame from the input stream.
// یک فریم را از جریان ورودی خوانده و رمزگشایی می‌کند.
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	var header [3]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++

	decrypted, err := s.readAEAD.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	payload := decrypted
	if frameType == FrameTypeData && len(decrypted) >= 2 {
		dataLen := binary.BigEndian.Uint16(decrypted[0:2])
		if int(dataLen)+2 <= len(decrypted) {
			payload = decrypted[2 : 2+dataLen]
		}
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

// WriteFrame encrypts and writes a data frame to the output stream.
// یک فریم داده را رمزنگاری کرده و در جریان خروجی می‌نویسد.
const MaxFrameDataSize = 65500

// WriteFrame encrypts and writes a data frame to the output stream.
// It automatically chunks data if it exceeds the maximum frame size.
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	if len(data) > MaxFrameDataSize {
		if err := s.WriteFrame(writer, frameType, data[:MaxFrameDataSize]); err != nil {
			return err
		}
		return s.WriteFrame(writer, frameType, data[MaxFrameDataSize:])
	}
	return s.WriteFrameWithPadding(writer, frameType, data, 0)
}

func (s *Session) WriteFrameWithPadding(writer io.Writer, frameType uint8, data []byte, paddingLen int) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	var payload []byte
	if frameType == FrameTypeData {
		payload = make([]byte, 2+len(data)+paddingLen)
		binary.BigEndian.PutUint16(payload[0:2], uint16(len(data)))
		copy(payload[2:], data)
		if paddingLen > 0 {
			// For traffic morphing padding, cryptographic randomness is not strictly required.
			// But we use crand to stay consistent with the rest of the protocol.
			crand.Read(payload[2+len(data):])
		}
	} else {
		payload = data
	}

	// Optimize: combined allocation for header and encrypted payload to reduce syscalls.
	// 3 bytes header + len(payload) + 16 bytes AEAD overhead.
	buffer := make([]byte, 3, 3+len(payload)+16)
	binary.BigEndian.PutUint16(buffer[0:2], uint16(len(payload)+16))
	buffer[2] = frameType

	encrypted := s.writeAEAD.Seal(buffer, nonce, payload, nil)

	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	return nil
}

func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil {
		return
	}
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload))
			profile.mu.Lock()
			profile.nextPacketSize = targetSize
			profile.mu.Unlock()
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.mu.Lock()
			profile.nextDelay = time.Duration(delayMs) * time.Millisecond
			profile.mu.Unlock()
		}
	}
}

func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	ctrlData := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, ctrlData)
}

func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	ctrlData := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrlData, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, ctrlData)
}

func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	for len(data) > 0 {
		targetTotalSize := profile.GetPacketSize()
		// Header (3) + DataLength (2) + RealData + Padding + AEAD Tag (16) = targetTotalSize
		maxData := targetTotalSize - 21
		if maxData <= 0 {
			maxData = 1
		}

		chunkSize := len(data)
		paddingLen := 0
		if chunkSize > maxData {
			chunkSize = maxData
		} else {
			paddingLen = maxData - chunkSize
		}

		if err := s.WriteFrameWithPadding(writer, frameType, data[:chunkSize], paddingLen); err != nil {
			return err
		}

		data = data[chunkSize:]
		time.Sleep(profile.GetDelay())
	}
	return nil
}
