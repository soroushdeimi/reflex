package inbound

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

type Session struct {
	cipher coreCipher
	locker sync.Mutex
	rxSeq  uint64
	txSeq  uint64
}

type coreCipher cipher.AEAD

func NewSession(secret []byte) (*Session, error) {
	engine, err := chacha20poly1305.New(secret)
	if err != nil {
		return nil, err
	}
	return &Session{cipher: engine}, nil
}

func (s *Session) advanceNonce(isTx bool) []byte {
	nBuf := make([]byte, 12)
	s.locker.Lock()
	defer s.locker.Unlock()

	if isTx {
		binary.BigEndian.PutUint64(nBuf[4:], s.txSeq)
		s.txSeq++
	} else {
		binary.BigEndian.PutUint64(nBuf[4:], s.rxSeq)
		s.rxSeq++
	}
	
	return nBuf
}

func (s *Session) ReadFrame(stream io.Reader) (*Frame, error) {
	hdr := make([]byte, 3)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return nil, err
	}

	pldLen := binary.BigEndian.Uint16(hdr[:2])
	kind := hdr[2]

	cipherText := make([]byte, pldLen)
	if _, err := io.ReadFull(stream, cipherText); err != nil {
		return nil, err
	}

	iv := s.advanceNonce(false)

	plainText, err := s.cipher.Open(nil, iv, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{Length: pldLen, Type: kind, Payload: plainText}, nil
}

func (s *Session) WriteFrame(stream io.Writer, kind uint8, chunk []byte) error {
	iv := s.advanceNonce(true)

	cipherText := s.cipher.Seal(nil, iv, chunk, nil)

	hdr := make([]byte, 3)
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(cipherText)))
	hdr[2] = kind

	if _, err := stream.Write(hdr); err != nil {
		return err
	}
	
	_, err := stream.Write(cipherText)
	return err
}