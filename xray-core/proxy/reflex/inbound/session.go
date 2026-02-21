package inbound

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04

	maxFramePayloadSize = 65535
	replayWindowSize    = 1000
)

// Frame is one encrypted Reflex frame.
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// Session stores framing and AEAD state for one Reflex connection.
type Session struct {
	aead       cipherAEAD
	readNonce  uint64
	writeNonce uint64
	profile    *TrafficProfile

	writeMu sync.Mutex

	replayMu    sync.Mutex
	replaySeen  map[[32]byte]struct{}
	replayOrder [][32]byte
}

type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewSession creates a new encrypted frame session.
func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		aead:       aead,
		replaySeen: make(map[[32]byte]struct{}),
	}, nil
}

// SetTrafficProfile sets traffic morphing profile for this session.
func (s *Session) SetTrafficProfile(profile *TrafficProfile) {
	s.profile = profile
}

func makeNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func (s *Session) rememberCiphertext(ciphertext []byte) bool {
	h := sha256.Sum256(ciphertext)
	s.replayMu.Lock()
	defer s.replayMu.Unlock()

	if _, found := s.replaySeen[h]; found {
		return false
	}
	s.replaySeen[h] = struct{}{}
	s.replayOrder = append(s.replayOrder, h)
	if len(s.replayOrder) > replayWindowSize {
		old := s.replayOrder[0]
		s.replayOrder = s.replayOrder[1:]
		delete(s.replaySeen, old)
	}
	return true
}

// ReadFrame reads and decrypts one frame from reader.
func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[:2])
	frameType := header[2]
	if length == 0 || int(length) > maxFramePayloadSize {
		return nil, errors.New("invalid reflex frame length")
	}

	encryptedPayload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}
	if !s.rememberCiphertext(encryptedPayload) {
		return nil, errors.New("replay detected")
	}

	nonce := makeNonce(s.readNonce)
	s.readNonce++
	payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{Length: length, Type: frameType, Payload: payload}, nil
}

// WriteFrame encrypts and writes one frame.
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	nonce := makeNonce(s.writeNonce)
	s.writeNonce++
	encrypted := s.aead.Seal(nil, nonce, data, nil)
	if len(encrypted) > maxFramePayloadSize {
		return errors.New("frame too large")
	}

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}
	return nil
}

// WriteFrameWithMorphing writes data frames with size/timing shaping.
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte) error {
	if frameType != FrameTypeData || s.profile == nil {
		return s.WriteFrame(writer, frameType, data)
	}

	remaining := data
	for len(remaining) > 0 {
		targetSize := s.profile.GetPacketSize()
		if targetSize <= 0 {
			targetSize = len(remaining)
		}

		chunkSize := len(remaining)
		if chunkSize > targetSize {
			chunkSize = targetSize
		}
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		if err := s.WriteFrame(writer, FrameTypeData, chunk); err != nil {
			return err
		}

		// Use control frames to coordinate peer-side shaping.
		if err := s.SendPaddingControl(writer, targetSize); err != nil {
			return err
		}
		delay := s.profile.GetDelay()
		if delay > 0 {
			if err := s.SendTimingControl(writer, delay); err != nil {
				return err
			}
			time.Sleep(delay)
		}
	}

	return nil
}

func parseDestination(data []byte) (net.Destination, []byte, error) {
	if len(data) < 3 {
		return net.Destination{}, nil, errors.New("data frame too short")
	}
	addrLen := int(data[0])
	if len(data) < 1+addrLen+2 {
		return net.Destination{}, nil, errors.New("data frame missing destination")
	}
	addr := net.ParseAddress(string(data[1 : 1+addrLen]))
	port := binary.BigEndian.Uint16(data[1+addrLen : 1+addrLen+2])
	return net.TCPDestination(addr, net.Port(port)), data[1+addrLen+2:], nil
}

func writeUpstream(link *transport.Link, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)})
}

func forwardUpstreamToClient(link *transport.Link, session *Session, conn stat.Connection, errCh chan<- error) {
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			errCh <- err
			return
		}
		for _, b := range mb {
			if writeErr := session.WriteFrameWithMorphing(conn, FrameTypeData, b.Bytes()); writeErr != nil {
				b.Release()
				errCh <- writeErr
				return
			}
			b.Release()
		}
	}
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	session, err := NewSession(sessionKey)
	if err != nil {
		return err
	}
	session.SetTrafficProfile(profileFromPolicy(userPolicy(user)))

	var link *transport.Link
	upstreamErr := make(chan error, 1)

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch frame.Type {
		case FrameTypeData:
			if link == nil {
				dest, payload, parseErr := parseDestination(frame.Payload)
				if parseErr != nil {
					return parseErr
				}
				link, err = dispatcher.Dispatch(ctx, dest)
				if err != nil {
					return err
				}
				go forwardUpstreamToClient(link, session, conn, upstreamErr)
				if err := writeUpstream(link, payload); err != nil {
					return err
				}
				continue
			}
			if err := writeUpstream(link, frame.Payload); err != nil {
				return err
			}
		case FrameTypePadding:
			if err := session.HandleControlFrame(frame); err != nil {
				return err
			}
			continue
		case FrameTypeTiming:
			if err := session.HandleControlFrame(frame); err != nil {
				return err
			}
			continue
		case FrameTypeClose:
			if link != nil {
				common.Close(link.Writer)
			}
			return nil
		default:
			return errors.New("unknown frame type")
		}

		select {
		case upErr := <-upstreamErr:
			if upErr == io.EOF {
				_ = session.WriteFrame(conn, FrameTypeClose, nil)
				return nil
			}
			return upErr
		default:
		}
	}
}
