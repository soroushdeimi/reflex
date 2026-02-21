package inbound

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FrameTypeData    uint8 = 0x01
	FrameTypePadding uint8 = 0x02
	FrameTypeTiming  uint8 = 0x03
	FrameTypeClose   uint8 = 0x04
)

type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

type Session struct {
	aead            framePass
	readNonce       uint64
	writeNonce      uint64
	readMu          sync.Mutex
	writeMu         sync.Mutex
	profile         *TrafficProfile
	morphingEnabled bool
}

type framePass interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

type PacketSizeDist struct {
	Size   int
	Weight float64
}

type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

type TrafficProfile struct {
	Name           string
	PacketSizes    []PacketSizeDist
	Delays         []DelayDist
	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

var (
	profiles = map[string]*TrafficProfile{
		"youtube": {
			Name: "youtube",
			PacketSizes: []PacketSizeDist{
				{Size: 1400, Weight: 0.4},
				{Size: 1200, Weight: 0.3},
				{Size: 1000, Weight: 0.2},
				{Size: 800, Weight: 0.1},
			},
			Delays: []DelayDist{
				{Delay: 10 * time.Millisecond, Weight: 0.5},
				{Delay: 20 * time.Millisecond, Weight: 0.3},
				{Delay: 30 * time.Millisecond, Weight: 0.2},
			},
		},
		"zoom": {
			Name: "zoom",
			PacketSizes: []PacketSizeDist{
				{Size: 500, Weight: 0.3},
				{Size: 600, Weight: 0.4},
				{Size: 700, Weight: 0.3},
			},
			Delays: []DelayDist{
				{Delay: 30 * time.Millisecond, Weight: 0.4},
				{Delay: 40 * time.Millisecond, Weight: 0.4},
				{Delay: 50 * time.Millisecond, Weight: 0.2},
			},
		},
		"http2-api": {
			Name: "HTTP/2 API",
			PacketSizes: []PacketSizeDist{
				{Size: 200, Weight: 0.2},
				{Size: 500, Weight: 0.3},
				{Size: 1000, Weight: 0.3},
				{Size: 1500, Weight: 0.2},
			},
			Delays: []DelayDist{
				{Delay: 5 * time.Millisecond, Weight: 0.3},
				{Delay: 10 * time.Millisecond, Weight: 0.4},
				{Delay: 15 * time.Millisecond, Weight: 0.3},
			},
		},
	}
	DefaultProfile = cloneProfile(profiles["http2-api"])
)

var rngCounter uint64

func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		aead:            aead,
		profile:         cloneProfile(DefaultProfile),
		morphingEnabled: true,
	}, nil
}

func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[:2])
	frameType := header[2]

	encryptedPayload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	nonce := makeNonce(s.readNonce)
	if s.readNonce == math.MaxUint64 {
		return nil, errors.New("read nonce overflow")
	}
	s.readNonce++

	payload, err := s.aead.Open(nil, nonce[:], encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	nonce := makeNonce(s.writeNonce)
	if s.writeNonce == math.MaxUint64 {
		return errors.New("write nonce overflow")
	}
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce[:], data, nil)
	if len(encrypted) > math.MaxUint16 {
		return errors.New("encrypted frame too large")
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

func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte) error {
	if !s.morphingEnabled || s.profile == nil || frameType != FrameTypeData {
		return s.WriteFrame(writer, frameType, data)
	}

	targetSize := s.profile.GetPacketSize()
	if targetSize <= 0 {
		return s.WriteFrame(writer, frameType, data)
	}

	if len(data) > targetSize {
		if err := s.WriteFrameWithMorphing(writer, frameType, data[:targetSize]); err != nil {
			return err
		}
		return s.WriteFrameWithMorphing(writer, frameType, data[targetSize:])
	}

	morphed := AddPadding(data, targetSize)
	if err := s.WriteFrame(writer, frameType, morphed); err != nil {
		return err
	}
	time.Sleep(s.profile.GetDelay())
	return nil
}

func (s *Session) HandleControlFrame(frame *Frame) {
	if s.profile == nil || len(frame.Payload) == 0 {
		return
	}

	switch frame.Type {
	case FrameTypePadding:
		// for better error handling to see whether frame.Payload[:2] works correctly
		if len(frame.Payload) < 2 {
			return
		}
		targetSize := int(binary.BigEndian.Uint16(frame.Payload[:2]))
		s.profile.SetNextPacketSize(targetSize)
	case FrameTypeTiming:
		if len(frame.Payload) < 8 {
			return
		}
		delayMs := binary.BigEndian.Uint64(frame.Payload[:8])
		s.profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
	}
}

func (s *Session) SetTrafficProfile(profile *TrafficProfile) {
	if profile == nil {
		s.profile = cloneProfile(DefaultProfile)
		return
	}
	s.profile = cloneProfile(profile)
}

func (s *Session) GetProfile() *TrafficProfile {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.profile
}

func GetTrafficProfile(name string) *TrafficProfile {
	if p, ok := profiles[name]; ok {
		return cloneProfile(p)
	}
	return cloneProfile(DefaultProfile)
}

func AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	padding := make([]byte, targetSize-len(data))
	_, _ = crand.Read(padding)
	out := make([]byte, 0, targetSize)
	out = append(out, data...)
	out = append(out, padding...)
	return out
}

func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}

	if len(p.PacketSizes) == 0 {
		return 0
	}

	r := nextRandFloat64()
	cumulative := 0.0
	for _, d := range p.PacketSizes {
		cumulative += d.Weight
		if r <= cumulative {
			return d.Size
		}
	}
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0
		return delay
	}
	if len(p.Delays) == 0 {
		return 0
	}

	r := nextRandFloat64()
	cumulative := 0.0
	for _, d := range p.Delays {
		cumulative += d.Weight
		if r <= cumulative {
			return d.Delay
		}
	}
	return p.Delays[len(p.Delays)-1].Delay
}

func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

func cloneProfile(p *TrafficProfile) *TrafficProfile {
	if p == nil {
		return nil
	}
	cp := &TrafficProfile{
		Name:           p.Name,
		nextPacketSize: p.nextPacketSize,
		nextDelay:      p.nextDelay,
	}
	cp.PacketSizes = append(cp.PacketSizes, p.PacketSizes...)
	cp.Delays = append(cp.Delays, p.Delays...)
	return cp
}

func nextRandFloat64() float64 {
	seed := int64(time.Now().UnixNano()) + int64(atomic.AddUint64(&rngCounter, 1))
	return mrand.New(mrand.NewSource(seed)).Float64()
}

func makeNonce(counter uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}
