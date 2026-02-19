package reflex

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	mathrand "math/rand"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	nonceCache *NonceCache
}

type TrafficProfile struct {
	Name           string
	PacketSizes    []PacketSizeDist
	Delays         []DelayDist
	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

type PacketSizeDist struct {
	Size   int
	Weight float64
}

type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

var Profiles = map[string]TrafficProfile{
	"youtube": {
		Name: "YouTube",
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
		Name: "Zoom",
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

type NonceCache struct {
	seen map[uint64]bool
	mu   sync.Mutex
}

func NewNonceCache() *NonceCache {
	return &NonceCache{
		seen: make(map[uint64]bool),
	}
}

func (nc *NonceCache) Check(nonce uint64) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.seen[nonce] {
		return false
	}

	nc.seen[nonce] = true

	if len(nc.seen) > 1000 {
		nc.seen = make(map[uint64]bool)
	}

	return true
}

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
		nonceCache: NewNonceCache(),
	}, nil
}

func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	nonceValue := s.readNonce
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], nonceValue)
	s.readNonce++

	if !s.nonceCache.Check(nonceValue) {
		return nil, io.ErrUnexpectedEOF
	}

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

func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, data, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}

	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	return nil
}

func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}

	r := mathrand.Float64()
	cumsum := 0.0

	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
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

	r := mathrand.Float64()
	cumsum := 0.0

	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}

	return p.Delays[len(p.Delays)-1].Delay
}

func (s *Session) AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	padding := make([]byte, targetSize-len(data))
	rand.Read(padding)

	return append(data, padding...)
}

func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	targetSize := profile.GetPacketSize()

	if len(data) > targetSize {
		firstChunk := data[:targetSize]
		if err := s.writeFrameChunk(writer, frameType, firstChunk, profile); err != nil {
			return err
		}

		remaining := data[targetSize:]
		return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
	}

	morphedData := s.AddPadding(data, targetSize)

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, morphedData, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	writer.Write(header)
	writer.Write(encrypted)

	delay := profile.GetDelay()
	time.Sleep(delay)

	return nil
}

func (s *Session) writeFrameChunk(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	return s.WriteFrameWithMorphing(writer, frameType, data, profile)
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

func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	switch frame.Type {
	case FrameTypePadding:
		targetSize := int(binary.BigEndian.Uint16(frame.Payload))
		profile.SetNextPacketSize(targetSize)

	case FrameTypeTiming:
		delayMs := binary.BigEndian.Uint64(frame.Payload)
		profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
	}
}
