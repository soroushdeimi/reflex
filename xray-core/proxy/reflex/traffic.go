package reflex

import (
	"encoding/binary"
	"io"
	"math/rand"
	"sync"
	"time"
)

// TrafficProfile describes a simple statistical model for packet sizes
// and inter-packet delays used for basic traffic morphing.
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist
	nextSize    int
	nextDelay   time.Duration
	mu          sync.Mutex
}

type PacketSizeDist struct {
	Size   int
	Weight float64
}

type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// Built-in profiles for traffic morphing (Step 5). Policy names in config can match these.
var (
	HTTP2APIProfile = &TrafficProfile{
		Name: "http2-api",
		PacketSizes: []PacketSizeDist{
			{Size: 200, Weight: 0.25},
			{Size: 600, Weight: 0.35},
			{Size: 1200, Weight: 0.25},
			{Size: 1500, Weight: 0.15},
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.4},
			{Delay: 10 * time.Millisecond, Weight: 0.4},
			{Delay: 20 * time.Millisecond, Weight: 0.2},
		},
	}
	// YouTubeProfile mimics streaming-like packet size and delay distribution.
	YouTubeProfile = &TrafficProfile{
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
	}
	// ZoomProfile mimics video-call-like distribution.
	ZoomProfile = &TrafficProfile{
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
	}
)

// GetPacketSize samples the next packet size. A one-shot override can be
// installed via SetNextPacketSize.
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextSize > 0 {
		size := p.nextSize
		p.nextSize = 0
		return size
	}

	if len(p.PacketSizes) == 0 {
		return 1024
	}

	r := rand.Float64()
	cumsum := 0.0
	for _, d := range p.PacketSizes {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Size
		}
	}
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

// GetDelay samples the next inter-packet delay. A one-shot override can be
// installed via SetNextDelay.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		d := p.nextDelay
		p.nextDelay = 0
		return d
	}

	if len(p.Delays) == 0 {
		return 0
	}

	r := rand.Float64()
	cumsum := 0.0
	for _, d := range p.Delays {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Delay
		}
	}
	return p.Delays[len(p.Delays)-1].Delay
}

// SetNextPacketSize overrides the next sampled packet size once.
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextSize = size
}

// SetNextDelay overrides the next sampled delay once.
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

// StripMorphingPrefix removes the 2-byte length prefix and padding from a
// DATA payload written with WriteFrameWithMorphing. Returns the real data and true
// if the format matches morphing, otherwise returns the payload unchanged and false.
func StripMorphingPrefix(payload []byte) (data []byte, ok bool) {
	// Need at least 2 bytes for length prefix
	if len(payload) < 2 {
		return payload, false
	}

	originalLen := int(binary.BigEndian.Uint16(payload[0:2]))

	// Validate: originalLen must be reasonable and fit within payload
	if originalLen < 0 || originalLen > len(payload)-2 {
		return payload, false
	}

	// Calculate padding length
	paddingLen := len(payload) - 2 - originalLen

	// Simple check: if there's padding, it's a morphed frame.
	// Format: [2 bytes BE length][data][padding]
	if paddingLen > 0 {
		return payload[2 : 2+originalLen], true
	}

	return payload, false
}

// AddPadding pads data up to targetSize with random bytes. If data is already
// larger, it is truncated to targetSize.
func (s *Session) AddPadding(data []byte, targetSize int) []byte {
	if targetSize <= 0 {
		return data
	}
	if len(data) >= targetSize {
		return data[:targetSize]
	}
	padding := make([]byte, targetSize-len(data))
	_, _ = rand.Read(padding)
	return append(data, padding...)
}

// WriteFrameWithMorphing writes a DATA frame whose encrypted length and
// timing roughly follow the given profile. Control frames still use the
// regular WriteFrame.
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	if profile == nil || frameType != FrameTypeData {
		return s.WriteFrame(writer, frameType, data)
	}

	target := profile.GetPacketSize()
	if len(data) > target {
		// Split large payload into multiple frames.
		first := data[:target]
		if err := s.WriteFrameWithMorphing(writer, frameType, first, profile); err != nil {
			return err
		}
		return s.WriteFrameWithMorphing(writer, frameType, data[target:], profile)
	}

	// Prepend 2-byte length prefix so receiver can strip padding
	// Format: [2 bytes original length BE][original data][padding]
	originalLen := len(data)
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(originalLen))
	dataWithPrefix := append(lengthPrefix, data...)

	// Adjust target to account for 2-byte prefix
	targetWithPrefix := target + 2
	morphed := s.AddPadding(dataWithPrefix, targetWithPrefix)

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, morphed, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	time.Sleep(profile.GetDelay())
	return nil
}

// SendPaddingControl sends a one-shot padding control command to adjust the
// peer's next packet size.
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	ctrl := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrl, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, ctrl)
}

// SendTimingControl sends a one-shot timing control command to adjust the
// peer's next delay.
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	ctrl := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrl, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, ctrl)
}

// HandleControlFrame updates the local profile in response to a control frame.
func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil || frame == nil {
		return
	}
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			size := int(binary.BigEndian.Uint16(frame.Payload))
			profile.SetNextPacketSize(size)
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}
}
