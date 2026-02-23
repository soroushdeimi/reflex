package inbound

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	mathrand "math/rand"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// TrafficProfile represents a traffic morphing profile
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist
	nextPacketSize int
	nextDelay       time.Duration
	mu              sync.Mutex
}

// PacketSizeDist represents packet size distribution
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist represents delay distribution
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// Predefined traffic profiles
var (
	YouTubeProfile = TrafficProfile{
		Name: "YouTube",
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.35},
			{Size: 1200, Weight: 0.25},
			{Size: 1000, Weight: 0.20},
			{Size: 800, Weight: 0.10},
			{Size: 600, Weight: 0.05},
			{Size: 400, Weight: 0.05},
		},
		Delays: []DelayDist{
			{Delay: 8 * time.Millisecond, Weight: 0.30},
			{Delay: 12 * time.Millisecond, Weight: 0.25},
			{Delay: 16 * time.Millisecond, Weight: 0.20},
			{Delay: 20 * time.Millisecond, Weight: 0.15},
			{Delay: 30 * time.Millisecond, Weight: 0.10},
		},
	}

	ZoomProfile = TrafficProfile{
		Name: "Zoom",
		PacketSizes: []PacketSizeDist{
			{Size: 500, Weight: 0.30},
			{Size: 600, Weight: 0.40},
			{Size: 700, Weight: 0.30},
		},
		Delays: []DelayDist{
			{Delay: 30 * time.Millisecond, Weight: 0.40},
			{Delay: 40 * time.Millisecond, Weight: 0.40},
			{Delay: 50 * time.Millisecond, Weight: 0.20},
		},
	}

	HTTP2APIProfile = TrafficProfile{
		Name: "HTTP/2 API",
		PacketSizes: []PacketSizeDist{
			{Size: 200, Weight: 0.20},
			{Size: 500, Weight: 0.30},
			{Size: 1000, Weight: 0.30},
			{Size: 1500, Weight: 0.20},
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.30},
			{Delay: 10 * time.Millisecond, Weight: 0.40},
			{Delay: 15 * time.Millisecond, Weight: 0.30},
		},
	}

	// Profiles map for quick lookup
	Profiles = map[string]*TrafficProfile{
		"youtube":     &YouTubeProfile,
		"zoom":       &ZoomProfile,
		"http2-api":  &HTTP2APIProfile,
		"mimic-http2-api": &HTTP2APIProfile, // alias
	}
)

// GetPacketSize selects packet size based on distribution (or override)
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// If override is set, use it
	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0 // reset after use
		return size
	}

	// Otherwise use distribution
	r := mathrand.Float64()
	cumsum := 0.0

	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
		}
	}

	// Fallback to last size
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

// GetDelay selects delay based on distribution (or override)
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	// If override is set, use it
	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0 // reset after use
		return delay
	}

	// Otherwise use distribution
	r := mathrand.Float64()
	cumsum := 0.0

	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}

	// Fallback to last delay
	return p.Delays[len(p.Delays)-1].Delay
}

// SetNextPacketSize sets override for next packet size
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

// SetNextDelay sets override for next delay
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

// AddPadding adds padding to data to reach target size
func (s *Session) AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		// If larger, truncate (or could split)
		return data[:targetSize]
	}

	padding := make([]byte, targetSize-len(data))
	_, _ = rand.Read(padding) // random padding

	return append(data, padding...)
}

// WriteFrameWithMorphing writes a frame with traffic morphing
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	if profile == nil {
		// No morphing, use regular WriteFrame
		return s.WriteFrame(writer, frameType, data)
	}

	// Select target size based on profile
	targetSize := profile.GetPacketSize()

	// If data is larger than targetSize, split it
	if len(data) > targetSize {
		// Send first chunk
		firstChunk := data[:targetSize]
		if err := s.writeFrameChunk(writer, frameType, firstChunk, profile); err != nil {
			return err
		}

		// Send remaining data
		remaining := data[targetSize:]
		return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
	}

	// Add padding
	morphedData := s.AddPadding(data, targetSize)

	// Encrypt
	s.writeNonceMu.Lock()
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++
	s.writeNonceMu.Unlock()

	encrypted := s.aead.Seal(nil, nonce, morphedData, nil)

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

	// Apply delay based on profile
	delay := profile.GetDelay()
	time.Sleep(delay)

	return nil
}

// writeFrameChunk writes a chunk of frame with morphing
func (s *Session) writeFrameChunk(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	return s.WriteFrameWithMorphing(writer, frameType, data, profile)
}

// SendPaddingControl sends padding control frame
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	ctrlData := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, ctrlData)
}

// SendTimingControl sends timing control frame
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	ctrlData := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrlData, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, ctrlData)
}

// HandleControlFrame processes control frames (PADDING_CTRL and TIMING_CTRL)
func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil {
		return
	}

	switch frame.Type {
	case FrameTypePadding:
		// Peer wants us to add padding
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload))
			profile.SetNextPacketSize(targetSize)
		}

	case FrameTypeTiming:
		// Peer wants us to add delay
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}
}

// GetProfileByName returns a traffic profile by name
func GetProfileByName(name string) *TrafficProfile {
	if profile, ok := Profiles[name]; ok {
		// Return a copy to avoid race conditions
		return &TrafficProfile{
			Name:        profile.Name,
			PacketSizes: profile.PacketSizes,
			Delays:      profile.Delays,
		}
	}
	return nil
}

// CreateProfileFromCapture creates a profile from captured traffic data
func CreateProfileFromCapture(packetSizes []int, delays []time.Duration) *TrafficProfile {
	sizeDist := calculateSizeDistribution(packetSizes)
	delayDist := calculateDelayDistribution(delays)

	return &TrafficProfile{
		Name:        "Custom",
		PacketSizes: sizeDist,
		Delays:      delayDist,
	}
}

// calculateSizeDistribution calculates size distribution from values
func calculateSizeDistribution(values []int) []PacketSizeDist {
	// Count frequency of each value
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}

	// Convert to probability distribution
	total := len(values)
	dist := make([]PacketSizeDist, 0, len(freq))

	for size, count := range freq {
		dist = append(dist, PacketSizeDist{
			Size:   size,
			Weight: float64(count) / float64(total),
		})
	}

	// Sort by size
	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Size < dist[j].Size
	})

	return dist
}

// calculateDelayDistribution calculates delay distribution from values
func calculateDelayDistribution(values []time.Duration) []DelayDist {
	// Count frequency of each value
	freq := make(map[time.Duration]int)
	for _, v := range values {
		freq[v]++
	}

	// Convert to probability distribution
	total := len(values)
	dist := make([]DelayDist, 0, len(freq))

	for delay, count := range freq {
		dist = append(dist, DelayDist{
			Delay:  delay,
			Weight: float64(count) / float64(total),
		})
	}

	// Sort by delay
	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Delay < dist[j].Delay
	})

	return dist
}

