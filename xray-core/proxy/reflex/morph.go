package reflex

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// TrafficProfile describes the statistical shape of traffic for a given
// impersonated protocol (e.g. YouTube, Zoom, HTTP/2 API).
type TrafficProfile struct {
	Name          string
	PacketSizes   []PacketSizeDist
	Delays        []DelayDist
	nextPacketSize int
	nextDelay       time.Duration
	mu              sync.Mutex
}

// PacketSizeDist represents a single bucket in the packet-size distribution.
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist represents a single bucket in the inter-packet delay distribution.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// Predefined traffic profiles. These can be tuned using real-world captures.
var Profiles = map[string]*TrafficProfile{
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

// GetPacketSize samples a packet size according to the profile's distribution,
// or uses a one-shot override if present.
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

	r := rand.Float64()
	cumsum := 0.0
	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
		}
	}
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

// GetDelay samples an inter-packet delay according to the profile's
// distribution, or uses a one-shot override if present.
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

	r := rand.Float64()
	cumsum := 0.0
	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}
	return p.Delays[len(p.Delays)-1].Delay
}

// SetNextPacketSize sets a one-shot override for the next sampled packet size.
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

// SetNextDelay sets a one-shot override for the next sampled delay.
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

// AddPadding pads or truncates a payload to reach the targetSize. When padding
// is required, random bytes are appended to reach the exact target size.
func AddPadding(data []byte, targetSize int) []byte {
	if targetSize <= 0 {
		return data
	}
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	padding := make([]byte, targetSize-len(data))
	_, _ = crand.Read(padding)
	return append(data, padding...)
}

// WriteFrameWithMorphing writes a frame with traffic morphing: payload is padded
// to a profile-sampled size, then written via session, then a profile-sampled
// delay is applied. If profile is nil, morphing is skipped (no padding, no delay).
func WriteFrameWithMorphing(session *Session, w io.Writer, frameType uint8, payload []byte, profile *TrafficProfile) error {
	if profile == nil {
		return session.WriteFrame(w, frameType, payload)
	}
	targetSize := profile.GetPacketSize()
	morphed := AddPadding(payload, targetSize)
	if err := session.WriteFrame(w, frameType, morphed); err != nil {
		return err
	}
	if d := profile.GetDelay(); d > 0 {
		time.Sleep(d)
	}
	return nil
}

// ApplyControlFrame updates profile from a PADDING_CTRL or TIMING_CTRL frame payload.
// PADDING_CTRL: payload is 2 bytes (big-endian target size).
// TIMING_CTRL: payload is 8 bytes (big-endian delay in milliseconds).
func ApplyControlFrame(profile *TrafficProfile, frameType uint8, payload []byte) {
	if profile == nil {
		return
	}
	switch frameType {
	case FrameTypePaddingCtrl:
		if len(payload) >= 2 {
			profile.SetNextPacketSize(int(binary.BigEndian.Uint16(payload)))
		}
	case FrameTypeTimingCtrl:
		if len(payload) >= 8 {
			profile.SetNextDelay(time.Duration(binary.BigEndian.Uint64(payload)) * time.Millisecond)
		}
	}
}

// CreateProfileFromCapture builds a TrafficProfile from raw packet sizes and
// delays collected from real-world captures.
func CreateProfileFromCapture(name string, packetSizes []int, delays []time.Duration) *TrafficProfile {
	sizeDist := calculateSizeDistribution(packetSizes)
	delayDist := calculateDelayDistribution(delays)
	return &TrafficProfile{
		Name:        name,
		PacketSizes: sizeDist,
		Delays:      delayDist,
	}
}

func calculateSizeDistribution(values []int) []PacketSizeDist {
	if len(values) == 0 {
		return nil
	}

	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}

	total := len(values)
	dist := make([]PacketSizeDist, 0, len(freq))
	for size, count := range freq {
		dist = append(dist, PacketSizeDist{
			Size:   size,
			Weight: float64(count) / float64(total),
		})
	}

	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Size < dist[j].Size
	})
	return dist
}

func calculateDelayDistribution(values []time.Duration) []DelayDist {
	if len(values) == 0 {
		return nil
	}

	freq := make(map[time.Duration]int)
	for _, v := range values {
		freq[v]++
	}

	total := len(values)
	dist := make([]DelayDist, 0, len(freq))
	for delay, count := range freq {
		dist = append(dist, DelayDist{
			Delay:  delay,
			Weight: float64(count) / float64(total),
		})
	}

	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Delay < dist[j].Delay
	})
	return dist
}

