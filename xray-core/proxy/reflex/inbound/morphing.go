package inbound

import (
	"encoding/binary"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// TrafficProfile defines packet size and delay distributions for traffic morphing.
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist
	nextSize    int
	nextDelay   time.Duration
	mu          sync.Mutex
}

// PacketSizeDist is a size with weight (probability).
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist is a delay with weight (probability).
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// DefaultProfiles are built-in profiles (e.g. for policy name).
var DefaultProfiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "YouTube",
		PacketSizes: []PacketSizeDist{
			{1400, 0.4}, {1200, 0.3}, {1000, 0.2}, {800, 0.1},
		},
		Delays: []DelayDist{
			{10 * time.Millisecond, 0.5}, {20 * time.Millisecond, 0.3}, {30 * time.Millisecond, 0.2},
		},
	},
	"http2-api": {
		Name: "HTTP/2 API",
		PacketSizes: []PacketSizeDist{
			{200, 0.2}, {500, 0.3}, {1000, 0.3}, {1500, 0.2},
		},
		Delays: []DelayDist{
			{5 * time.Millisecond, 0.3}, {10 * time.Millisecond, 0.4}, {15 * time.Millisecond, 0.3},
		},
	},
	"zoom": {
		Name: "Zoom",
		PacketSizes: []PacketSizeDist{
			{500, 0.3}, {600, 0.4}, {700, 0.3},
		},
		Delays: []DelayDist{
			{30 * time.Millisecond, 0.4}, {40 * time.Millisecond, 0.4}, {50 * time.Millisecond, 0.2},
		},
	},
}

// DefaultProfile used when user has no policy.
var DefaultProfile = DefaultProfiles["http2-api"]

// GetPacketSize returns the next target packet size (from override or distribution).
func (p *TrafficProfile) GetPacketSize() int {
	if p == nil {
		return 1200
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextSize > 0 {
		size := p.nextSize
		p.nextSize = 0
		return size
	}
	r := rand.Float64()
	cum := 0.0
	for _, d := range p.PacketSizes {
		cum += d.Weight
		if r <= cum {
			return d.Size
		}
	}
	if len(p.PacketSizes) > 0 {
		return p.PacketSizes[len(p.PacketSizes)-1].Size
	}
	return 1200
}

// GetDelay returns the next delay (from override or distribution).
func (p *TrafficProfile) GetDelay() time.Duration {
	if p == nil {
		return 10 * time.Millisecond
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextDelay > 0 {
		d := p.nextDelay
		p.nextDelay = 0
		return d
	}
	r := rand.Float64()
	cum := 0.0
	for _, d := range p.Delays {
		cum += d.Weight
		if r <= cum {
			return d.Delay
		}
	}
	if len(p.Delays) > 0 {
		return p.Delays[len(p.Delays)-1].Delay
	}
	return 10 * time.Millisecond
}

// SetNextPacketSize sets the next packet size (from PADDING_CTRL).
func (p *TrafficProfile) SetNextPacketSize(size int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextSize = size
}

// SetNextDelay sets the next delay (from TIMING_CTRL).
func (p *TrafficProfile) SetNextDelay(d time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = d
}

// ApplyMorphing pads data to target size (or truncates) and returns delay to apply after send. If profile is nil, returns data unchanged with no delay.
func (p *TrafficProfile) ApplyMorphing(data []byte) (out []byte, delay time.Duration) {
	if p == nil {
		return data, 0
	}
	target := p.GetPacketSize()
	delay = p.GetDelay()
	if len(data) >= target {
		return data[:target], delay
	}
	padded := make([]byte, target)
	copy(padded, data)
	for i := len(data); i < target; i++ {
		padded[i] = byte(rand.Intn(256))
	}
	return padded, delay
}

// getProfile returns the profile for the user's policy (or default).
func (h *Handler) getProfile(policy string) *TrafficProfile {
	if policy != "" && DefaultProfiles[policy] != nil {
		return DefaultProfiles[policy]
	}
	return DefaultProfile
}

// handleControlFrame applies PADDING_CTRL or TIMING_CTRL to the session's profile.
func (h *Handler) handleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil {
		return
	}
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			profile.SetNextPacketSize(int(binary.BigEndian.Uint16(frame.Payload)))
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			profile.SetNextDelay(time.Duration(binary.BigEndian.Uint64(frame.Payload)) * time.Millisecond)
		}
	}
}

// sortPacketSizes ensures PacketSizes are sorted by Size for deterministic sampling (optional).
func sortPacketSizes(d []PacketSizeDist) {
	sort.Slice(d, func(i, j int) bool { return d[i].Size < d[j].Size })
}

func init() {
	for _, p := range DefaultProfiles {
		if p != nil {
			sortPacketSizes(p.PacketSizes)
		}
	}
	if DefaultProfile != nil {
		sortPacketSizes(DefaultProfile.PacketSizes)
	}
}
