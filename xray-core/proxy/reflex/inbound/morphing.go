package inbound

import (
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// PacketSizeDist is a weighted packet-size bucket.
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist is a weighted inter-frame delay bucket.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// TrafficProfile defines packet-size and timing distributions.
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist

	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

// Profiles contains built-in traffic profiles.
var Profiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "youtube",
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.35},
			{Size: 1200, Weight: 0.25},
			{Size: 1000, Weight: 0.2},
			{Size: 800, Weight: 0.1},
			{Size: 600, Weight: 0.1},
		},
		Delays: []DelayDist{
			{Delay: 8 * time.Millisecond, Weight: 0.30},
			{Delay: 12 * time.Millisecond, Weight: 0.25},
			{Delay: 16 * time.Millisecond, Weight: 0.20},
			{Delay: 20 * time.Millisecond, Weight: 0.15},
			{Delay: 30 * time.Millisecond, Weight: 0.10},
		},
	},
	"zoom": {
		Name: "zoom",
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
	},
	"http2-api": {
		Name: "http2-api",
		PacketSizes: []PacketSizeDist{
			{Size: 200, Weight: 0.20},
			{Size: 500, Weight: 0.30},
			{Size: 1000, Weight: 0.30},
			{Size: 1400, Weight: 0.20},
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.30},
			{Delay: 10 * time.Millisecond, Weight: 0.40},
			{Delay: 15 * time.Millisecond, Weight: 0.30},
		},
	},
	"mimic-http2-api": {
		Name: "mimic-http2-api",
		PacketSizes: []PacketSizeDist{
			{Size: 200, Weight: 0.20},
			{Size: 500, Weight: 0.30},
			{Size: 1000, Weight: 0.30},
			{Size: 1400, Weight: 0.20},
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.30},
			{Delay: 10 * time.Millisecond, Weight: 0.40},
			{Delay: 15 * time.Millisecond, Weight: 0.30},
		},
	},
}

func cloneProfile(p *TrafficProfile) *TrafficProfile {
	cp := &TrafficProfile{Name: p.Name}
	cp.PacketSizes = append(cp.PacketSizes, p.PacketSizes...)
	cp.Delays = append(cp.Delays, p.Delays...)
	return cp
}

func profileFromPolicy(policy string) *TrafficProfile {
	if p, ok := Profiles[policy]; ok {
		return cloneProfile(p)
	}
	return cloneProfile(Profiles["http2-api"])
}

func weightedPickSize(values []PacketSizeDist) int {
	if len(values) == 0 {
		return 0
	}
	pick := rand.Float64()
	sum := 0.0
	for _, d := range values {
		sum += d.Weight
		if pick <= sum {
			return d.Size
		}
	}
	return values[len(values)-1].Size
}

func weightedPickDelay(values []DelayDist) time.Duration {
	if len(values) == 0 {
		return 0
	}
	pick := rand.Float64()
	sum := 0.0
	for _, d := range values {
		sum += d.Weight
		if pick <= sum {
			return d.Delay
		}
	}
	return values[len(values)-1].Delay
}

// GetPacketSize returns next packet size using override or weighted distribution.
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}
	return weightedPickSize(p.PacketSizes)
}

// GetDelay returns next delay using override or weighted distribution.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextDelay > 0 {
		d := p.nextDelay
		p.nextDelay = 0
		return d
	}
	return weightedPickDelay(p.Delays)
}

// SetNextPacketSize overrides the next packet size.
func (p *TrafficProfile) SetNextPacketSize(size int) {
	if size <= 0 {
		return
	}
	p.mu.Lock()
	p.nextPacketSize = size
	p.mu.Unlock()
}

// SetNextDelay overrides the next delay.
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	if delay <= 0 {
		return
	}
	p.mu.Lock()
	p.nextDelay = delay
	p.mu.Unlock()
}

// SendPaddingControl sends a PADDING_CTRL frame with target size.
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	if targetSize <= 0 || targetSize > 65535 {
		return errors.New("invalid target size")
	}
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, payload)
}

// SendTimingControl sends a TIMING_CTRL frame with delay in milliseconds.
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	if delay <= 0 {
		return errors.New("invalid delay")
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, payload)
}

// HandleControlFrame applies control-frame overrides to current profile.
func (s *Session) HandleControlFrame(frame *Frame) error {
	if s.profile == nil {
		return nil
	}
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) != 2 {
			return errors.New("invalid padding control payload")
		}
		s.profile.SetNextPacketSize(int(binary.BigEndian.Uint16(frame.Payload)))
	case FrameTypeTiming:
		if len(frame.Payload) != 8 {
			return errors.New("invalid timing control payload")
		}
		ms := binary.BigEndian.Uint64(frame.Payload)
		s.profile.SetNextDelay(time.Duration(ms) * time.Millisecond)
	}
	return nil
}

// CreateProfileFromObservations builds a profile from captured sizes and delays.
func CreateProfileFromObservations(name string, packetSizes []int, delays []time.Duration) (*TrafficProfile, error) {
	if len(packetSizes) == 0 || len(delays) == 0 {
		return nil, errors.New("insufficient samples")
	}
	return &TrafficProfile{
		Name:        name,
		PacketSizes: calculateSizeDistribution(packetSizes),
		Delays:      calculateDelayDistribution(delays),
	}, nil
}

func calculateSizeDistribution(values []int) []PacketSizeDist {
	freq := map[int]int{}
	for _, v := range values {
		if v > 0 {
			freq[v]++
		}
	}
	total := 0
	for _, c := range freq {
		total += c
	}
	dist := make([]PacketSizeDist, 0, len(freq))
	for size, count := range freq {
		dist = append(dist, PacketSizeDist{Size: size, Weight: float64(count) / float64(total)})
	}
	sort.Slice(dist, func(i, j int) bool { return dist[i].Size < dist[j].Size })
	return dist
}

func calculateDelayDistribution(values []time.Duration) []DelayDist {
	freq := map[time.Duration]int{}
	for _, v := range values {
		if v > 0 {
			freq[v]++
		}
	}
	total := 0
	for _, c := range freq {
		total += c
	}
	dist := make([]DelayDist, 0, len(freq))
	for delay, count := range freq {
		dist = append(dist, DelayDist{Delay: delay, Weight: float64(count) / float64(total)})
	}
	sort.Slice(dist, func(i, j int) bool { return dist[i].Delay < dist[j].Delay })
	return dist
}
