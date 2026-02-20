package reflex

import (
	"math/rand"
	"sort"
	"sync"
	"time"
)

// PacketSizeDist represents packet size distribution
type PacketSizeDist struct {
	Size   int     `json:"size"`
	Weight float64 `json:"weight"`
}

// DelayDist represents delay distribution
type DelayDist struct {
	Delay  time.Duration `json:"delay"`
	Weight float64       `json:"weight"`
}

// TrafficProfile defines traffic morphing profile
type TrafficProfile struct {
	Name             string
	PacketSizes      []PacketSizeDist
	Delays           []DelayDist
	nextSize         int
	nextDelay        time.Duration
	mu               sync.Mutex
	cumulativeSizes  []float64 // precomputed cumulative weights
	cumulativeDelays []float64 // precomputed cumulative weights
}

// NewTrafficProfile creates new profile
func NewTrafficProfile(name string, sizes []PacketSizeDist, delays []DelayDist) *TrafficProfile {
	profile := &TrafficProfile{
		Name:        name,
		PacketSizes: sizes,
		Delays:      delays,
	}
	profile.computeCumulative()
	return profile
}

// computeCumulative precomputes cumulative weights for faster sampling
func (p *TrafficProfile) computeCumulative() {
	p.cumulativeSizes = make([]float64, len(p.PacketSizes))
	cumsum := 0.0
	for i, dist := range p.PacketSizes {
		cumsum += dist.Weight
		p.cumulativeSizes[i] = cumsum
	}

	p.cumulativeDelays = make([]float64, len(p.Delays))
	cumsum = 0.0
	for i, dist := range p.Delays {
		cumsum += dist.Weight
		p.cumulativeDelays[i] = cumsum
	}
}

// GetPacketSize returns next packet size from distribution
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Override if set
	if p.nextSize > 0 {
		size := p.nextSize
		p.nextSize = 0
		return size
	}

	r := rand.Float64()
	for i, cumWeight := range p.cumulativeSizes {
		if r <= cumWeight {
			return p.PacketSizes[i].Size
		}
	}

	// Fallback to last size
	if len(p.PacketSizes) > 0 {
		return p.PacketSizes[len(p.PacketSizes)-1].Size
	}
	return 1400 // default MTU-like size
}

// GetDelay returns next delay from distribution
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Override if set
	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0
		return delay
	}

	r := rand.Float64()
	for i, cumWeight := range p.cumulativeDelays {
		if r <= cumWeight {
			return p.Delays[i].Delay
		}
	}

	// Fallback to last delay
	if len(p.Delays) > 0 {
		return p.Delays[len(p.Delays)-1].Delay
	}
	return 10 * time.Millisecond
}

// SetNextSize overrides next packet size
func (p *TrafficProfile) SetNextSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextSize = size
}

// SetNextDelay overrides next delay
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

// Predefined traffic profiles based on real-world analysis
var (
	// YouTube profile: large packets with low latency
	YouTubeProfile = NewTrafficProfile(
		"YouTube",
		[]PacketSizeDist{
			{Size: 1400, Weight: 0.35},
			{Size: 1200, Weight: 0.25},
			{Size: 1000, Weight: 0.20},
			{Size: 800, Weight: 0.10},
			{Size: 600, Weight: 0.05},
			{Size: 400, Weight: 0.05},
		},
		[]DelayDist{
			{Delay: 8 * time.Millisecond, Weight: 0.30},
			{Delay: 12 * time.Millisecond, Weight: 0.25},
			{Delay: 16 * time.Millisecond, Weight: 0.20},
			{Delay: 20 * time.Millisecond, Weight: 0.15},
			{Delay: 30 * time.Millisecond, Weight: 0.10},
		},
	)

	// Zoom profile: moderate packet sizes with moderate latency
	ZoomProfile = NewTrafficProfile(
		"Zoom",
		[]PacketSizeDist{
			{Size: 500, Weight: 0.20},
			{Size: 600, Weight: 0.30},
			{Size: 700, Weight: 0.30},
			{Size: 800, Weight: 0.15},
			{Size: 900, Weight: 0.05},
		},
		[]DelayDist{
			{Delay: 25 * time.Millisecond, Weight: 0.25},
			{Delay: 30 * time.Millisecond, Weight: 0.30},
			{Delay: 35 * time.Millisecond, Weight: 0.25},
			{Delay: 40 * time.Millisecond, Weight: 0.15},
			{Delay: 50 * time.Millisecond, Weight: 0.05},
		},
	)

	// HTTP/2 API profile: varied packet sizes
	HTTP2APIProfile = NewTrafficProfile(
		"HTTP2-API",
		[]PacketSizeDist{
			{Size: 200, Weight: 0.15},
			{Size: 500, Weight: 0.25},
			{Size: 1000, Weight: 0.35},
			{Size: 1400, Weight: 0.20},
			{Size: 2000, Weight: 0.05},
		},
		[]DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.20},
			{Delay: 10 * time.Millisecond, Weight: 0.35},
			{Delay: 15 * time.Millisecond, Weight: 0.30},
			{Delay: 20 * time.Millisecond, Weight: 0.10},
			{Delay: 30 * time.Millisecond, Weight: 0.05},
		},
	)

	// Generic profile: balanced distribution
	GenericProfile = NewTrafficProfile(
		"Generic",
		[]PacketSizeDist{
			{Size: 512, Weight: 0.20},
			{Size: 1024, Weight: 0.30},
			{Size: 1400, Weight: 0.30},
			{Size: 2048, Weight: 0.15},
			{Size: 4096, Weight: 0.05},
		},
		[]DelayDist{
			{Delay: 10 * time.Millisecond, Weight: 0.30},
			{Delay: 15 * time.Millisecond, Weight: 0.30},
			{Delay: 20 * time.Millisecond, Weight: 0.25},
			{Delay: 30 * time.Millisecond, Weight: 0.10},
			{Delay: 50 * time.Millisecond, Weight: 0.05},
		},
	)
)

// GetProfileByName returns profile by name
func GetProfileByName(name string) *TrafficProfile {
	switch name {
	case "youtube":
		return YouTubeProfile
	case "zoom":
		return ZoomProfile
	case "http2-api":
		return HTTP2APIProfile
	default:
		return GenericProfile
	}
}

// CreateProfileFromSamples creates profile from packet samples
func CreateProfileFromSamples(sizes []int, delays []time.Duration) *TrafficProfile {
	sizeFreq := make(map[int]int)
	for _, s := range sizes {
		sizeFreq[s]++
	}

	var sizeDist []PacketSizeDist
	for size, count := range sizeFreq {
		sizeDist = append(sizeDist, PacketSizeDist{
			Size:   size,
			Weight: float64(count) / float64(len(sizes)),
		})
	}
	sort.Slice(sizeDist, func(i, j int) bool {
		return sizeDist[i].Size < sizeDist[j].Size
	})

	delayFreq := make(map[time.Duration]int)
	for _, d := range delays {
		delayFreq[d]++
	}

	var delayDist []DelayDist
	for delay, count := range delayFreq {
		delayDist = append(delayDist, DelayDist{
			Delay:  delay,
			Weight: float64(count) / float64(len(delays)),
		})
	}
	sort.Slice(delayDist, func(i, j int) bool {
		return delayDist[i].Delay < delayDist[j].Delay
	})

	return NewTrafficProfile("Custom", sizeDist, delayDist)
}
