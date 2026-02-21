package reflex

import (
	"math/rand"
	"sort"
	"sync"
	"time"
)

// TrafficProfile defines statistical distribution for traffic morphing
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist // Distribution of packet sizes
	Delays      []DelayDist      // Distribution of delays
	nextPacketSize int           // Override for next packet size
	nextDelay      time.Duration // Override for next delay
	mu             sync.Mutex    // Mutex for thread safety
}

// PacketSizeDist represents a packet size with its probability weight
type PacketSizeDist struct {
	Size   int     // Packet size in bytes
	Weight float64 // Probability weight (0.0 to 1.0)
}

// DelayDist represents a delay with its probability weight
type DelayDist struct {
	Delay  time.Duration // Delay duration
	Weight float64       // Probability weight (0.0 to 1.0)
}

// GetPacketSize selects a packet size based on distribution (or override)
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// If override is set, use it
	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0 // Reset after use
		return size
	}

	// Otherwise use distribution
	if len(p.PacketSizes) == 0 {
		return 1400 // Default MTU size
	}

	r := rand.Float64()
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

// GetDelay selects a delay based on distribution (or override)
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	// If override is set, use it
	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0 // Reset after use
		return delay
	}

	// Otherwise use distribution
	if len(p.Delays) == 0 {
		return 10 * time.Millisecond // Default delay
	}

	r := rand.Float64()
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

// Predefined traffic profiles
var (
	// YouTubeProfile mimics YouTube streaming traffic
	YouTubeProfile = &TrafficProfile{
		Name: "YouTube",
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.35}, // Most packets are MTU size
			{Size: 1200, Weight: 0.25},
			{Size: 1000, Weight: 0.20},
			{Size: 800, Weight: 0.10},
			{Size: 600, Weight: 0.05},
			{Size: 400, Weight: 0.05},
		},
		Delays: []DelayDist{
			{Delay: 8 * time.Millisecond, Weight: 0.30},   // Low delay for streaming
			{Delay: 12 * time.Millisecond, Weight: 0.25},
			{Delay: 16 * time.Millisecond, Weight: 0.20},
			{Delay: 20 * time.Millisecond, Weight: 0.15},
			{Delay: 30 * time.Millisecond, Weight: 0.10},
		},
	}

	// ZoomProfile mimics Zoom video conferencing traffic
	ZoomProfile = &TrafficProfile{
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

	// HTTP2APIProfile mimics HTTP/2 API traffic
	HTTP2APIProfile = &TrafficProfile{
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
)

// GetProfile returns a predefined profile by name
func GetProfile(name string) *TrafficProfile {
	switch name {
	case "youtube":
		return YouTubeProfile
	case "zoom":
		return ZoomProfile
	case "http2-api", "http2api":
		return HTTP2APIProfile
	default:
		return nil
	}
}

// CreateProfileFromCapture creates a TrafficProfile from captured traffic data
func CreateProfileFromCapture(packetSizes []int, delays []time.Duration) *TrafficProfile {
	sizeDist := calculateSizeDistribution(packetSizes)
	delayDist := calculateDelayDistribution(delays)

	return &TrafficProfile{
		Name:        "Custom",
		PacketSizes: sizeDist,
		Delays:      delayDist,
	}
}

// calculateSizeDistribution converts packet sizes to probability distribution
func calculateSizeDistribution(values []int) []PacketSizeDist {
	if len(values) == 0 {
		return []PacketSizeDist{{Size: 1400, Weight: 1.0}}
	}

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

// calculateDelayDistribution converts delays to probability distribution
func calculateDelayDistribution(values []time.Duration) []DelayDist {
	if len(values) == 0 {
		return []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}}
	}

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
