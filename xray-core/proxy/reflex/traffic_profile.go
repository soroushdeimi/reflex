package reflex

import (
	"math/rand"
	"sync"
	"time"
)

// TrafficProfile defines the statistical shape of the traffic.
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist

	// Internal state for temporary overrides from Control Frames
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

// Pre-defined profiles with exact weights from Step 5 documentation
var YouTubeProfile = TrafficProfile{
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
}

var ZoomProfile = TrafficProfile{
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
}

// GetPacketSize selects a target size based on probability weights.
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0 
		return size
	}

	r := rand.Float64()
	cumsum := 0.0

	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
		}
	}

	return p.PacketSizes[0].Size // Safe fallback
}

// GetDelay selects a delay duration based on probability weights.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0 
		return delay
	}

	r := rand.Float64()
	cumsum := 0.0

	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}

	return p.Delays[0].Delay // Safe fallback
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

// --- BONUS: Dynamic Profile Manager ---

type DynamicMorpher struct {
	profiles       []*TrafficProfile
	currentIndex   int
	mu             sync.Mutex
	lastSwitch     time.Time
	switchInterval time.Duration
}

func NewDynamicMorpher(interval time.Duration) *DynamicMorpher {
	return &DynamicMorpher{
		profiles:       []*TrafficProfile{&YouTubeProfile, &ZoomProfile},
		currentIndex:   0,
		lastSwitch:     time.Now(),
		switchInterval: interval,
	}
}

func (dm *DynamicMorpher) GetCurrentProfile() *TrafficProfile {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if time.Since(dm.lastSwitch) > dm.switchInterval {
		dm.currentIndex = (dm.currentIndex + 1) % len(dm.profiles)
		dm.lastSwitch = time.Now()
	}

	return dm.profiles[dm.currentIndex]
}

