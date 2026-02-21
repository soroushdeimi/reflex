package reflex

import (
	mrand "math/rand/v2"
	"sync"
	"time"
)

// TrafficProfile defines statistical distributions for packet sizes and delays.
// مشخصات آماری برای توزیع سایز بسته‌ها و تاخیرها را تعریف می‌کند.
type TrafficProfile struct {
	Name           string
	PacketSizes    []PacketSizeDist
	Delays         []DelayDist
	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

// PacketSizeDist represents a weighted entry in a packet size distribution.
type PacketSizeDist struct {
	Size   int     // Target packet size in bytes.
	Weight float64 // Probability weight (0.0 to 1.0).
}

// DelayDist represents a weighted entry in an inter-arrival delay distribution.
type DelayDist struct {
	Delay  time.Duration // Target delay.
	Weight float64       // Probability weight (0.0 to 1.0).
}

// Profiles is a registry of predefined traffic profiles (e.g., "youtube", "streaming").
var Profiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "YouTube",
		PacketSizes: []PacketSizeDist{
			{Size: 1450, Weight: 0.8},
			{Size: 1200, Weight: 0.1},
			{Size: 800, Weight: 0.1},
		},
		Delays: []DelayDist{
			{Delay: 1 * time.Millisecond, Weight: 0.7},
			{Delay: 5 * time.Millisecond, Weight: 0.2},
			{Delay: 10 * time.Millisecond, Weight: 0.1},
		},
	},
	"streaming": {
		Name: "Streaming",
		PacketSizes: []PacketSizeDist{
			{Size: 64000, Weight: 0.9},
			{Size: 32000, Weight: 0.05},
			{Size: 16000, Weight: 0.05},
		},
		Delays: []DelayDist{
			{Delay: 100 * time.Microsecond, Weight: 0.8},
			{Delay: 500 * time.Microsecond, Weight: 0.15},
			{Delay: 1 * time.Millisecond, Weight: 0.05},
		},
	},
	"web": {
		Name: "Web Browsing",
		PacketSizes: []PacketSizeDist{
			{Size: 1500, Weight: 0.4},
			{Size: 1000, Weight: 0.3},
			{Size: 500, Weight: 0.2},
			{Size: 100, Weight: 0.1},
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.5},
			{Delay: 10 * time.Millisecond, Weight: 0.3},
			{Delay: 50 * time.Millisecond, Weight: 0.2},
		},
	},
}

// GetPacketSize returns a packet size based on the profile's weighted distribution.
// یک سایز بسته را بر اساس توزیع وزنی پروفایل انتخاب می‌کند.
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

func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}

	r := mrand.Float64()
	cumsum := 0.0
	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
		}
	}
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

// GetDelay returns an inter-arrival delay based on the profile's weighted distribution.
// یک مقدار تاخیر زمانی را بر اساس توزیع وزنی پروفایل انتخاب می‌کند.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0
		return delay
	}

	r := mrand.Float64()
	cumsum := 0.0
	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}
	return p.Delays[len(p.Delays)-1].Delay
}
