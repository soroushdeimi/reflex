package reflex

import (
	"math/rand"
	"sync"
	"time"
)

// TrafficProfile defines traffic morphing characteristics
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist
	mu          sync.Mutex
}

// PacketSizeDist represents packet size distribution
type PacketSizeDist struct {
	Size   int     // Packet size in bytes
	Weight float64 // Probability weight
}

// DelayDist represents delay distribution
type DelayDist struct {
	Delay  time.Duration // Delay duration
	Weight float64       // Probability weight
}

// Predefined traffic profiles
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

// GetPacketSize returns a packet size based on the profile's distribution
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Calculate total weight
	totalWeight := 0.0
	for _, ps := range p.PacketSizes {
		totalWeight += ps.Weight
	}
	
	// Select based on weighted random
	r := rand.Float64() * totalWeight
	cumWeight := 0.0
	for _, ps := range p.PacketSizes {
		cumWeight += ps.Weight
		if r <= cumWeight {
			return ps.Size
		}
	}
	
	// Fallback to last size
	if len(p.PacketSizes) > 0 {
		return p.PacketSizes[len(p.PacketSizes)-1].Size
	}
	return 1024 // Default
}

// GetDelay returns a delay based on the profile's distribution
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Calculate total weight
	totalWeight := 0.0
	for _, d := range p.Delays {
		totalWeight += d.Weight
	}
	
	// Select based on weighted random
	r := rand.Float64() * totalWeight
	cumWeight := 0.0
	for _, d := range p.Delays {
		cumWeight += d.Weight
		if r <= cumWeight {
			return d.Delay
		}
	}
	
	// Fallback to last delay
	if len(p.Delays) > 0 {
		return p.Delays[len(p.Delays)-1].Delay
	}
	return 10 * time.Millisecond // Default
}

// GetProfile returns a traffic profile by name, or a default if not found
func GetProfile(name string) *TrafficProfile {
	if profile, ok := Profiles[name]; ok {
		return profile
	}
	// Return default profile
	return Profiles["http2-api"]
}

// ApplyMorphing applies traffic morphing to data
func (p *TrafficProfile) ApplyMorphing(data []byte) ([]byte, time.Duration) {
	targetSize := p.GetPacketSize()
	delay := p.GetDelay()
	
	// If data is larger than target, split will be handled by caller
	// If data is smaller, add padding
	if len(data) < targetSize {
		padded := make([]byte, targetSize)
		copy(padded, data)
		// Fill rest with random padding
		for i := len(data); i < targetSize; i++ {
			padded[i] = byte(rand.Intn(256))
		}
		return padded, delay
	}
	
	return data, delay
}
