// Package morph implements traffic morphing for the Reflex protocol (Step 5).
// It provides traffic profiles that control packet sizes and timing delays
// to mimic the statistical distributions of real-world protocols.
package morph

import (
	"math/rand"
	"sync"
	"time"
)

// PacketSizeDist represents a packet size with an associated probability weight.
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist represents a delay with an associated probability weight.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// TrafficProfile controls traffic morphing behaviour for a session.
// Packet sizes and delays are sampled from weighted distributions.
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist

	mu             sync.Mutex
	nextPacketSize int
	nextDelay      time.Duration
}

// Profiles contains the built-in traffic profiles.
var Profiles = map[string]*TrafficProfile{
	"default": {
		Name: "Default",
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.5},
			{Size: 800, Weight: 0.3},
			{Size: 400, Weight: 0.2},
		},
		Delays: []DelayDist{
			{Delay: 0, Weight: 0.6},
			{Delay: 5 * time.Millisecond, Weight: 0.3},
			{Delay: 10 * time.Millisecond, Weight: 0.1},
		},
	},
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
	"mimic-http2-api": {
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

// GetProfile returns the named profile, falling back to "default".
func GetProfile(name string) *TrafficProfile {
	if p, ok := Profiles[name]; ok {
		return p
	}
	return Profiles["default"]
}

// GetPacketSize samples a packet size from the profile's weighted distribution.
// If a size override has been set (e.g. via a PADDING_CTRL frame), it is returned
// once and then cleared.
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}

	return sampleSize(p.PacketSizes)
}

// GetDelay samples a delay from the profile's weighted distribution.
// If a delay override has been set (e.g. via a TIMING_CTRL frame), it is returned
// once and then cleared.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		d := p.nextDelay
		p.nextDelay = 0
		return d
	}

	return sampleDelay(p.Delays)
}

// SetNextPacketSize allows a PADDING_CTRL frame to override the next packet size.
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

// SetNextDelay allows a TIMING_CTRL frame to override the next delay.
func (p *TrafficProfile) SetNextDelay(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = d
}

// AddPadding appends zero-byte padding to data to reach targetSize.
// If data is already >= targetSize, it is returned unchanged.
func AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padded := make([]byte, targetSize)
	copy(padded, data)
	return padded
}

// sampleSize picks a size by weighted random sampling.
func sampleSize(dist []PacketSizeDist) int {
	if len(dist) == 0 {
		return 1400 // sensible default
	}
	r := rand.Float64()
	cumsum := 0.0
	for _, d := range dist {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Size
		}
	}
	return dist[len(dist)-1].Size
}

// sampleDelay picks a delay by weighted random sampling.
func sampleDelay(dist []DelayDist) time.Duration {
	if len(dist) == 0 {
		return 0
	}
	r := rand.Float64()
	cumsum := 0.0
	for _, d := range dist {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Delay
		}
	}
	return dist[len(dist)-1].Delay
}
