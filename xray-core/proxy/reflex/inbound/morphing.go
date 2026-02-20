package inbound

import (
	"encoding/binary"
	mrand "math/rand"
	"sort"
	"sync"
	"time"
)

type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist
	nextSize    int
	nextDelay   time.Duration
	mu          sync.Mutex
}

type PacketSizeDist struct {
	Size   int
	Weight float64
}

type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

var DefaultProfiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "YouTube",
		PacketSizes: []PacketSizeDist{{1400, 0.4}, {1200, 0.3}, {1000, 0.2}, {800, 0.1}},
		Delays:      []DelayDist{{10 * time.Millisecond, 0.5}, {20 * time.Millisecond, 0.3}, {30 * time.Millisecond, 0.2}},
	},
	"http2-api": {
		Name: "HTTP/2 API",
		PacketSizes: []PacketSizeDist{{200, 0.2}, {500, 0.3}, {1000, 0.3}, {1500, 0.2}},
		Delays:      []DelayDist{{5 * time.Millisecond, 0.3}, {10 * time.Millisecond, 0.4}, {15 * time.Millisecond, 0.3}},
	},
	"zoom": {
		Name: "Zoom",
		PacketSizes: []PacketSizeDist{{500, 0.3}, {600, 0.4}, {700, 0.3}},
		Delays:      []DelayDist{{30 * time.Millisecond, 0.4}, {40 * time.Millisecond, 0.4}, {50 * time.Millisecond, 0.2}},
	},
}

var DefaultProfile = DefaultProfiles["http2-api"]

func (p *TrafficProfile) GetPacketSize() int {
	if p == nil {
		return 1200
	}

	p.mu.Lock()
	if p.nextSize > 0 {
		val := p.nextSize
		p.nextSize = 0
		p.mu.Unlock()
		return val
	}
	p.mu.Unlock()

	spin := mrand.Float64()
	var threshold float64

	for _, dist := range p.PacketSizes {
		threshold += dist.Weight
		if spin <= threshold {
			return dist.Size
		}
	}

	if sz := len(p.PacketSizes); sz > 0 {
		return p.PacketSizes[sz-1].Size
	}
	return 1200
}

func (p *TrafficProfile) GetDelay() time.Duration {
	if p == nil {
		return 10 * time.Millisecond
	}

	p.mu.Lock()
	if p.nextDelay > 0 {
		val := p.nextDelay
		p.nextDelay = 0
		p.mu.Unlock()
		return val
	}
	p.mu.Unlock()

	spin := mrand.Float64()
	var threshold float64

	for _, dist := range p.Delays {
		threshold += dist.Weight
		if spin <= threshold {
			return dist.Delay
		}
	}

	if sz := len(p.Delays); sz > 0 {
		return p.Delays[sz-1].Delay
	}
	return 10 * time.Millisecond
}

func (p *TrafficProfile) SetNextPacketSize(sz int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.nextSize = sz
	p.mu.Unlock()
}

func (p *TrafficProfile) SetNextDelay(dur time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.nextDelay = dur
	p.mu.Unlock()
}

func (p *TrafficProfile) ApplyMorphing(chunk []byte) ([]byte, time.Duration) {
	if p == nil {
		return chunk, 0
	}

	goalSize := p.GetPacketSize()
	waitDur := p.GetDelay()

	if len(chunk) >= goalSize {
		return chunk[:goalSize], waitDur
	}

	buffer := make([]byte, goalSize)
	copy(buffer, chunk)
	
	mrand.Read(buffer[len(chunk):])

	return buffer, waitDur
}

func (h *Handler) getProfile(pol string) *TrafficProfile {
	if pol != "" {
		if matched, exists := DefaultProfiles[pol]; exists && matched != nil {
			return matched
		}
	}
	return DefaultProfile
}

func (h *Handler) handleControlFrame(frm *Frame, prof *TrafficProfile) {
	if prof == nil {
		return
	}

	switch frm.Type {
	case FrameTypePadding:
		if len(frm.Payload) >= 2 {
			prof.SetNextPacketSize(int(binary.BigEndian.Uint16(frm.Payload)))
		}
	case FrameTypeTiming:
		if len(frm.Payload) >= 8 {
			prof.SetNextDelay(time.Duration(binary.BigEndian.Uint64(frm.Payload)) * time.Millisecond)
		}
	}
}

func orderSizesAscending(dists []PacketSizeDist) {
	sort.Slice(dists, func(a, b int) bool {
		return dists[a].Size < dists[b].Size
	})
}

func init() {
	for _, prof := range DefaultProfiles {
		if prof != nil {
			orderSizesAscending(prof.PacketSizes)
		}
	}
	if DefaultProfile != nil {
		orderSizesAscending(DefaultProfile.PacketSizes)
	}
}