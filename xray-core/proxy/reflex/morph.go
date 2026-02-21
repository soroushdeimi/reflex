package reflex

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	mrand "math/rand"
	"sync"
	"time"
)

// TrafficProfile defines a statistical model of a target protocol's traffic
// characteristics. Morphing adapts Reflex frame sizes and inter-packet delays
// to match the target profile, making the encrypted tunnel statistically
// indistinguishable from the imitated application.
type TrafficProfile struct {
	Name           string
	PacketSizes    []PacketSizeDist
	Delays         []DelayDist
	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

// PacketSizeDist pairs a packet size (bytes) with its probability weight.
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist pairs an inter-packet delay with its probability weight.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// BuiltinProfiles contains traffic profiles derived from published network
// traffic characterization studies.
//
// YouTube: Based on MPEG-DASH streaming analysis (IMC 2017, IEEE Access 2022).
//   Video chunks are sent in bursts near MTU size, interspersed with smaller
//   audio/control packets. The bursty on-off pattern creates characteristic
//   inter-packet delay distributions.
//
// Zoom: Based on passive measurement studies (IMC 2022, ICPE 2023, PAM 2022).
//   Video conferencing uses smaller, regular-interval packets. Audio frames
//   arrive at ~20ms intervals; video at ~33ms (30fps). Packet sizes cluster
//   around 200-700 bytes with a secondary mode at MTU for screen sharing.
//
// Netflix: DASH-based adaptive streaming with larger initial burst segments
//   followed by steady-state playback. Similar to YouTube but with different
//   segment scheduling and buffer management strategies.
//
// HTTP2API: REST-over-HTTP/2 workloads exhibit small request frames (HEADERS +
//   short DATA) and variable response payloads, with irregular timing driven
//   by user interaction patterns.
//
// Discord: Voice-over-IP traffic uses small, fixed-interval Opus audio frames
//   at ~20ms cadence, with occasional larger packets for video.
var BuiltinProfiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "YouTube DASH Streaming",
		PacketSizes: []PacketSizeDist{
			{Size: 1460, Weight: 0.32}, // MTU-sized video chunk segments
			{Size: 1400, Weight: 0.18}, // Near-MTU video data
			{Size: 1200, Weight: 0.14}, // Partial video segments
			{Size: 1000, Weight: 0.10}, // Mid-range video/audio mux
			{Size: 800, Weight: 0.08},  // Audio + metadata
			{Size: 500, Weight: 0.06},  // Control / manifest fetch
			{Size: 300, Weight: 0.05},  // Small HTTP/2 frames
			{Size: 150, Weight: 0.04},  // ACK / window update
			{Size: 64, Weight: 0.03},   // TCP ACK
		},
		Delays: []DelayDist{
			{Delay: 1 * time.Millisecond, Weight: 0.15},  // Intra-burst (back-to-back)
			{Delay: 3 * time.Millisecond, Weight: 0.20},  // Intra-burst spacing
			{Delay: 8 * time.Millisecond, Weight: 0.20},  // Short gap
			{Delay: 15 * time.Millisecond, Weight: 0.15}, // Video frame interval
			{Delay: 33 * time.Millisecond, Weight: 0.12}, // ~30fps boundary
			{Delay: 80 * time.Millisecond, Weight: 0.08}, // Buffer refill gap
			{Delay: 150 * time.Millisecond, Weight: 0.06},// Segment boundary
			{Delay: 500 * time.Millisecond, Weight: 0.04},// Adaptive bitrate pause
		},
	},
	"zoom": {
		Name: "Zoom Video Conference",
		PacketSizes: []PacketSizeDist{
			{Size: 160, Weight: 0.22},  // Opus audio frames (20ms)
			{Size: 250, Weight: 0.12},  // Audio + FEC
			{Size: 400, Weight: 0.10},  // Small video keyframe slice
			{Size: 550, Weight: 0.16},  // Typical video P-frame
			{Size: 700, Weight: 0.14},  // Large video frame
			{Size: 900, Weight: 0.10},  // Video I-frame slice
			{Size: 1200, Weight: 0.09}, // Screen share data
			{Size: 1460, Weight: 0.07}, // Full MTU screen share
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.10},  // Back-to-back fragments
			{Delay: 10 * time.Millisecond, Weight: 0.15}, // Intra-frame
			{Delay: 20 * time.Millisecond, Weight: 0.30}, // Audio cadence (20ms)
			{Delay: 33 * time.Millisecond, Weight: 0.25}, // Video cadence (~30fps)
			{Delay: 50 * time.Millisecond, Weight: 0.12}, // Probe / RTCP
			{Delay: 100 * time.Millisecond, Weight: 0.08},// Bandwidth adaptation
		},
	},
	"netflix": {
		Name: "Netflix DASH Streaming",
		PacketSizes: []PacketSizeDist{
			{Size: 1460, Weight: 0.38}, // Dominant: MTU-sized video
			{Size: 1380, Weight: 0.15}, // Near-MTU
			{Size: 1100, Weight: 0.12}, // Partial segment
			{Size: 800, Weight: 0.10},  // Audio segments
			{Size: 500, Weight: 0.08},  // HTTP/2 headers + small body
			{Size: 250, Weight: 0.07},  // Control frames
			{Size: 100, Weight: 0.06},  // Window updates / ACKs
			{Size: 50, Weight: 0.04},   // Keep-alive / PING
		},
		Delays: []DelayDist{
			{Delay: 1 * time.Millisecond, Weight: 0.25},  // Burst download
			{Delay: 5 * time.Millisecond, Weight: 0.20},  // Intra-segment
			{Delay: 12 * time.Millisecond, Weight: 0.15}, // Segment gap
			{Delay: 40 * time.Millisecond, Weight: 0.15}, // Frame boundary
			{Delay: 100 * time.Millisecond, Weight: 0.10},// Buffer level pause
			{Delay: 250 * time.Millisecond, Weight: 0.08},// Segment fetch interval
			{Delay: 1000 * time.Millisecond, Weight: 0.07},// Buffer full, wait
		},
	},
	"http2-api": {
		Name: "HTTP/2 REST API",
		PacketSizes: []PacketSizeDist{
			{Size: 128, Weight: 0.15},  // Small JSON responses
			{Size: 256, Weight: 0.18},  // Typical API request
			{Size: 512, Weight: 0.22},  // Medium response body
			{Size: 1024, Weight: 0.18}, // Large API response
			{Size: 1460, Weight: 0.10}, // Paginated / list responses
			{Size: 64, Weight: 0.10},   // HEADERS-only / empty body
			{Size: 32, Weight: 0.07},   // PING / WINDOW_UPDATE
		},
		Delays: []DelayDist{
			{Delay: 2 * time.Millisecond, Weight: 0.10},   // Pipelined
			{Delay: 10 * time.Millisecond, Weight: 0.15},  // Fast response
			{Delay: 50 * time.Millisecond, Weight: 0.25},  // Typical API latency
			{Delay: 100 * time.Millisecond, Weight: 0.20}, // Moderate
			{Delay: 200 * time.Millisecond, Weight: 0.15}, // Slow query
			{Delay: 500 * time.Millisecond, Weight: 0.10}, // Heavy computation
			{Delay: 1000 * time.Millisecond, Weight: 0.05},// Timeout-adjacent
		},
	},
	"discord": {
		Name: "Discord Voice/Video",
		PacketSizes: []PacketSizeDist{
			{Size: 120, Weight: 0.28},  // Opus voice (low bitrate)
			{Size: 200, Weight: 0.22},  // Opus voice (normal bitrate)
			{Size: 320, Weight: 0.15},  // Opus voice + FEC
			{Size: 500, Weight: 0.12},  // Video thumbnail / small
			{Size: 800, Weight: 0.10},  // Video frame slice
			{Size: 1200, Weight: 0.08}, // Video keyframe slice
			{Size: 1460, Weight: 0.05}, // Screen share MTU
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.08},  // Back-to-back
			{Delay: 20 * time.Millisecond, Weight: 0.40}, // Opus 20ms cadence
			{Delay: 33 * time.Millisecond, Weight: 0.22}, // Video 30fps
			{Delay: 40 * time.Millisecond, Weight: 0.15}, // Mixed
			{Delay: 60 * time.Millisecond, Weight: 0.10}, // Low activity
			{Delay: 100 * time.Millisecond, Weight: 0.05},// Idle keepalive
		},
	},
}

// GetPacketSize selects a packet size from the profile distribution, or
// returns an override if one was set by a PADDING_CTRL frame.
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}

	return sampleWeighted(p.PacketSizes)
}

// GetDelay selects an inter-packet delay from the profile distribution, or
// returns an override if one was set by a TIMING_CTRL frame.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0
		return delay
	}

	return sampleDelayWeighted(p.Delays)
}

// SetNextPacketSize overrides the next GetPacketSize call (used by PADDING_CTRL).
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

// SetNextDelay overrides the next GetDelay call (used by TIMING_CTRL).
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

// AddPadding pads data with cryptographically random bytes to reach targetSize.
// If data is already >= targetSize, it is returned as-is.
func AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padLen := targetSize - len(data)
	padding := make([]byte, padLen)
	_, _ = rand.Read(padding)
	return append(data, padding...)
}

// TrafficMorph holds the active morphing state for a session direction.
type TrafficMorph struct {
	Profile *TrafficProfile
	Enabled bool
}

// NewTrafficMorph creates a morph engine for the named profile.
// Returns nil if the profile name is empty or unknown.
func NewTrafficMorph(profileName string) *TrafficMorph {
	if profileName == "" {
		return nil
	}
	p, ok := BuiltinProfiles[profileName]
	if !ok {
		return nil
	}
	return &TrafficMorph{
		Profile: p,
		Enabled: true,
	}
}

// MorphWrite splits or pads data into profile-sized frames, applying delays.
func (m *TrafficMorph) MorphWrite(sess *Session, writer io.Writer, data []byte) error {
	if !m.Enabled || m.Profile == nil {
		return sess.WriteFrame(writer, FrameTypeData, data)
	}

	for len(data) > 0 {
		targetSize := m.Profile.GetPacketSize()

		// Account for AEAD overhead when choosing the plaintext chunk size
		overhead := sess.aead.Overhead()
		chunkSize := targetSize - overhead - FrameHeaderSize
		if chunkSize <= 0 {
			chunkSize = targetSize
		}
		if chunkSize > MaxFramePayload {
			chunkSize = MaxFramePayload
		}

		var chunk []byte
		if len(data) <= chunkSize {
			// Pad the final (or only) chunk to the target size
			chunk = AddPadding(data, chunkSize)
			data = nil
		} else {
			chunk = data[:chunkSize]
			data = data[chunkSize:]
		}

		if err := sess.WriteFrame(writer, FrameTypeData, chunk); err != nil {
			return err
		}

		delay := m.Profile.GetDelay()
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	return nil
}

// sampleWeighted picks a random size from the weighted distribution.
func sampleWeighted(dists []PacketSizeDist) int {
	if len(dists) == 0 {
		return 1400
	}

	r := mrand.Float64()
	cumsum := 0.0
	for _, d := range dists {
		cumsum += d.Weight
		if r <= cumsum {
			// Add small jitter (±5%) to avoid perfectly discrete values
			jitter := 1.0 + (mrand.Float64()-0.5)*0.1
			return int(math.Round(float64(d.Size) * jitter))
		}
	}
	return dists[len(dists)-1].Size
}

// sampleDelayWeighted picks a random delay from the weighted distribution.
func sampleDelayWeighted(dists []DelayDist) time.Duration {
	if len(dists) == 0 {
		return 10 * time.Millisecond
	}

	r := mrand.Float64()
	cumsum := 0.0
	for _, d := range dists {
		cumsum += d.Weight
		if r <= cumsum {
			// Add jitter (±20%) to avoid perfectly discrete timing
			jitter := 1.0 + (mrand.Float64()-0.5)*0.4
			return time.Duration(float64(d.Delay) * jitter)
		}
	}
	return dists[len(dists)-1].Delay
}

// EncodePaddingControl creates a PADDING_CTRL payload with the target size.
func EncodePaddingControl(targetSize int) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(targetSize))
	return data
}

// EncodeTimingControl creates a TIMING_CTRL payload with delay in milliseconds.
func EncodeTimingControl(delay time.Duration) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(delay.Milliseconds()))
	return data
}

// HandleControlFrame processes PADDING_CTRL and TIMING_CTRL frames received
// from the peer, adjusting the local morph profile accordingly.
func HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil {
		return
	}
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload))
			profile.SetNextPacketSize(targetSize)
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}
}
