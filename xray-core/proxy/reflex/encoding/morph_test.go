package encoding

import (
	"math"
	"testing"
	"time"
)

func TestTrafficProfileOverrides(t *testing.T) {
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1200, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	profile.SetNextPacketSize(777)
	profile.SetNextDelay(23 * time.Millisecond)

	if got := profile.GetPacketSize(); got != 777 {
		t.Fatalf("GetPacketSize override = %d, want 777", got)
	}
	if got := profile.GetDelay(); got != 23*time.Millisecond {
		t.Fatalf("GetDelay override = %v, want 23ms", got)
	}
}

func TestAddPadding(t *testing.T) {
	sess := &Session{}

	out := sess.AddPadding([]byte("abc"), 8)
	if len(out) != 8 {
		t.Fatalf("AddPadding len = %d, want 8", len(out))
	}
	if string(out[:3]) != "abc" {
		t.Fatalf("AddPadding prefix = %q, want %q", string(out[:3]), "abc")
	}
}

func TestHandleControlFrame(t *testing.T) {
	profile := &TrafficProfile{}
	sess := &Session{}

	sess.HandleControlFrame(&Frame{Type: PADDING_CTRL, Payload: []byte{0x03, 0x20}}, profile)
	if got := profile.GetPacketSize(); got != 800 {
		t.Fatalf("padding control = %d, want 800", got)
	}

	sess.HandleControlFrame(&Frame{Type: TIMING_CTRL, Payload: []byte{0x00, 0x32}}, profile)
	if got := profile.GetDelay(); got != 50*time.Millisecond {
		t.Fatalf("timing control = %v, want 50ms", got)
	}
}

func TestTrafficProfileDistributionSanity(t *testing.T) {
	// Statistical check: sampled size distribution should remain close to the configured profile.
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.4},
			{Size: 1200, Weight: 0.3},
			{Size: 1000, Weight: 0.2},
			{Size: 800, Weight: 0.1},
		},
	}

	const draws = 20000
	counts := map[int]int{
		1400: 0,
		1200: 0,
		1000: 0,
		800:  0,
	}
	for i := 0; i < draws; i++ {
		counts[profile.GetPacketSize()]++
	}

	expected := map[int]float64{
		1400: 0.4,
		1200: 0.3,
		1000: 0.2,
		800:  0.1,
	}

	const tolerance = 0.03
	for size, want := range expected {
		got := float64(counts[size]) / draws
		if math.Abs(got-want) > tolerance {
			t.Fatalf("size %d frequency %.4f outside tolerance of expected %.4f", size, got, want)
		}
	}
}
