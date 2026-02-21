package reflex

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

func TestNewTrafficMorph(t *testing.T) {
	morph := NewTrafficMorph("youtube")
	if morph == nil {
		t.Fatal("expected non-nil TrafficMorph for 'youtube'")
	}
	if !morph.Enabled {
		t.Fatal("morph should be enabled")
	}
	if morph.Profile == nil {
		t.Fatal("profile should not be nil")
	}
	if morph.Profile.Name != "YouTube DASH Streaming" {
		t.Fatalf("unexpected profile name: %s", morph.Profile.Name)
	}
}

func TestNewTrafficMorphEmptyName(t *testing.T) {
	morph := NewTrafficMorph("")
	if morph != nil {
		t.Fatal("expected nil for empty profile name")
	}
}

func TestNewTrafficMorphUnknownProfile(t *testing.T) {
	morph := NewTrafficMorph("nonexistent-profile")
	if morph != nil {
		t.Fatal("expected nil for unknown profile name")
	}
}

func TestBuiltinProfiles(t *testing.T) {
	expectedProfiles := []string{"youtube", "zoom", "netflix", "http2-api", "discord"}
	for _, name := range expectedProfiles {
		profile, ok := BuiltinProfiles[name]
		if !ok {
			t.Fatalf("missing builtin profile: %s", name)
		}
		if len(profile.PacketSizes) == 0 {
			t.Fatalf("profile %s has no packet sizes", name)
		}
		if len(profile.Delays) == 0 {
			t.Fatalf("profile %s has no delays", name)
		}

		// Verify weights roughly sum to 1.0 (within tolerance)
		var sizeWeightSum float64
		for _, ps := range profile.PacketSizes {
			sizeWeightSum += ps.Weight
		}
		if sizeWeightSum < 0.9 || sizeWeightSum > 1.1 {
			t.Fatalf("profile %s packet size weights sum to %.2f (expected ~1.0)", name, sizeWeightSum)
		}

		var delayWeightSum float64
		for _, d := range profile.Delays {
			delayWeightSum += d.Weight
		}
		if delayWeightSum < 0.9 || delayWeightSum > 1.1 {
			t.Fatalf("profile %s delay weights sum to %.2f (expected ~1.0)", name, delayWeightSum)
		}
	}
}

func TestAddPadding(t *testing.T) {
	data := []byte("hello")
	padded := AddPadding(data, 100)

	if len(padded) != 100 {
		t.Fatalf("expected padded length 100, got %d", len(padded))
	}
	if !bytes.Equal(padded[:5], data) {
		t.Fatal("original data should be preserved at the start")
	}
}

func TestAddPaddingNoOp(t *testing.T) {
	data := make([]byte, 200)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	padded := AddPadding(data, 100)
	if !bytes.Equal(padded, data) {
		t.Fatal("data already >= target should be returned as-is")
	}
}

func TestAddPaddingExactSize(t *testing.T) {
	data := make([]byte, 50)
	padded := AddPadding(data, 50)
	if len(padded) != 50 {
		t.Fatalf("expected length 50, got %d", len(padded))
	}
}

func TestGetPacketSize(t *testing.T) {
	profile := BuiltinProfiles["youtube"]

	for i := 0; i < 100; i++ {
		size := profile.GetPacketSize()
		if size <= 0 {
			t.Fatalf("GetPacketSize returned non-positive value: %d", size)
		}
	}
}

func TestGetPacketSizeOverride(t *testing.T) {
	profile := &TrafficProfile{
		Name:        "test",
		PacketSizes: []PacketSizeDist{{Size: 500, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	profile.SetNextPacketSize(1234)
	size := profile.GetPacketSize()
	if size != 1234 {
		t.Fatalf("expected overridden size 1234, got %d", size)
	}

	// After consuming the override, it should sample from distribution
	size = profile.GetPacketSize()
	if size <= 0 {
		t.Fatalf("expected positive sampled size, got %d", size)
	}
}

func TestGetDelay(t *testing.T) {
	profile := BuiltinProfiles["zoom"]

	for i := 0; i < 100; i++ {
		delay := profile.GetDelay()
		if delay < 0 {
			t.Fatalf("GetDelay returned negative value: %v", delay)
		}
	}
}

func TestGetDelayOverride(t *testing.T) {
	profile := &TrafficProfile{
		Name:        "test",
		PacketSizes: []PacketSizeDist{{Size: 500, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	profile.SetNextDelay(42 * time.Millisecond)
	delay := profile.GetDelay()
	if delay != 42*time.Millisecond {
		t.Fatalf("expected 42ms override, got %v", delay)
	}

	// After consuming, samples from distribution
	delay = profile.GetDelay()
	if delay < 0 {
		t.Fatal("expected non-negative delay")
	}
}

func TestEncodePaddingControl(t *testing.T) {
	data := EncodePaddingControl(1024)
	if len(data) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(data))
	}
	decoded := binary.BigEndian.Uint16(data)
	if decoded != 1024 {
		t.Fatalf("expected 1024, got %d", decoded)
	}
}

func TestEncodeTimingControl(t *testing.T) {
	delay := 500 * time.Millisecond
	data := EncodeTimingControl(delay)
	if len(data) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(data))
	}
	decoded := binary.BigEndian.Uint64(data)
	if decoded != 500 {
		t.Fatalf("expected 500ms, got %d", decoded)
	}
}

func TestHandleControlFrame(t *testing.T) {
	profile := &TrafficProfile{
		Name:        "test",
		PacketSizes: []PacketSizeDist{{Size: 500, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	// Test PADDING_CTRL
	paddingPayload := EncodePaddingControl(2048)
	HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: paddingPayload}, profile)
	size := profile.GetPacketSize()
	if size != 2048 {
		t.Fatalf("expected overridden size 2048, got %d", size)
	}

	// Test TIMING_CTRL
	timingPayload := EncodeTimingControl(100 * time.Millisecond)
	HandleControlFrame(&Frame{Type: FrameTypeTiming, Payload: timingPayload}, profile)
	delay := profile.GetDelay()
	if delay != 100*time.Millisecond {
		t.Fatalf("expected 100ms delay, got %v", delay)
	}
}

func TestHandleControlFrameNilProfile(t *testing.T) {
	// Should not panic with nil profile
	HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: make([]byte, 2)}, nil)
}

func TestHandleControlFrameShortPayload(t *testing.T) {
	profile := &TrafficProfile{
		Name:        "test",
		PacketSizes: []PacketSizeDist{{Size: 500, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	// Short PADDING_CTRL (< 2 bytes) should be ignored
	HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: []byte{0x01}}, profile)

	// Short TIMING_CTRL (< 8 bytes) should be ignored
	HandleControlFrame(&Frame{Type: FrameTypeTiming, Payload: make([]byte, 4)}, profile)
}

func TestMorphWrite(t *testing.T) {
	key := makeTestSessionKey()
	writerSess, _ := NewSession(key)
	readerSess, _ := NewSession(key)

	morph := &TrafficMorph{
		Profile: &TrafficProfile{
			Name:        "test-fast",
			PacketSizes: []PacketSizeDist{{Size: 500, Weight: 1.0}},
			Delays:      []DelayDist{{Delay: 0, Weight: 1.0}}, // No delays for fast test
		},
		Enabled: true,
	}

	var buf bytes.Buffer
	data := []byte("morphed data payload for testing")

	if err := morph.MorphWrite(writerSess, &buf, data); err != nil {
		t.Fatalf("MorphWrite failed: %v", err)
	}

	// Read all frames and reassemble
	var assembled []byte
	for buf.Len() > 0 {
		frame, err := readerSess.ReadFrame(&buf)
		if err != nil {
			break
		}
		assembled = append(assembled, frame.Payload...)
	}

	// The original data should appear at the start of the assembled output
	// (may be padded)
	if len(assembled) < len(data) {
		t.Fatalf("reassembled data too short: got %d, want >= %d", len(assembled), len(data))
	}
	if !bytes.Equal(assembled[:len(data)], data) {
		t.Fatal("reassembled data does not start with original data")
	}
}

func TestMorphWriteDisabled(t *testing.T) {
	key := makeTestSessionKey()
	writerSess, _ := NewSession(key)
	readerSess, _ := NewSession(key)

	morph := &TrafficMorph{
		Profile: BuiltinProfiles["youtube"],
		Enabled: false,
	}

	var buf bytes.Buffer
	data := []byte("not morphed")

	if err := morph.MorphWrite(writerSess, &buf, data); err != nil {
		t.Fatal(err)
	}

	frame, err := readerSess.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}

	// When disabled, should be written as a single frame with exact data
	if !bytes.Equal(frame.Payload, data) {
		t.Fatal("disabled morph should write data as-is")
	}
}

func TestMorphWriteNilProfile(t *testing.T) {
	key := makeTestSessionKey()
	writerSess, _ := NewSession(key)
	readerSess, _ := NewSession(key)

	morph := &TrafficMorph{
		Profile: nil,
		Enabled: true,
	}

	var buf bytes.Buffer
	data := []byte("no profile")

	if err := morph.MorphWrite(writerSess, &buf, data); err != nil {
		t.Fatal(err)
	}

	frame, err := readerSess.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame.Payload, data) {
		t.Fatal("nil profile should write data as-is")
	}
}

func TestSampleWeightedEmptyDistribution(t *testing.T) {
	size := sampleWeighted(nil)
	if size != 1400 {
		t.Fatalf("empty distribution should return default 1400, got %d", size)
	}
}

func TestSampleDelayWeightedEmptyDistribution(t *testing.T) {
	delay := sampleDelayWeighted(nil)
	if delay != 10*time.Millisecond {
		t.Fatalf("empty distribution should return default 10ms, got %v", delay)
	}
}

func BenchmarkMorphWrite(b *testing.B) {
	key := makeTestSessionKey()
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	morph := &TrafficMorph{
		Profile: &TrafficProfile{
			Name:        "bench",
			PacketSizes: []PacketSizeDist{{Size: 1400, Weight: 1.0}},
			Delays:      []DelayDist{{Delay: 0, Weight: 1.0}},
		},
		Enabled: true,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sess, _ := NewSession(key)
		var buf bytes.Buffer
		_ = morph.MorphWrite(sess, &buf, data)
	}
}
