package reflex_test

import (
	"bytes"
	"io"
	"testing"
	"time"
	"github.com/xtls/xray-core/proxy/reflex"
)

func TestSessionFrames(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	s1, _ := reflex.NewSession(key1, key2)
	s2, _ := reflex.NewSession(key2, key1)

	var buf bytes.Buffer
	data := []byte("hello world")
	err := s1.WriteFrame(&buf, reflex.FrameTypeData, data)
	if err != nil {
		t.Fatal(err)
	}

	frame, err := s2.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if frame.Type != reflex.FrameTypeData {
		t.Errorf("expected frame type %d, got %d", reflex.FrameTypeData, frame.Type)
	}

	if !bytes.Equal(frame.Payload, data) {
		t.Errorf("expected payload %s, got %s", string(data), string(frame.Payload))
	}
}

func TestSessionMorphing(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	s1, _ := reflex.NewSession(key1, key2)
	s2, _ := reflex.NewSession(key2, key1)

	var buf bytes.Buffer
	data := []byte("short")
	profile := reflex.Profiles["youtube"]

	err := s1.WriteFrameWithMorphing(&buf, reflex.FrameTypeData, data, profile)
	if err != nil {
		t.Fatal(err)
	}

	frame, err := s2.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if frame.Type != reflex.FrameTypeData {
		t.Errorf("expected frame type %d, got %d", reflex.FrameTypeData, frame.Type)
	}

	if len(frame.Payload) < len(data) {
		t.Errorf("payload too short")
	}

	if !bytes.Equal(frame.Payload[:len(data)], data) {
		t.Errorf("original data corrupted")
	}
}

func TestSessionErrorCases(t *testing.T) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key, key)

	// Short header
	shortBuf := bytes.NewBuffer([]byte{0x01})
	_, err := s.ReadFrame(shortBuf)
	if err == nil {
		t.Error("expected error for short header")
	}

	// Invalid payload length
	invalidBuf := bytes.NewBuffer([]byte{0x00, 0x10, 0x01}) // length 16, but empty buffer
	_, err = s.ReadFrame(invalidBuf)
	if err == nil {
		t.Error("expected error for missing payload")
	}
}

func TestLargeDataMorphing(t *testing.T) {
	key := make([]byte, 32)
	s1, _ := reflex.NewSession(key, key)
	s2, _ := reflex.NewSession(key, key)

	// Profile with small packet size to force chunking
	p := &reflex.TrafficProfile{
		Name: "small",
		PacketSizes: []reflex.PacketSizeDist{{Size: 100, Weight: 1.0}},
		Delays: []reflex.DelayDist{{Delay: time.Microsecond, Weight: 1.0}},
	}

	data := make([]byte, 250) // Should result in several frames
	var buf bytes.Buffer
	err := s1.WriteFrameWithMorphing(&buf, reflex.FrameTypeData, data, p)
	if err != nil {
		t.Fatal(err)
	}

	// Read back frames
	for buf.Len() > 0 {
		frame, err := s2.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("failed to read frame: %v", err)
		}
		if frame.Type != reflex.FrameTypeData {
			t.Error("wrong frame type")
		}
	}
}

func TestTrafficProfiles(t *testing.T) {
	p := reflex.Profiles["youtube"]
	if p == nil {
		t.Fatal("youtube profile not found")
	}

	size := p.GetPacketSize()
	if size <= 0 {
		t.Error("invalid packet size from profile")
	}

	delay := p.GetDelay()
	if delay < 0 {
		t.Error("invalid delay from profile")
	}
}

func TestMorphingStatistics(t *testing.T) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key, key)
	profile := reflex.Profiles["youtube"]

	counts := make(map[int]int)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		var buf bytes.Buffer
		data := []byte("test")
		s.WriteFrameWithMorphing(&buf, reflex.FrameTypeData, data, profile)
		// Frame size is buf.Len()
		counts[buf.Len()]++
	}

	expectedSizes := []int{1450, 1200, 800}
	totalFound := 0
	for _, size := range expectedSizes {
		count := counts[size]
		totalFound += count
		if count == 0 {
			t.Errorf("size %d not found in distribution", size)
		}
	}

	if totalFound != iterations {
		t.Errorf("expected total iterations %d, got %d", iterations, totalFound)
	}

	t.Logf("Morphing Statistics: %v", counts)
}

func TestWriteFrameWithPadding(t *testing.T) {
	key := make([]byte, 32)
	s1, _ := reflex.NewSession(key, key)
	s2, _ := reflex.NewSession(key, key)

	var buf bytes.Buffer
	data := []byte("test data")
	paddingLen := 100
	err := s1.WriteFrameWithPadding(&buf, reflex.FrameTypeData, data, paddingLen)
	if err != nil {
		t.Fatal(err)
	}

	// Read it back
	frame, err := s2.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(frame.Payload, data) {
		t.Errorf("expected %s, got %s", string(data), string(frame.Payload))
	}
}

func TestCloseFrame(t *testing.T) {
	key := make([]byte, 32)
	s1, _ := reflex.NewSession(key, key)
	s2, _ := reflex.NewSession(key, key)

	var buf bytes.Buffer
	s1.WriteFrame(&buf, reflex.FrameTypeClose, nil)

	frame, _ := s2.ReadFrame(&buf)
	if frame.Type != reflex.FrameTypeClose {
		t.Error("expected close frame")
	}
}

func TestTrafficProfileOverrides(t *testing.T) {
	p := &reflex.TrafficProfile{
		Name: "test",
		PacketSizes: []reflex.PacketSizeDist{{Size: 100, Weight: 1.0}},
		Delays: []reflex.DelayDist{{Delay: time.Second, Weight: 1.0}},
	}

	p.SetNextPacketSize(500)
	if p.GetPacketSize() != 500 {
		t.Error("packet size override failed")
	}
	if p.GetPacketSize() != 100 {
		t.Error("packet size reset failed")
	}

	p.SetNextDelay(time.Millisecond)
	if p.GetDelay() != time.Millisecond {
		t.Error("delay override failed")
	}
	if p.GetDelay() != time.Second {
		t.Error("delay reset failed")
	}
}

func TestControlFrames(t *testing.T) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key, key)
	p := &reflex.TrafficProfile{
		Name: "test",
		PacketSizes: []reflex.PacketSizeDist{{Size: 100, Weight: 1.0}},
		Delays: []reflex.DelayDist{{Delay: time.Second, Weight: 1.0}},
	}

	// Test Padding Control
	var buf bytes.Buffer
	s.SendPaddingControl(&buf, 500)
	frame, _ := s.ReadFrame(&buf)
	s.HandleControlFrame(frame, p)
	if p.GetPacketSize() != 500 {
		t.Error("padding control frame failed to update profile")
	}

	// Test Timing Control
	buf.Reset()
	s.SendTimingControl(&buf, 10*time.Millisecond)
	frame, _ = s.ReadFrame(&buf)
	s.HandleControlFrame(frame, p)
	if p.GetDelay() != 10*time.Millisecond {
		t.Error("timing control frame failed to update profile")
	}
}

func BenchmarkWriteFrame(b *testing.B) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key, key)
	data := make([]byte, 4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.WriteFrame(io.Discard, reflex.FrameTypeData, data)
	}
}

func BenchmarkReadFrame(b *testing.B) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key, key)
	data := make([]byte, 4096)
	var buf bytes.Buffer
	session.WriteFrame(&buf, reflex.FrameTypeData, data)
	frameData := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(frameData)
		_, _ = session.ReadFrame(reader)
		session.ResetReadNonce()
	}
}

func BenchmarkWriteFrameWithMorphingStreaming(b *testing.B) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key, key)
	data := make([]byte, 1024*1024) // 1MB
	profile := reflex.Profiles["streaming"]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.WriteFrameWithMorphing(io.Discard, reflex.FrameTypeData, data, profile)
	}
}
