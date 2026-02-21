package inbound

import (
	"bytes"
	"testing"
	"time"
)

func TestTrafficProfileOverrides(t *testing.T) {
	p := profileFromPolicy("http2-api")
	p.SetNextPacketSize(777)
	if got := p.GetPacketSize(); got != 777 {
		t.Fatalf("unexpected override packet size: %d", got)
	}
	p.SetNextDelay(42 * time.Millisecond)
	if got := p.GetDelay(); got != 42*time.Millisecond {
		t.Fatalf("unexpected override delay: %v", got)
	}
}

func TestHandleControlFrame(t *testing.T) {
	s, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}
	s.SetTrafficProfile(profileFromPolicy("http2-api"))

	if err := s.HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: []byte{0x03, 0xE8}}); err != nil {
		t.Fatal(err)
	}
	if got := s.profile.GetPacketSize(); got != 1000 {
		t.Fatalf("expected 1000 override, got %d", got)
	}

	payload := make([]byte, 8)
	payload[7] = 25
	if err := s.HandleControlFrame(&Frame{Type: FrameTypeTiming, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if got := s.profile.GetDelay(); got != 25*time.Millisecond {
		t.Fatalf("expected 25ms override, got %v", got)
	}
}

func TestWriteFrameWithMorphingSendsControlFrames(t *testing.T) {
	writerSession, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}
	profile := &TrafficProfile{
		Name:        "test",
		PacketSizes: []PacketSizeDist{{Size: 5, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 0, Weight: 1.0}},
	}
	writerSession.SetTrafficProfile(profile)

	readerSession, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	if err := writerSession.WriteFrameWithMorphing(&wire, FrameTypeData, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	f1, err := readerSession.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if f1.Type != FrameTypeData {
		t.Fatalf("first frame type = %d", f1.Type)
	}

	f2, err := readerSession.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if f2.Type != FrameTypePadding {
		t.Fatalf("second frame type = %d", f2.Type)
	}
	if len(f2.Payload) != 2 {
		t.Fatalf("unexpected padding ctrl length: %d", len(f2.Payload))
	}
}

func TestCreateProfileFromObservations(t *testing.T) {
	p, err := CreateProfileFromObservations("capture", []int{100, 100, 200}, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "capture" {
		t.Fatalf("unexpected profile name: %s", p.Name)
	}
	if len(p.PacketSizes) != 2 {
		t.Fatalf("unexpected packet distribution count: %d", len(p.PacketSizes))
	}
	if len(p.Delays) != 2 {
		t.Fatalf("unexpected delay distribution count: %d", len(p.Delays))
	}
}
