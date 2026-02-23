package reflex

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestDestinationParser(t *testing.T) {
	// Targets ParseDestFromPayload (currently 0.0%)
	// Format: [Type(1)] [Addr] [Port(2)]
	cases := []struct {
		name string
		raw  []byte
	}{
		{"IPv4", append(append([]byte{1}, net.ParseIP("1.1.1.1").To4()...), 0, 80)},
		{"Domain", append(append([]byte{2, 6}, []byte("google")...), 1, 187)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseDestFromPayload(tc.raw)
			if err != nil {
				t.Errorf("Failed to parse %s: %v", tc.name, err)
			}
		})
	}
}

func TestControlFrames(t *testing.T) {
	// Targets SendPaddingControl, SendTimingControl, and HandleControlFrame (currently 0.0%)
	sess, _ := NewSession(make([]byte, 32))
	buf := new(bytes.Buffer)
	profile := &YouTubeProfile

	// 1. Test Padding Control
	_ = sess.SendPaddingControl(buf, 1200)
	frame, _ := sess.ReadFrame(buf)
	sess.HandleControlFrame(frame, profile)

	// 2. Test Timing Control
	buf.Reset()
	_ = sess.SendTimingControl(buf, 50*time.Millisecond)
	frame, _ = sess.ReadFrame(buf)
	sess.HandleControlFrame(frame, profile)

	// 3. Test Traffic Profile Overrides (targets SetNext...)
	profile.SetNextPacketSize(900)
	profile.SetNextDelay(10 * time.Millisecond)
	if profile.GetPacketSize() != 900 || profile.GetDelay() != 10*time.Millisecond {
		t.Error("Overrides failed")
	}
}
