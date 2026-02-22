package reflex

import (
	"net"
	"testing"
	"time"
)

func TestSession_ControlFrames_ApplyToProfile(t *testing.T) {
	// same session key on both sides
	var key [32]byte
	for i := range key {
		key[i] = byte(0x42 + i)
	}

	s1, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	_ = c1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))

	profile := CloneProfile("http2-api")
	if profile == nil {
		t.Fatal("profile not found")
	}

	readOne := func() *Frame {
		ch := make(chan *Frame, 1)
		ech := make(chan error, 1)

		go func() {
			f, err := s2.ReadFrame(c2)
			if err != nil {
				ech <- err
				return
			}
			ch <- f
		}()

		select {
		case f := <-ch:
			return f
		case err := <-ech:
			t.Fatalf("ReadFrame err: %v", err)
			return nil
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for frame")
			return nil
		}
	}

	// ---- Padding control ----
	go func() {
		_ = s1.SendPaddingControl(c1, 321)
	}()
	f1 := readOne()
	s2.HandleControlFrame(f1, profile)

	if got := profile.GetPacketSize(); got != 321 {
		t.Fatalf("packet size override mismatch: got=%d want=%d", got, 321)
	}

	// ---- Timing control ----
	wantDelay := 12 * time.Millisecond
	go func() {
		_ = s1.SendTimingControl(c1, wantDelay)
	}()
	f2 := readOne()
	s2.HandleControlFrame(f2, profile)

	if got := profile.GetDelay(); got != wantDelay {
		t.Fatalf("delay override mismatch: got=%v want=%v", got, wantDelay)
	}
}
