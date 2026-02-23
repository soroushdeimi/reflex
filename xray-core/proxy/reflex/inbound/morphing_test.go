package inbound

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTrafficProfile(t *testing.T) {
	profile := GetProfileByName("youtube")
	if profile == nil {
		t.Fatal("should get YouTube profile")
	}

	if profile.Name != "YouTube" {
		t.Fatal("profile name mismatch")
	}

	if len(profile.PacketSizes) == 0 {
		t.Fatal("profile should have packet sizes")
	}

	if len(profile.Delays) == 0 {
		t.Fatal("profile should have delays")
	}
}

func TestGetPacketSize(t *testing.T) {
	profile := GetProfileByName("youtube")
	if profile == nil {
		t.Fatal("should get profile")
	}

	// Test multiple calls - should return valid sizes
	for i := 0; i < 100; i++ {
		size := profile.GetPacketSize()
		if size <= 0 {
			t.Fatal("packet size should be positive")
		}
		if size > 65535 {
			t.Fatal("packet size should be reasonable")
		}
	}
}

func TestGetDelay(t *testing.T) {
	profile := GetProfileByName("youtube")
	if profile == nil {
		t.Fatal("should get profile")
	}

	// Test multiple calls - should return valid delays
	for i := 0; i < 100; i++ {
		delay := profile.GetDelay()
		if delay < 0 {
			t.Fatal("delay should be non-negative")
		}
		if delay > 1*time.Second {
			t.Fatal("delay should be reasonable")
		}
	}
}

func TestSetNextPacketSize(t *testing.T) {
	profile := GetProfileByName("youtube")
	if profile == nil {
		t.Fatal("should get profile")
	}

	// Set override
	targetSize := 1500
	profile.SetNextPacketSize(targetSize)

	// Get should return override
	size := profile.GetPacketSize()
	if size != targetSize {
		t.Fatal("should return overridden packet size")
	}

	// Next call should use distribution again
	_ = profile.GetPacketSize()
	if profile.nextPacketSize != 0 {
		t.Fatal("packet size override should be reset after one read")
	}
}

func TestSetNextDelay(t *testing.T) {
	profile := GetProfileByName("youtube")
	if profile == nil {
		t.Fatal("should get profile")
	}

	// Set override
	targetDelay := 50 * time.Millisecond
	profile.SetNextDelay(targetDelay)

	// Get should return override
	delay := profile.GetDelay()
	if delay != targetDelay {
		t.Fatal("should return overridden delay")
	}

	// Next call should use distribution again
	_ = profile.GetDelay()
	if profile.nextDelay != 0 {
		t.Fatal("delay override should be reset after one read")
	}
}

func TestAddPadding(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Test with small data
	smallData := []byte("test")
	targetSize := 100
	padded := session.AddPadding(smallData, targetSize)

	if len(padded) != targetSize {
		t.Fatalf("padded data should be %d bytes, got %d", targetSize, len(padded))
	}

	// Original data should be at the beginning
	if !bytes.Equal(padded[:len(smallData)], smallData) {
		t.Fatal("original data should be preserved")
	}

	// Test with data larger than target
	largeData := make([]byte, 200)
	copy(largeData[:4], []byte("test"))
	truncated := session.AddPadding(largeData, targetSize)

	if len(truncated) != targetSize {
		t.Fatalf("truncated data should be %d bytes, got %d", targetSize, len(truncated))
	}
}

func TestWriteFrameWithMorphing(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	profile := GetProfileByName("youtube")
	if profile == nil {
		t.Fatal("should get profile")
	}

	testData := []byte("test data")
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write frame with morphing
	go func() {
		defer clientConn.Close()
		if err := session.WriteFrameWithMorphing(clientConn, FrameTypeData, testData, profile); err != nil {
			t.Errorf("failed to write frame: %v", err)
		}
	}()

	// Read frame
	frame, err := session.ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}

	// Verify frame type
	if frame.Type != FrameTypeData {
		t.Fatal("frame type mismatch")
	}

	// Note: With morphing, the payload might be padded
	// So we check that original data is contained
	if !bytes.Contains(frame.Payload, testData) {
		t.Fatal("original data should be in payload")
	}
}

func TestHandleControlFrame(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	profile := GetProfileByName("youtube")
	if profile == nil {
		t.Fatal("should get profile")
	}

	// Test PADDING control frame
	paddingFrame := &Frame{
		Type:    FrameTypePadding,
		Payload: make([]byte, 2),
	}
	paddingFrame.Payload[0] = 0x05 // size high
	paddingFrame.Payload[1] = 0xDC // size low (1500)

	session.HandleControlFrame(paddingFrame, profile)

	// Verify override was set
	size := profile.GetPacketSize()
	if size != 1500 {
		t.Fatalf("expected size override 1500, got %d", size)
	}

	// Test TIMING control frame
	timingFrame := &Frame{
		Type:    FrameTypeTiming,
		Payload: make([]byte, 8),
	}
	// Set delay to 50ms
	delayMs := uint64(50)
	timingFrame.Payload[0] = byte(delayMs >> 56)
	timingFrame.Payload[1] = byte(delayMs >> 48)
	timingFrame.Payload[2] = byte(delayMs >> 40)
	timingFrame.Payload[3] = byte(delayMs >> 32)
	timingFrame.Payload[4] = byte(delayMs >> 24)
	timingFrame.Payload[5] = byte(delayMs >> 16)
	timingFrame.Payload[6] = byte(delayMs >> 8)
	timingFrame.Payload[7] = byte(delayMs)

	session.HandleControlFrame(timingFrame, profile)

	// Verify override was set
	delay := profile.GetDelay()
	if delay != 50*time.Millisecond {
		t.Fatalf("expected delay override 50ms, got %v", delay)
	}
}

func TestProfileNotFound(t *testing.T) {
	profile := GetProfileByName("nonexistent")
	if profile != nil {
		t.Fatal("should return nil for nonexistent profile")
	}
}

func TestWriteFrameWithMorphingNoProfile(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	testData := []byte("test data")
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write frame without profile (should use regular WriteFrame)
	go func() {
		defer clientConn.Close()
		if err := session.WriteFrameWithMorphing(clientConn, FrameTypeData, testData, nil); err != nil {
			t.Errorf("failed to write frame: %v", err)
		}
	}()

	// Read frame
	frame, err := session.ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}

	// Verify payload matches (no padding)
	if !bytes.Equal(frame.Payload, testData) {
		t.Fatal("payload should match without morphing")
	}
}

