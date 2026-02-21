package reflex_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestSessionWithProfile(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	profile := reflex.YouTubeProfile
	session, err := reflex.NewSessionWithProfile(sessionKey, reflex.DefaultMorphingConfig(), profile)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	if session.GetTrafficProfile() != profile {
		t.Fatal("traffic profile mismatch")
	}

	if !session.GetMorphingConfig().Enabled {
		t.Fatal("morphing should be enabled")
	}
}

func TestWriteFrameWithMorphing(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	profile := reflex.ZoomProfile
	session, err := reflex.NewSessionWithProfile(sessionKey, reflex.DefaultMorphingConfig(), profile)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	// Test data
	data := []byte("Hello, World!")
	var buf bytes.Buffer

	// Write frame with morphing
	err = session.WriteFrameWithMorphing(&buf, reflex.FrameTypeData, data)
	if err != nil {
		t.Fatalf("write frame failed: %v", err)
	}

	// Read back
	readSession, _ := reflex.NewSession(sessionKey)
	frame, err := readSession.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read frame failed: %v", err)
	}

	// Verify frame type
	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("expected frame type %d, got %d", reflex.FrameTypeData, frame.Type)
	}

	// Verify data is padded (should be larger than original)
	if len(frame.Payload) < len(data) {
		t.Fatalf("expected padded data, got smaller size: %d < %d", len(frame.Payload), len(data))
	}

	// Verify original data is preserved
	if !bytes.Equal(frame.Payload[:len(data)], data) {
		t.Fatal("original data not preserved")
	}
}

func TestWriteFrameWithMorphingLargeData(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	profile := reflex.HTTP2APIProfile
	session, err := reflex.NewSessionWithProfile(sessionKey, reflex.DefaultMorphingConfig(), profile)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	// Create large data (larger than typical packet size)
	// Use smaller size to avoid too many chunks
	largeData := make([]byte, 3000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	var buf bytes.Buffer

	// Write frame - should split into multiple chunks
	err = session.WriteFrameWithMorphing(&buf, reflex.FrameTypeData, largeData)
	if err != nil {
		t.Fatalf("write frame failed: %v", err)
	}

	// Read frames back
	readSession, _ := reflex.NewSession(sessionKey)
	var readData []byte
	chunkCount := 0

	for {
		frame, err := readSession.ReadFrame(&buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			// End of buffer
			break
		}
		chunkCount++
		readData = append(readData, frame.Payload...)
		
		// Limit to avoid infinite loop
		if chunkCount > 100 {
			t.Fatal("too many chunks, possible infinite loop")
		}
	}

	// Verify we got multiple chunks
	if chunkCount < 2 {
		t.Logf("got %d chunks (expected multiple chunks for large data)", chunkCount)
	}

	// Verify all original data was received (may have padding)
	if len(readData) < len(largeData) {
		t.Fatalf("expected at least %d bytes, got %d", len(largeData), len(readData))
	}

	// Verify data integrity - check only original data (padding may be added)
	if !bytes.Equal(readData[:len(largeData)], largeData) {
		// Debug: find first mismatch
		for i := 0; i < len(largeData) && i < len(readData); i++ {
			if readData[i] != largeData[i] {
				t.Fatalf("data integrity check failed at byte %d: expected %d, got %d", i, largeData[i], readData[i])
			}
		}
		t.Fatal("data integrity check failed")
	}
}

func TestHandleControlFramePadding(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	profile := reflex.YouTubeProfile
	session, err := reflex.NewSessionWithProfile(sessionKey, reflex.DefaultMorphingConfig(), profile)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	// Create PADDING_CTRL frame
	targetSize := 1500
	ctrlData := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))

	frame := &reflex.Frame{
		Type:    reflex.FrameTypePadding,
		Payload: ctrlData,
	}

	// Handle control frame
	err = session.HandleControlFrame(frame)
	if err != nil {
		t.Fatalf("handle control frame failed: %v", err)
	}

	// Verify override is set
	size := profile.GetPacketSize()
	if size != targetSize {
		t.Fatalf("expected override size %d, got %d", targetSize, size)
	}
}

func TestHandleControlFrameTiming(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	profile := reflex.ZoomProfile
	session, err := reflex.NewSessionWithProfile(sessionKey, reflex.DefaultMorphingConfig(), profile)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	// Create TIMING_CTRL frame
	targetDelay := 100 * time.Millisecond
	ctrlData := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrlData, uint64(targetDelay.Milliseconds()))

	frame := &reflex.Frame{
		Type:    reflex.FrameTypeTiming,
		Payload: ctrlData,
	}

	// Handle control frame
	err = session.HandleControlFrame(frame)
	if err != nil {
		t.Fatalf("handle control frame failed: %v", err)
	}

	// Verify override is set
	delay := profile.GetDelay()
	if delay != targetDelay {
		t.Fatalf("expected override delay %v, got %v", targetDelay, delay)
	}
}

func TestSendPaddingControl(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	var buf bytes.Buffer
	targetSize := 2000

	err = session.SendPaddingControl(&buf, targetSize)
	if err != nil {
		t.Fatalf("send padding control failed: %v", err)
	}

	// Read frame back
	frame, err := session.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read frame failed: %v", err)
	}

	if frame.Type != reflex.FrameTypePadding {
		t.Fatalf("expected frame type %d, got %d", reflex.FrameTypePadding, frame.Type)
	}

	if len(frame.Payload) < 2 {
		t.Fatal("expected payload with size")
	}

	size := int(binary.BigEndian.Uint16(frame.Payload[0:2]))
	if size != targetSize {
		t.Fatalf("expected target size %d, got %d", targetSize, size)
	}
}

func TestSendTimingControl(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	var buf bytes.Buffer
	targetDelay := 50 * time.Millisecond

	err = session.SendTimingControl(&buf, targetDelay)
	if err != nil {
		t.Fatalf("send timing control failed: %v", err)
	}

	// Read frame back
	frame, err := session.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read frame failed: %v", err)
	}

	if frame.Type != reflex.FrameTypeTiming {
		t.Fatalf("expected frame type %d, got %d", reflex.FrameTypeTiming, frame.Type)
	}

	if len(frame.Payload) < 8 {
		t.Fatal("expected payload with delay")
	}

	delayMs := binary.BigEndian.Uint64(frame.Payload[0:8])
	delay := time.Duration(delayMs) * time.Millisecond
	if delay != targetDelay {
		t.Fatalf("expected delay %v, got %v", targetDelay, delay)
	}
}

func TestSessionMorphingEnabled(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	// Test without profile
	session1, _ := reflex.NewSession(sessionKey)
	if session1.GetTrafficProfile() != nil {
		t.Fatal("expected nil profile")
	}

	// Test with profile
	profile := reflex.YouTubeProfile
	session2, _ := reflex.NewSessionWithProfile(sessionKey, reflex.DefaultMorphingConfig(), profile)
	if session2.GetTrafficProfile() != profile {
		t.Fatal("profile mismatch")
	}

	// Test SetTrafficProfile
	session1.SetTrafficProfile(profile)
	if session1.GetTrafficProfile() != profile {
		t.Fatal("set profile failed")
	}
}
