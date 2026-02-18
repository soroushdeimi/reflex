package reflex

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestTrafficMorphing(t *testing.T) {
	// 1. Setup Session
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)
	
	// We will write to this buffer instead of a real network connection
	buf := new(bytes.Buffer)

	// 2. Define Input Data
	// A small message (e.g., "hello") that is much smaller than YouTube packets
	smallData := []byte("hello traffic morphing")
	
	// 3. Select a Profile (YouTube)
	// YouTube usually sends packets of 1400, 1200, 1000, or 800 bytes
	profile := &YouTubeProfile

	// 4. Send with Morphing
	// This function should add padding to make 'smallData' look like a big YouTube packet
	err := session.WriteFrameWithMorphing(buf, FrameTypeData, smallData, profile)
	if err != nil {
		t.Fatalf("Failed to write morphed frame: %v", err)
	}

	// 5. Verify the Output Size
	// The total bytes written = Header (3 bytes) + Encrypted Payload (TargetSize + 16 bytes overhead)
	totalLen := buf.Len()
	payloadLen := totalLen - 3 // Remove the 3-byte header
	
	// We expect the payload to match one of the YouTube sizes + 16 bytes (Poly1305 tag)
	// YouTube sizes defined in traffic_profile.go: 1400, 1200, 1000, 800
	validSizes := []int{1400, 1200, 1000, 800}
	
	matched := false
	for _, size := range validSizes {
		expectedLen := size + 16 // Target Size + Encryption Tag
		if payloadLen == expectedLen {
			matched = true
			t.Logf("Success! Packet morphed to %d bytes (Target %d + 16 overhead)", payloadLen, size)
			break
		}
	}

	if !matched {
		t.Errorf("Morphing Failed! Packet size %d did not match any YouTube profile targets (+16 overhead).", payloadLen)
	}
}