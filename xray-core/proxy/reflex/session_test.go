package reflex

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryption(t *testing.T) {
	// 1. Generate a random key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// 2. Create the Session
	session, err := NewSession(key)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// 3. Create a Pipe to simulate a network connection
	// reader is what we "read" from the wire
	// writer is what we "write" to the wire
	reader, writer := io.Pipe()

	// 4. Define Test Data
	originalPayload := []byte("Hello Reflex Protocol!")
	// FrameTypeData is defined in your session.go
	originalType := uint8(FrameTypeData)

	// 5. Test Writing (Encryption)
	// We run this in a goroutine to prevent the pipe from blocking (deadlock)
	go func() {
		defer writer.Close()
		// WriteFrame handles the nonce and encryption internally
		err := session.WriteFrame(writer, originalType, originalPayload)
		if err != nil {
			t.Errorf("WriteFrame failed: %v", err)
		}
	}()

	// 6. Test Reading (Decryption)
	// ReadFrame reads from the pipe, decrypts, and returns the frame
	receivedFrame, err := session.ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	// 7. Verify the results
	if receivedFrame.Type != originalType {
		t.Errorf("Type mismatch. Expected %d, got %d", originalType, receivedFrame.Type)
	}

	if !bytes.Equal(receivedFrame.Payload, originalPayload) {
		t.Errorf("Payload mismatch.\nExpected: %s\nGot:      %s", originalPayload, receivedFrame.Payload)
	}
}

// --- Replay Protection Test ---

func TestReplayProtection(t *testing.T) {
	// 1. Setup Session
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)

	// 2. Create a valid encrypted frame (Simulating a captured packet)
	data := []byte("Sensitive Request")
	buf := new(bytes.Buffer)
	
	// Encrypts with Nonce 0, then increments WriteNonce to 1
	if err := session.WriteFrame(buf, FrameTypeData, data); err != nil {
		t.Fatalf("Failed to write frame: %v", err)
	}
	capturedPacket := buf.Bytes()

	// 3. First Attempt: Legitimate Decryption
	// The session expects Nonce 0. The packet has Nonce 0. -> Success
	reader1 := bytes.NewReader(capturedPacket)
	if _, err := session.ReadFrame(reader1); err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	// 4. Second Attempt: Replay Attack
	// The session now expects Nonce 1 (it incremented after the first read).
	// We feed it the SAME packet (which was encrypted with Nonce 0).
	reader2 := bytes.NewReader(capturedPacket)
	_, err := session.ReadFrame(reader2)

	// 5. Verify Rejection
	if err == nil {
		t.Fatal("Security Failure: Replay attack succeeded! The server accepted the same frame twice.")
	} else {
		t.Logf("Success: Replay attack blocked with error: %v", err)
	}
}

// --- Edge Case Tests ---

func TestEmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)
	buf := new(bytes.Buffer)

	// Test sending 0 bytes
	emptyData := []byte{}
	if err := session.WriteFrame(buf, FrameTypeData, emptyData); err != nil {
		t.Fatalf("Failed to write empty frame: %v", err)
	}

	reader := bytes.NewReader(buf.Bytes())
	frame, err := session.ReadFrame(reader)
	if err != nil {
		t.Fatalf("Failed to read empty frame: %v", err)
	}

	if len(frame.Payload) != 0 {
		t.Errorf("Expected 0 bytes, got %d", len(frame.Payload))
	}
}

func TestLargeData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)
	
	// Create a large payload (e.g., 60KB)
	// Max uint16 is 65535, so we test near the limit
	largeSize := 60 * 1024 
	largeData := make([]byte, largeSize)
	rand.Read(largeData)

	buf := new(bytes.Buffer)
	if err := session.WriteFrame(buf, FrameTypeData, largeData); err != nil {
		t.Fatalf("Failed to write large frame: %v", err)
	}

	reader := bytes.NewReader(buf.Bytes())
	frame, err := session.ReadFrame(reader)
	if err != nil {
		t.Fatalf("Failed to read large frame: %v", err)
	}

	if len(frame.Payload) != largeSize {
		t.Errorf("Size mismatch. Expected %d, got %d", largeSize, len(frame.Payload))
	}
}
// --- Performance Benchmarks ---

func BenchmarkEncryption(b *testing.B) {
	// Setup
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)

	// Create a 4KB chunk of data
	data := make([]byte, 4096)
	rand.Read(data)
	buf := new(bytes.Buffer)
	buf.Grow(5000) // Pre-allocate memory

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		// Test standard encryption speed
		if err := session.WriteFrame(buf, FrameTypeData, data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMorphingYouTube(b *testing.B) {
	// Setup
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)
	
	data := make([]byte, 100) // Small data to trigger padding
	buf := new(bytes.Buffer)
	buf.Grow(2000)
	
	// We test the YouTube profile
	profile := &YouTubeProfile

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		// Test how fast we can morph/pad packets
		// Note: This involves random number generation, so it will be slower than raw encryption
		if err := session.WriteFrameWithMorphing(buf, FrameTypeData, data, profile); err != nil {
			b.Fatal(err)
		}
	}
}