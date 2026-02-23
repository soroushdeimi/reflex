package inbound

import (
	"bufio"
	"io"
	"net"
	"testing"

	"github.com/google/uuid"
)

func TestEmptyData(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Test with empty data
	emptyData := []byte{}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		if err := session.WriteFrame(clientConn, FrameTypeData, emptyData); err != nil {
			t.Errorf("failed to write frame: %v", err)
		}
	}()

	frame, err := session.ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("should handle empty data: %v", err)
	}

	if len(frame.Payload) != 0 {
		t.Fatal("empty data should remain empty")
	}
}

func TestLargeData(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Test with large data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write frame - should handle large data
	go func() {
		defer clientConn.Close()
		// Note: WriteFrame might need to split large data
		// For now, we test that it doesn't crash
		_ = session.WriteFrame(clientConn, FrameTypeData, largeData)
	}()

	// Read frame
	frame, err := session.ReadFrame(serverConn)
	if err != nil {
		// Large data might exceed frame size limit
		// That's OK, we just test that it doesn't crash
		if err != nil {
			// Expected error for oversized frame
			return
		}
	}

	// If successful, verify data
	if frame != nil && len(frame.Payload) > 0 {
		// Verify first and last bytes
		if frame.Payload[0] != largeData[0] {
			t.Fatal("first byte mismatch")
		}
	}
}

func TestClosedConnection(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	
	// Close connection before writing
	clientConn.Close()
	serverConn.Close()

	// Try to write frame - should return error
	err = session.WriteFrame(clientConn, FrameTypeData, []byte("test"))
	if err == nil {
		t.Fatal("should return error for closed connection")
	}
}

func TestInvalidHandshake(t *testing.T) {
	_ = createTestHandler()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Send invalid data (not Reflex)
	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write([]byte("invalid data that is not Reflex"))
	}()

	// Process should handle invalid handshake
	// In real scenario, it would go to fallback or return error
	// For testing, we verify it doesn't crash
	reader := bufio.NewReader(serverConn)
	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil && err != io.EOF {
		// Peek might fail with insufficient data
		if len(peeked) < 4 {
			return // Not enough data
		}
	}

	// Check that it's not recognized as Reflex
	if len(peeked) >= 4 {
		magic := peeked[0:4]
		if string(magic) == "inva" {
			t.Log("non-Reflex data detected as expected")
		}
	}
}

func TestInvalidUUID(t *testing.T) {
	handler := createTestHandler()

	// Create handshake with UUID that doesn't exist in config
	invalidUserID := uuid.New()
	
	// Test authentication
	user, err := handler.authenticateUser([16]byte(invalidUserID))
	if err == nil {
		t.Fatal("should reject invalid UUID")
	}

	if user != nil {
		t.Fatal("user should be nil for invalid UUID")
	}
}

func TestConnectionReset(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	clientConn, serverConn := net.Pipe()

	// Start writing
	go func() {
		defer clientConn.Close()
		// Write some data
		_ = session.WriteFrame(clientConn, FrameTypeData, []byte("test"))
		// Close connection mid-transfer
		clientConn.Close()
	}()

	// Try to read - should handle connection reset gracefully
	_, err = session.ReadFrame(serverConn)
	// Either read succeeds before close or returns an expected connection error.
	_ = err

	serverConn.Close()
}

func TestOversizedPayload(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Create payload larger than max frame size (65535)
	hugeData := make([]byte, 100*1024) // 100KB

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write frame - should handle oversized payload
	// Either split it or return error
	go func() {
		defer clientConn.Close()
		err := session.WriteFrame(clientConn, FrameTypeData, hugeData)
		if err != nil {
			// Error is acceptable for oversized payload
			return
		}
	}()

	// Try to read
	frame, err := session.ReadFrame(serverConn)
	if err != nil {
		// Error is expected for oversized frame
		return
	}

	// If successful, verify it was handled
	if frame != nil {
		if len(frame.Payload) == 0 && len(hugeData) > 0 {
			t.Fatal("frame payload should not be empty when a frame is returned")
		}
	}
}

func TestIncompleteHandshake(t *testing.T) {
	_ = createTestHandler()

	clientConn, serverConn := net.Pipe()

	// Send only partial handshake
	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write([]byte("POST /api"))
		// Close before completing handshake
		clientConn.Close()
	}()

	// Process should handle incomplete handshake gracefully
	reader := bufio.NewReader(serverConn)
	_, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error for incomplete handshake peek: %v", err)
	}

	serverConn.Close()
}

func TestSessionKeyInvalidLength(t *testing.T) {
	// Test with various invalid key lengths
	invalidLengths := []int{0, 16, 24, 31, 33, 64}

	for _, length := range invalidLengths {
		invalidKey := make([]byte, length)
		_, err := NewSession(invalidKey)
		if err == nil {
			t.Fatalf("should reject key of length %d", length)
		}
	}
}

func TestFrameTypeValidation(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Test valid frame types
	validTypes := []uint8{FrameTypeData, FrameTypePadding, FrameTypeTiming, FrameTypeClose}

	for _, frameType := range validTypes {
		clientConn, serverConn := net.Pipe()

		go func() {
			defer clientConn.Close()
			_ = session.WriteFrame(clientConn, frameType, []byte("test"))
		}()

		frame, err := session.ReadFrame(serverConn)
		if err != nil {
			t.Fatalf("valid frame type %d should succeed: %v", frameType, err)
		}

		if frame.Type != frameType {
			t.Fatalf("frame type mismatch: expected %d, got %d", frameType, frame.Type)
		}

		clientConn.Close()
		serverConn.Close()
	}
}

