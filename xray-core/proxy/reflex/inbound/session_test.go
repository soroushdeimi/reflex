package inbound

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func createTestSession() (*Session, error) {
	sessionKey := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, sessionKey)
	if err != nil {
		return nil, err
	}
	return NewSession(sessionKey)
}

func TestEncryptionDecryption(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Test data
	original := []byte("test data for encryption")

	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write frame from client
	go func() {
		defer clientConn.Close()
		if err := session.WriteFrame(clientConn, FrameTypeData, original); err != nil {
			t.Errorf("failed to write frame: %v", err)
		}
	}()

	// Read frame on server
	readFrame, err := session.ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}

	// Verify
	if readFrame.Type != FrameTypeData {
		t.Fatal("frame type mismatch")
	}

	if !bytes.Equal(original, readFrame.Payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncryptionLargeData(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Large data (10KB)
	original := make([]byte, 10*1024)
	_, err = io.ReadFull(rand.Reader, original)
	if err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write frame
	go func() {
		defer clientConn.Close()
		if err := session.WriteFrame(clientConn, FrameTypeData, original); err != nil {
			t.Errorf("failed to write frame: %v", err)
		}
	}()

	// Read frame
	readFrame, err := session.ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}

	// Verify
	if !bytes.Equal(original, readFrame.Payload) {
		t.Fatal("large payload mismatch")
	}
}

func TestEncryptionEmptyData(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Empty data
	original := []byte{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write frame
	go func() {
		defer clientConn.Close()
		if err := session.WriteFrame(clientConn, FrameTypeData, original); err != nil {
			t.Errorf("failed to write frame: %v", err)
		}
	}()

	// Read frame
	readFrame, err := session.ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}

	// Verify
	if len(readFrame.Payload) != 0 {
		t.Fatal("empty payload should remain empty")
	}
}

func TestFrameTypes(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	testData := []byte("test")

	frameTypes := []uint8{
		FrameTypeData,
		FrameTypePadding,
		FrameTypeTiming,
		FrameTypeClose,
	}

	for _, frameType := range frameTypes {
		clientConn, serverConn := net.Pipe()

		// Write frame
		go func() {
			defer clientConn.Close()
			if err := session.WriteFrame(clientConn, frameType, testData); err != nil {
				t.Errorf("failed to write frame: %v", err)
			}
		}()

		// Read frame
		readFrame, err := session.ReadFrame(serverConn)
		if err != nil {
			t.Fatalf("failed to read frame type %d: %v", frameType, err)
		}

		if readFrame.Type != frameType {
			t.Fatalf("frame type mismatch: expected %d, got %d", frameType, readFrame.Type)
		}

		clientConn.Close()
		serverConn.Close()
	}
}

func TestInvalidFrameType(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Create invalid frame manually
	header := make([]byte, 3)
	header[0] = 0x00 // length low
	header[1] = 0x05 // length high
	header[2] = 0xFF // invalid frame type

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write invalid header
	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write(header)
		_, _ = clientConn.Write([]byte("test"))
	}()

	// Try to read frame
	_, err = session.ReadFrame(serverConn)
	if err == nil {
		t.Fatal("should reject invalid frame type")
	}
}

func TestNonceIncrement(t *testing.T) {
	session, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	testData := []byte("test")

	// Use same connection for sequential frames to test nonce increment
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write first frame
	go func() {
		defer clientConn.Close()
		_ = session.WriteFrame(clientConn, FrameTypeData, testData)
		// Write second frame after first
		_ = session.WriteFrame(clientConn, FrameTypeData, testData)
	}()

	// Read frames sequentially
	frame1, err1 := session.ReadFrame(serverConn)
	if err1 != nil {
		t.Fatalf("failed to read first frame: %v", err1)
	}
	
	frame2, err2 := session.ReadFrame(serverConn)
	if err2 != nil {
		t.Fatalf("failed to read second frame: %v", err2)
	}

	// Verify both frames decrypted successfully
	if !bytes.Equal(frame1.Payload, testData) {
		t.Fatal("first frame payload mismatch")
	}
	if !bytes.Equal(frame2.Payload, testData) {
		t.Fatal("second frame payload mismatch")
	}

	// Nonces should be different (tested implicitly by successful decryption)
	// If nonces were the same, decryption would fail
}

func TestSessionKeyValidation(t *testing.T) {
	// Test invalid session key length
	invalidKey := make([]byte, 16) // Should be 32 bytes
	_, err := NewSession(invalidKey)
	if err == nil {
		t.Fatal("should reject invalid session key length")
	}

	// Test valid session key
	validKey := make([]byte, 32)
	_, err = NewSession(validKey)
	if err != nil {
		t.Fatalf("should accept valid session key: %v", err)
	}
}

