package reflex

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestHandshake(t *testing.T) {
	// Generate client key pair
	var clientPrivateKey, clientPublicKey [32]byte
	if _, err := rand.Read(clientPrivateKey[:]); err != nil {
		t.Fatal(err)
	}
	copy(clientPublicKey[:], clientPrivateKey[:]) // Simplified for test
	
	// Create client handshake
	var userID [16]byte
	var nonce [16]byte
	rand.Read(userID[:])
	rand.Read(nonce[:])
	
	clientHandshake := &ClientHandshake{
		PublicKey: clientPublicKey,
		UserID:    userID,
		PolicyReq: []byte("http2-api"),
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}
	
	// Write to buffer
	var buf bytes.Buffer
	if err := clientHandshake.Write(&buf); err != nil {
		t.Fatal(err)
	}
	
	// Read back
	readHandshake, err := ReadClientHandshake(&buf)
	if err != nil {
		t.Fatal(err)
	}
	
	// Compare
	if readHandshake.PublicKey != clientHandshake.PublicKey {
		t.Error("Public key mismatch")
	}
	if readHandshake.UserID != clientHandshake.UserID {
		t.Error("User ID mismatch")
	}
	if readHandshake.Timestamp != clientHandshake.Timestamp {
		t.Error("Timestamp mismatch")
	}
}

func TestSession(t *testing.T) {
	// Create session key
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	
	// Create session
	sess, err := NewSession(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	
	// Test data
	testData := []byte("Hello, Reflex!")
	
	// Write frame
	var buf bytes.Buffer
	if err := sess.WriteFrame(&buf, FrameTypeData, testData); err != nil {
		t.Fatal(err)
	}
	
	// Read frame
	sess2, err := NewSession(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	
	frame, err := sess2.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	
	// Compare
	if frame.Type != FrameTypeData {
		t.Errorf("Expected frame type %d, got %d", FrameTypeData, frame.Type)
	}
	if !bytes.Equal(frame.Payload, testData) {
		t.Error("Payload mismatch")
	}
}

func TestTrafficMorphing(t *testing.T) {
	profile := GetProfile("youtube")
	if profile == nil {
		t.Fatal("Failed to get profile")
	}
	
	// Test packet size selection
	for i := 0; i < 10; i++ {
		size := profile.GetPacketSize()
		if size <= 0 {
			t.Error("Invalid packet size")
		}
	}
	
	// Test delay selection
	for i := 0; i < 10; i++ {
		delay := profile.GetDelay()
		if delay < 0 {
			t.Error("Invalid delay")
		}
	}
}
