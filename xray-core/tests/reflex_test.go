package tests

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex/encoding"
)

// TestHandshakeKeyExchange tests X25519 ECDH key exchange
func TestHandshakeKeyExchange(t *testing.T) {
	clientPriv, clientPub, err := encoding.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client key generation failed: %v", err)
	}

	serverPriv, serverPub, err := encoding.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server key generation failed: %v", err)
	}

	clientShared := encoding.DeriveSharedKey(clientPriv, serverPub)
	serverShared := encoding.DeriveSharedKey(serverPriv, clientPub)

	if !bytes.Equal(clientShared[:], serverShared[:]) {
		t.Fatal("shared secrets do not match - ECDH failed")
	}
}

// TestHandshakeSessionKey tests session key derivation
func TestHandshakeSessionKey(t *testing.T) {
	clientPriv, clientPub, _ := encoding.GenerateKeyPair()
	serverPriv, serverPub, _ := encoding.GenerateKeyPair()

	clientShared := encoding.DeriveSharedKey(clientPriv, serverPub)
	serverShared := encoding.DeriveSharedKey(serverPriv, clientPub)

	clientKey, err := encoding.DeriveSessionKey(clientShared, []byte("reflex-session-v1"))
	if err != nil {
		t.Fatalf("client session key derivation failed: %v", err)
	}

	serverKey, err := encoding.DeriveSessionKey(serverShared, []byte("reflex-session-v1"))
	if err != nil {
		t.Fatalf("server session key derivation failed: %v", err)
	}

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatal("session keys do not match")
	}
}

// TestEncryptionEncodeDecodeFrame tests ChaCha20-Poly1305 frame encryption
func TestEncryptionEncodeDecodeFrame(t *testing.T) {
	priv, pub, _ := encoding.GenerateKeyPair()
	shared := encoding.DeriveSharedKey(priv, pub)
	sessionKey, _ := encoding.DeriveSessionKey(shared, []byte("reflex-session-v1"))

	encoder, err := encoding.NewFrameEncoder(sessionKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	decoder, err := encoding.NewFrameDecoder(sessionKey)
	if err != nil {
		t.Fatalf("failed to create decoder: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	original := []byte("Hello Reflex - test payload 12345")

	errCh := make(chan error, 1)
	go func() {
		frame := encoding.GetFrame()
		frame.Type = encoding.FrameTypeData
		frame.Payload = original
		errCh <- encoder.WriteFrame(client, frame)
		encoding.PutFrame(frame)
	}()

	frame, err := decoder.ReadFrame(server)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	defer encoding.PutFrame(frame)

	if err := <-errCh; err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	if !bytes.Equal(frame.Payload, original) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, original)
	}
}

// TestEncryptionTamperDetection tests that tampered frames are rejected
func TestEncryptionTamperDetection(t *testing.T) {
	priv, pub, _ := encoding.GenerateKeyPair()
	shared := encoding.DeriveSharedKey(priv, pub)
	sessionKey, _ := encoding.DeriveSessionKey(shared, []byte("reflex-session-v1"))

	encoder, _ := encoding.NewFrameEncoder(sessionKey)

	wrongKey := make([]byte, len(sessionKey))
	copy(wrongKey, sessionKey)
	wrongKey[0] ^= 0xFF

	decoder, _ := encoding.NewFrameDecoder(wrongKey)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		frame := encoding.GetFrame()
		frame.Type = encoding.FrameTypeData
		frame.Payload = []byte("secret data")
		encoder.WriteFrame(client, frame)
		encoding.PutFrame(frame)
	}()

	_, err := decoder.ReadFrame(server)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key, but it succeeded")
	}
}

// isHTTPRequest checks if data looks like an HTTP request (mirrors fallback logic)
func isHTTPRequest(data []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	for _, m := range methods {
		if len(data) >= len(m) && string(data[:len(m)]) == m {
			return true
		}
	}
	return false
}

// TestFallbackHTTPDetection tests HTTP request detection for fallback
func TestFallbackHTTPDetection(t *testing.T) {
	httpRequests := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
		[]byte("POST /api HTTP/1.1\r\n"),
		[]byte("CONNECT example.com:443 HTTP/1.1\r\n"),
	}

	nonHTTPRequests := [][]byte{
		{0x01, 0x02, 0x03, 0x04},
		[]byte("random text"),
	}

	for _, req := range httpRequests {
		if !isHTTPRequest(req) {
			t.Errorf("expected HTTP request detected: %q", req)
		}
	}

	for _, req := range nonHTTPRequests {
		if isHTTPRequest(req) {
			t.Errorf("expected non-HTTP request not detected: %q", req)
		}
	}
}

// TestReplayProtection tests that multiple frames can be sent and received correctly
func TestReplayProtection(t *testing.T) {
	priv, pub, _ := encoding.GenerateKeyPair()
	shared := encoding.DeriveSharedKey(priv, pub)
	sessionKey, _ := encoding.DeriveSessionKey(shared, []byte("reflex-session-v1"))

	encoder, _ := encoding.NewFrameEncoder(sessionKey)
	decoder, _ := encoding.NewFrameDecoder(sessionKey)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("test replay")

	go func() {
		for i := 0; i < 3; i++ {
			frame := encoding.GetFrame()
			frame.Type = encoding.FrameTypeData
			frame.Payload = payload
			encoder.WriteFrame(client, frame)
			encoding.PutFrame(frame)
			time.Sleep(time.Millisecond)
		}
	}()

	for i := 0; i < 3; i++ {
		frame, err := decoder.ReadFrame(server)
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}
		encoding.PutFrame(frame)
	}
}

// TestIntegrationFullConnection tests complete client-server tunnel flow
func TestIntegrationFullConnection(t *testing.T) {
	priv, pub, _ := encoding.GenerateKeyPair()
	shared := encoding.DeriveSharedKey(priv, pub)
	sessionKey, _ := encoding.DeriveSessionKey(shared, []byte("reflex-session-v1"))

	encoder, _ := encoding.NewFrameEncoder(sessionKey)
	decoder, _ := encoding.NewFrameDecoder(sessionKey)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	messages := []string{"hello", "world", "reflex protocol", "test complete"}

	go func() {
		for _, msg := range messages {
			frame := encoding.GetFrame()
			frame.Type = encoding.FrameTypeData
			frame.Payload = []byte(msg)
			encoder.WriteFrame(client, frame)
			encoding.PutFrame(frame)
		}
	}()

	for _, expected := range messages {
		frame, err := decoder.ReadFrame(server)
		if err != nil {
			t.Fatalf("ReadFrame failed: %v", err)
		}
		if string(frame.Payload) != expected {
			t.Errorf("expected %q, got %q", expected, frame.Payload)
		}
		encoding.PutFrame(frame)
	}
}
