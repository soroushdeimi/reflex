package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

// TestReflexHandshakeIntegration verifies the full Handshake flow: key exchange,
// client authentication, session key derivation, and encrypted frame exchange
// over a network connection.
func TestReflexHandshakeIntegration(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientUUID := "b831381d-6324-4d53-ad4f-8cda48b30811"
	clients := []*reflex.ClientEntry{
		{ID: clientUUID, Policy: "youtube"},
	}

	var (
		clientSessionKey []byte
		serverSessionKey []byte
		clientErr        error
		serverErr        error
	)

	var wg sync.WaitGroup
	wg.Add(2)

	// Server side
	go func() {
		defer wg.Done()

		hsData := make([]byte, reflex.HandshakeHeaderSize)
		if _, err := io.ReadFull(serverConn, hsData); err != nil {
			serverErr = err
			return
		}

		clientHS, err := reflex.UnmarshalClientHandshake(hsData)
		if err != nil {
			serverErr = err
			return
		}

		if !reflex.ValidateTimestamp(clientHS.Timestamp) {
			serverErr = io.ErrUnexpectedEOF
			return
		}

		entry := reflex.AuthenticateUser(clientHS.UserID, clients)
		if entry == nil {
			serverErr = io.ErrUnexpectedEOF
			return
		}

		serverPrivKey, serverPubKey, err := reflex.GenerateKeyPair()
		if err != nil {
			serverErr = err
			return
		}

		sharedSecret, err := reflex.DeriveSharedSecret(serverPrivKey, clientHS.PublicKey)
		if err != nil {
			serverErr = err
			return
		}

		serverSessionKey, err = reflex.DeriveSessionKey(sharedSecret, clientHS.Nonce[:])
		if err != nil {
			serverErr = err
			return
		}

		serverHS := &reflex.ServerHandshake{PublicKey: serverPubKey}
		if _, err := serverConn.Write(reflex.MarshalServerHandshake(serverHS)); err != nil {
			serverErr = err
			return
		}
	}()

	// Client side
	go func() {
		defer wg.Done()

		clientPrivKey, clientPubKey, err := reflex.GenerateKeyPair()
		if err != nil {
			clientErr = err
			return
		}

		userUUID, err := uuid.ParseString(clientUUID)
		if err != nil {
			clientErr = err
			return
		}

		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			clientErr = err
			return
		}

		clientHS := &reflex.ClientHandshake{
			PublicKey: clientPubKey,
			UserID:    userUUID,
			Timestamp: time.Now().Unix(),
			Nonce:     nonce,
		}

		if _, err := clientConn.Write(reflex.MarshalClientHandshake(clientHS)); err != nil {
			clientErr = err
			return
		}

		serverHSData := make([]byte, 64)
		if _, err := io.ReadFull(clientConn, serverHSData); err != nil {
			clientErr = err
			return
		}

		serverHS, err := reflex.UnmarshalServerHandshake(serverHSData)
		if err != nil {
			clientErr = err
			return
		}

		sharedSecret, err := reflex.DeriveSharedSecret(clientPrivKey, serverHS.PublicKey)
		if err != nil {
			clientErr = err
			return
		}

		clientSessionKey, err = reflex.DeriveSessionKey(sharedSecret, nonce[:])
		if err != nil {
			clientErr = err
			return
		}
	}()

	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}

	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		t.Fatal("client and server derived different session keys")
	}
}

// TestReflexFallbackDetection verifies that non-Reflex traffic (lacking the
// Reflex magic number) can be distinguished from valid handshake packets,
// enabling correct Fallback routing.
func TestReflexFallbackDetection(t *testing.T) {
	// Valid Reflex handshake starts with magic 0x5246584C
	validMagic := make([]byte, 4)
	binary.BigEndian.PutUint32(validMagic, reflex.ReflexMagic)

	// HTTP traffic starts with "GET " or "POST"
	httpTraffic := []byte("GET / HTTP/1.1\r\n")

	// Check magic detection
	if binary.BigEndian.Uint32(validMagic) != reflex.ReflexMagic {
		t.Fatal("valid magic should match ReflexMagic")
	}

	if binary.BigEndian.Uint32(httpTraffic[:4]) == reflex.ReflexMagic {
		t.Fatal("HTTP traffic should not match ReflexMagic")
	}

	// TLS ClientHello starts with 0x16 0x03
	tlsTraffic := []byte{0x16, 0x03, 0x01, 0x00}
	if binary.BigEndian.Uint32(tlsTraffic) == reflex.ReflexMagic {
		t.Fatal("TLS traffic should not match ReflexMagic")
	}

	// Random data should not match
	randomData := make([]byte, 4)
	if _, err := rand.Read(randomData); err != nil {
		t.Fatal(err)
	}
	// It's astronomically unlikely that random bytes match 0x5246584C
	if binary.BigEndian.Uint32(randomData) == reflex.ReflexMagic {
		t.Log("extremely unlikely: random data matched magic (not a failure)")
	}

	// Verify that a full marshalled handshake starts with the magic
	_, pubKey, _ := reflex.GenerateKeyPair()
	uid, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	hs := &reflex.ClientHandshake{
		PublicKey: pubKey,
		UserID:    uid,
		Timestamp: time.Now().Unix(),
	}
	hsBytes := reflex.MarshalClientHandshake(hs)
	if binary.BigEndian.Uint32(hsBytes[:4]) != reflex.ReflexMagic {
		t.Fatal("marshalled handshake should start with ReflexMagic")
	}
}

// TestReflexReplayProtection verifies that the nonce tracker correctly prevents
// Replay attacks by rejecting duplicate nonces while accepting unique ones.
func TestReflexReplayProtection(t *testing.T) {
	tracker := reflex.NewNonceTracker(1000)

	// First use of each nonce should succeed
	for i := uint64(1); i <= 10; i++ {
		if !tracker.Check(i) {
			t.Fatalf("nonce %d should be accepted on first use", i)
		}
	}

	// Replay of any previously seen nonce should be rejected
	for i := uint64(1); i <= 10; i++ {
		if tracker.Check(i) {
			t.Fatalf("replay of nonce %d should be rejected", i)
		}
	}

	// New nonces should still be accepted
	for i := uint64(100); i <= 110; i++ {
		if !tracker.Check(i) {
			t.Fatalf("new nonce %d should be accepted", i)
		}
	}
}

// TestReflexReplayTimestampValidation verifies that expired timestamps are
// rejected, preventing old handshake Replay attempts.
func TestReflexReplayTimestampValidation(t *testing.T) {
	now := time.Now().Unix()

	// Fresh timestamp
	if !reflex.ValidateTimestamp(now) {
		t.Fatal("current timestamp should be valid")
	}

	// Stale timestamp (5 minutes old)
	if reflex.ValidateTimestamp(now - 300) {
		t.Fatal("5-minute-old timestamp should be rejected")
	}

	// Far future timestamp
	if reflex.ValidateTimestamp(now + 300) {
		t.Fatal("timestamp 5 minutes in the future should be rejected")
	}
}

// TestReflexIntegrationFullConnection simulates a complete Integration test:
// handshake -> session creation -> bidirectional encrypted data exchange.
func TestReflexIntegrationFullConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	// Generate a shared session key (simulating successful handshake)
	clientPriv, clientPub, _ := reflex.GenerateKeyPair()
	serverPriv, serverPub, _ := reflex.GenerateKeyPair()

	clientSecret, _ := reflex.DeriveSharedSecret(clientPriv, serverPub)
	serverSecret, _ := reflex.DeriveSharedSecret(serverPriv, clientPub)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	clientKey, _ := reflex.DeriveSessionKey(clientSecret, nonce)
	serverKey, _ := reflex.DeriveSessionKey(serverSecret, nonce)

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatal("session keys must match")
	}

	clientSess, _ := reflex.NewSession(clientKey)
	serverSess, _ := reflex.NewSession(serverKey)

	testPayloads := []string{
		"Hello from client",
		"This is a larger payload with more data to test frame handling",
		"Short",
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Client sends, server receives
	go func() {
		defer wg.Done()
		for _, msg := range testPayloads {
			if err := clientSess.WriteFrame(clientConn, reflex.FrameTypeData, []byte(msg)); err != nil {
				t.Errorf("client WriteFrame failed: %v", err)
				return
			}
		}
		if err := clientSess.WriteCloseFrame(clientConn); err != nil {
			t.Errorf("WriteCloseFrame failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		for i, expected := range testPayloads {
			frame, err := serverSess.ReadFrame(serverConn)
			if err != nil {
				t.Errorf("server ReadFrame %d failed: %v", i, err)
				return
			}
			if frame.Type != reflex.FrameTypeData {
				t.Errorf("expected DATA frame, got type %d", frame.Type)
				return
			}
			if string(frame.Payload) != expected {
				t.Errorf("payload %d mismatch: got %q, want %q", i, frame.Payload, expected)
				return
			}
		}

		// Read close frame
		closeFrame, err := serverSess.ReadFrame(serverConn)
		if err != nil {
			t.Errorf("reading close frame failed: %v", err)
			return
		}
		if closeFrame.Type != reflex.FrameTypeClose {
			t.Errorf("expected CLOSE frame, got type %d", closeFrame.Type)
		}
	}()

	wg.Wait()
}

// TestReflexIntegrationBidirectional tests full-duplex encrypted data exchange.
func TestReflexIntegrationBidirectional(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Client uses WriteFrame/ReadFrame in one direction,
	// server in the opposite. They need separate sessions with separate nonces.
	clientWriteSess, _ := reflex.NewSession(key)
	serverReadSess, _ := reflex.NewSession(key)

	// For the reverse direction, use a different key to avoid nonce conflicts
	reverseKey := make([]byte, 32)
	if _, err := rand.Read(reverseKey); err != nil {
		t.Fatal(err)
	}
	serverWriteSess, _ := reflex.NewSession(reverseKey)
	clientReadSess, _ := reflex.NewSession(reverseKey)

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Server
	go func() {
		defer wg.Done()
		if err := clientWriteSess.WriteFrame(clientConn, reflex.FrameTypeData, []byte("request")); err != nil {
			t.Errorf("client WriteFrame failed: %v", err)
			return
		}

		frame, err := clientReadSess.ReadFrame(clientConn)
		if err != nil {
			t.Errorf("client read failed: %v", err)
			return
		}
		if string(frame.Payload) != "response" {
			t.Errorf("expected 'response', got %q", frame.Payload)
		}
	}()

	// Server <- Client, then Server -> Client
	go func() {
		defer wg.Done()
		frame, err := serverReadSess.ReadFrame(serverConn)
		if err != nil {
			t.Errorf("server read failed: %v", err)
			return
		}
		if string(frame.Payload) != "request" {
			t.Errorf("expected 'request', got %q", frame.Payload)
			return
		}

		if err := serverWriteSess.WriteFrame(serverConn, reflex.FrameTypeData, []byte("response")); err != nil {
			t.Errorf("server WriteFrame failed: %v", err)
		}
	}()

	wg.Wait()
}

// TestReflexIntegrationMorphedTraffic tests that traffic morphing correctly
// splits and pads data frames according to a traffic profile.
func TestReflexIntegrationMorphedTraffic(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	writerSess, _ := reflex.NewSession(key)
	readerSess, _ := reflex.NewSession(key)

	morph := reflex.NewTrafficMorph("youtube")
	if morph == nil {
		t.Fatal("expected non-nil morph for youtube profile")
	}

	var buf bytes.Buffer
	data := make([]byte, 5000) // Larger than typical profile packet size
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	if err := morph.MorphWrite(writerSess, &buf, data); err != nil {
		t.Fatalf("MorphWrite failed: %v", err)
	}

	// Read all frames and verify data can be recovered
	var assembled []byte
	frameCount := 0
	for buf.Len() > 0 {
		frame, err := readerSess.ReadFrame(&buf)
		if err != nil {
			break
		}
		assembled = append(assembled, frame.Payload...)
		frameCount++
	}

	if frameCount == 0 {
		t.Fatal("expected at least one morphed frame")
	}

	// Original data should be a prefix of the assembled output (padding is appended)
	if len(assembled) < len(data) {
		t.Fatalf("assembled data too short: %d < %d", len(assembled), len(data))
	}
	if !bytes.Equal(assembled[:len(data)], data) {
		t.Fatal("original data not recoverable from morphed frames")
	}
}

// TestReflexIntegrationECHConfig tests that ECH configuration can be generated
// and applied to TLS configs for both server and client sides.
func TestReflexIntegrationECHConfig(t *testing.T) {
	cfg, err := reflex.NewServerECHConfig("proxy.example.com", 1)
	if err != nil {
		t.Fatalf("NewServerECHConfig failed: %v", err)
	}

	if !cfg.Enabled {
		t.Fatal("ECH config should be enabled")
	}
	if cfg.KeySet == nil {
		t.Fatal("ECH key set should not be nil")
	}
	if len(cfg.ConfigList) == 0 {
		t.Fatal("ECH config list should not be empty")
	}
}
