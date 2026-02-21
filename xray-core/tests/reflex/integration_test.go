package reflex_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestEndToEndHandshake(t *testing.T) {
	userUUID := "00000000-0000-0000-0000-000000000000"
	secret, _ := reflex.GetSharedSecret(userUUID)
	userID, _ := reflex.UserIDToBytes(userUUID)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Client side: generate handshake
	clientPrivKey, clientPubKey, _ := reflex.GenerateKeyPair()
	var nonce [16]byte
	rand.Read(nonce[:])

	clientHS := &reflex.ClientHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: clientPubKey,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}
	clientHS.HMAC = reflex.ComputeClientHMAC(secret, clientHS.Version, clientHS.PublicKey, clientHS.UserID, clientHS.Timestamp, clientHS.Nonce)

	// Server side: process handshake
	go func() {
		clientData := reflex.EncodeClientHandshake(clientHS)
		clientConn.Write(clientData)

		// Read server response
		serverResponse := make([]byte, 65)
		io.ReadFull(clientConn, serverResponse)

		serverHS, err := reflex.DecodeServerHandshake(serverResponse)
		if err != nil {
			t.Errorf("decode server handshake failed: %v", err)
			return
		}

		// Verify server HMAC
		expectedHMAC := reflex.ComputeServerHMAC(secret, serverHS.Version, serverHS.PublicKey)
		if !bytes.Equal(serverHS.HMAC[:], expectedHMAC[:]) {
			t.Error("server HMAC verification failed")
			return
		}

		// Derive session key
		sharedKey := reflex.DeriveSharedKey(clientPrivKey, serverHS.PublicKey)
		sessionKey := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))

		if len(sessionKey) != 32 {
			t.Errorf("session key length mismatch: got %d, want 32", len(sessionKey))
		}
	}()

	// Server processes handshake
	handshakeData := make([]byte, reflex.HandshakeSize)
	io.ReadFull(serverConn, handshakeData)

	clientHSDecoded, err := reflex.DecodeClientHandshake(handshakeData)
	if err != nil {
		t.Fatalf("decode client handshake failed: %v", err)
	}

	// Verify client HMAC
	expectedHMAC := reflex.ComputeClientHMAC(secret, clientHSDecoded.Version, clientHSDecoded.PublicKey, clientHSDecoded.UserID, clientHSDecoded.Timestamp, clientHSDecoded.Nonce)
	if !bytes.Equal(clientHSDecoded.HMAC[:], expectedHMAC[:]) {
		t.Fatal("client HMAC verification failed")
	}

	// Generate server response
	_, serverPubKey, _ := reflex.GenerateKeyPair()
	serverHS := &reflex.ServerHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: serverPubKey,
		HMAC:      reflex.ComputeServerHMAC(secret, reflex.HandshakeVersion, serverPubKey),
	}

	serverData := reflex.EncodeServerHandshake(serverHS)
	serverConn.Write(serverData)

	// Wait for client to finish
	time.Sleep(100 * time.Millisecond)
}

func TestEndToEndFrameExchange(t *testing.T) {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	clientSession, _ := reflex.NewSession(sessionKey)
	serverSession, _ := reflex.NewSession(sessionKey)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	testPayloads := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
	}

	// Client writes frames
	go func() {
		for _, payload := range testPayloads {
			if err := clientSession.WriteFrame(clientConn, reflex.FrameTypeData, payload); err != nil {
				t.Errorf("client WriteFrame failed: %v", err)
				return
			}
		}
		clientSession.WriteFrame(clientConn, reflex.FrameTypeClose, nil)
	}()

	// Server reads frames
	received := make([][]byte, 0)
	for {
		frame, err := serverSession.ReadFrame(serverConn)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("server ReadFrame failed: %v", err)
		}

		if frame.Type == reflex.FrameTypeClose {
			break
		}

		if frame.Type == reflex.FrameTypeData {
			received = append(received, frame.Payload)
		}
	}

	if len(received) != len(testPayloads) {
		t.Fatalf("frame count mismatch: got %d, want %d", len(received), len(testPayloads))
	}

	for i, payload := range testPayloads {
		if !bytes.HasPrefix(received[i], payload) {
			t.Errorf("payload %d mismatch", i)
		}
	}
}

func TestEndToEndWithMorphing(t *testing.T) {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	morphingConfig := reflex.DefaultMorphingConfig()
	clientSession, _ := reflex.NewSessionWithMorphing(sessionKey, morphingConfig)
	serverSession, _ := reflex.NewSessionWithMorphing(sessionKey, morphingConfig)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	smallPayload := []byte("test") // Small payload to test morphing

	go func() {
		clientSession.WriteFrame(clientConn, reflex.FrameTypeData, smallPayload)
	}()

	frame, err := serverSession.ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	// Check that payload was morphed (padded)
	if len(frame.Payload) < morphingConfig.MinSize {
		t.Errorf("payload should be morphed: got %d, want >= %d", len(frame.Payload), morphingConfig.MinSize)
	}

	// Original data should be prefix
	if !bytes.HasPrefix(frame.Payload, smallPayload) {
		t.Error("morphed payload should contain original data")
	}
}
