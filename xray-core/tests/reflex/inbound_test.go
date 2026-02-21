package reflex_test

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// var testUserUUID = "00000000-0000-0000-0000-000000000000"

func createTestHandler() (*inbound.Handler, error) {
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{
				Id: testUserUUID,
			},
		},
	}

	handler, err := inbound.New(context.Background(), config)
	if err != nil {
		return nil, err
	}
	return handler.(*inbound.Handler), nil
}

func createTestHandshake() ([]byte, []byte, [32]byte, error) {
	secret, _ := reflex.GetSharedSecret(testUserUUID)
	userID, _ := reflex.UserIDToBytes(testUserUUID)
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

	clientData := reflex.EncodeClientHandshake(clientHS)

	// Generate server response
	_, serverPubKey, _ := reflex.GenerateKeyPair()
	serverHS := &reflex.ServerHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: serverPubKey,
		HMAC:      reflex.ComputeServerHMAC(secret, reflex.HandshakeVersion, serverPubKey),
	}
	serverData := reflex.EncodeServerHandshake(serverHS)

	return clientData, serverData, clientPrivKey, nil
}

func TestHandlerNetwork(t *testing.T) {
	handler, err := createTestHandler()
	if err != nil {
		t.Fatalf("createTestHandler failed: %v", err)
	}

	networks := handler.Network()
	if len(networks) != 1 || networks[0] != xnet.Network_TCP {
		t.Errorf("network mismatch: got %v, want [TCP]", networks)
	}
}

func TestHandlerInvalidHandshake(t *testing.T) {
	handler, _ := createTestHandler()
	clientConn, serverConn := net.Pipe()

	go func() {
		defer clientConn.Close()
		clientConn.Write([]byte("invalid data"))
	}()

	defer serverConn.Close()
	statConn := stat.Connection(serverConn)

	err := handler.Process(context.Background(), xnet.Network_TCP, statConn, nil)
	if err == nil {
		t.Fatal("should reject invalid handshake")
	}
}

func TestHandlerValidHandshake(t *testing.T) {
	handler, _ := createTestHandler()
	clientConn, serverConn := net.Pipe()

	clientData, _, clientPrivKey, _ := createTestHandshake()

	handshakeComplete := make(chan bool, 1)
	processDone := make(chan error, 1)

	go func() {
		defer clientConn.Close()
		clientConn.Write(clientData)
		// Read server response (should be 65 bytes)
		response := make([]byte, 65)
		n, err := clientConn.Read(response)
		if err != nil || n != 65 {
			t.Errorf("failed to read server response: n=%d, err=%v", n, err)
			handshakeComplete <- false
			return
		}
		// Verify response is valid server handshake
		serverHS, err := reflex.DecodeServerHandshake(response)
		if err != nil {
			t.Errorf("invalid server handshake: %v", err)
			handshakeComplete <- false
			return
		}
		if serverHS.Version != reflex.HandshakeVersion {
			t.Errorf("invalid server handshake version: %d", serverHS.Version)
			handshakeComplete <- false
			return
		}
		handshakeComplete <- true

		// Derive session key to send Close frame
		sharedKey := reflex.DeriveSharedKey(clientPrivKey, serverHS.PublicKey)
		sessionKey := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))

		// Create session and send Close frame to terminate connection
		session, _ := reflex.NewSession(sessionKey)
		session.WriteFrame(clientConn, reflex.FrameTypeClose, nil)
	}()

	defer serverConn.Close()
	statConn := stat.Connection(serverConn)

	// Process handshake in goroutine to avoid blocking
	go func() {
		err := handler.Process(context.Background(), xnet.Network_TCP, statConn, nil)
		processDone <- err
	}()

	// Wait for handshake verification
	select {
	case success := <-handshakeComplete:
		if !success {
			t.Fatal("handshake verification failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake timeout")
	}

	// Wait for process to complete (should finish after Close frame)
	select {
	case err := <-processDone:
		// Error may occur due to missing dispatcher, but handshake succeeded
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("process timeout")
	}
}

func TestHandlerOldTimestamp(t *testing.T) {
	handler, _ := createTestHandler()
	clientConn, serverConn := net.Pipe()

	secret, _ := reflex.GetSharedSecret(testUserUUID)
	userID, _ := reflex.UserIDToBytes(testUserUUID)
	_, clientPubKey, _ := reflex.GenerateKeyPair()

	var nonce [16]byte
	rand.Read(nonce[:])

	clientHS := &reflex.ClientHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: clientPubKey,
		UserID:    userID,
		Timestamp: time.Now().Unix() - 400, // Old timestamp
		Nonce:     nonce,
	}
	clientHS.HMAC = reflex.ComputeClientHMAC(secret, clientHS.Version, clientHS.PublicKey, clientHS.UserID, clientHS.Timestamp, clientHS.Nonce)

	clientData := reflex.EncodeClientHandshake(clientHS)

	go func() {
		defer clientConn.Close()
		clientConn.Write(clientData)
	}()

	defer serverConn.Close()
	statConn := stat.Connection(serverConn)

	err := handler.Process(context.Background(), xnet.Network_TCP, statConn, nil)
	if err == nil {
		t.Fatal("should reject old timestamp")
	}
}

func TestHandlerInvalidUUID(t *testing.T) {
	handler, _ := createTestHandler()
	clientConn, serverConn := net.Pipe()

	secret, _ := reflex.GetSharedSecret("11111111-1111-1111-1111-111111111111")
	userID, _ := reflex.UserIDToBytes("11111111-1111-1111-1111-111111111111")
	_, clientPubKey, _ := reflex.GenerateKeyPair()

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

	clientData := reflex.EncodeClientHandshake(clientHS)

	go func() {
		defer clientConn.Close()
		clientConn.Write(clientData)
	}()

	defer serverConn.Close()
	statConn := stat.Connection(serverConn)

	err := handler.Process(context.Background(), xnet.Network_TCP, statConn, nil)
	if err == nil {
		t.Fatal("should reject invalid UUID")
	}
}
