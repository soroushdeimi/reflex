package inbound

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/protocol"
)

func TestIntegrationHandshake(t *testing.T) {
	// 1. Setup Server
	userIDStr := "29525c56-6556-43f1-8b2b-09b673627038"
	acc := &MemoryAccount{Id: userIDStr}

	handler := &Handler{
		clients: []*protocol.MemoryUser{
			{Email: "test-user", Account: acc},
		},
	}
	priv, _, _ := generateKeyPair()
	handler.serverKey = priv

	// 2. Create Pipe
	clientConn, serverConn := net.Pipe()

	// Use a WaitGroup to ensure the client goroutine finishes before the test exits
	var wg sync.WaitGroup
	wg.Add(1)

	// 3. Run Server
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		reader := bufio.NewReader(serverConn)

		// FIX: Consume the 4 magic bytes before calling ProcessHandshake
		magicHeader := make([]byte, 4)
		if _, err := io.ReadFull(reader, magicHeader); err != nil {
			errChan <- err
			return
		}

		_, err := handler.ProcessHandshake(serverConn, reader)
		errChan <- err
	}()

	// 4. Run Client
	go func() {
		defer wg.Done()
		defer func() { _ = clientConn.Close() }()

		// A. Write Magic
		_ = binary.Write(clientConn, binary.BigEndian, uint32(ReflexMagic))

		// B. Write Handshake Data (Order: PubKey, UserID, Time, Nonce)
		clientPub := make([]byte, 32)
		_, _ = rand.Read(clientPub)
		_, _ = clientConn.Write(clientPub)

		uid, _ := uuid.Parse(userIDStr)
		uidBytes, _ := uid.MarshalBinary()
		_, _ = clientConn.Write(uidBytes)

		// Send current time to pass the 30s validation check
		_ = binary.Write(clientConn, binary.BigEndian, uint64(time.Now().Unix()))

		nonce := make([]byte, 16)
		_, _ = rand.Read(nonce)
		_, _ = clientConn.Write(nonce)

		// C. Read Server Response (Public Key)
		serverResp := make([]byte, 32)
		if _, err := io.ReadFull(clientConn, serverResp); err != nil {
			// Note: We use t.Log instead of Errorf here to avoid panics if the test already failed
			t.Logf("Client side: Server closed connection early (expected if auth failed): %v", err)
		}
	}()

	// 5. Final Result Check
	err := <-errChan
	if err != nil {
		t.Fatalf("Handshake Failed: %v", err)
	}

	// Clean up
	_ = serverConn.Close()
	wg.Wait()
}
