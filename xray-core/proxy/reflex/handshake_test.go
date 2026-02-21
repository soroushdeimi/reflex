package reflex

import (
	"net"
	"testing"
)

var testConfig = &Config{}

func createClientHandshake() []byte {
	return []byte("test-handshake")
}

func TestHandshake(t *testing.T) {
	handler := NewHandler(testConfig)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go func() {
		handshake := createClientHandshake()
		_, err := clientConn.Write(handshake)
		if err != nil {
			t.Errorf("client write failed: %v", err)
		}
	}()

	err := handler.ProcessHandshake(serverConn)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
}
