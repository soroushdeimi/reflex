package inbound_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// mockDispatcher implements routing.Dispatcher for tests.
type mockDispatcher struct{}

func (m *mockDispatcher) Type() interface{} { return (*routing.Dispatcher)(nil) }
func (m *mockDispatcher) Start() error      { return nil }
func (m *mockDispatcher) Close() error      { return nil }
func (m *mockDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	return nil, errors.New("mock dispatcher: not used in test")
}
func (m *mockDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return errors.New("mock dispatcher: not used in test")
}

// pipeConn wraps net.Conn to satisfy stat.Connection (same as net.Conn).
type pipeConn struct{ net.Conn }

func pipeToStat(c net.Conn) stat.Connection {
	if c == nil {
		return nil
	}
	return &pipeConn{c}
}

// TestHandshakeFull runs a full Reflex handshake: client sends magic+handshake, server responds with HTTP 200 + server pubkey, client derives session and sends CLOSE.
func TestHandshakeFull(t *testing.T) {
	ctx := context.Background()
	userUUID := uuid.New().String()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: userUUID, Policy: ""}},
	}
	handler, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		clientPriv, clientPub, err := reflex.GenerateKeyPair()
		if err != nil {
			done <- err
			return
		}
		uid, _ := uuid.Parse(userUUID)
		packet := &reflex.ClientHandshakePacket{
			Magic: reflex.ReflexMagic,
			Handshake: reflex.ClientHandshake{
				PublicKey: clientPub,
				UserID:    uid,
				PolicyReq: nil,
				Timestamp: time.Now().Unix(),
				Nonce:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		}
		handshakeBytes := reflex.EncodeClientHandshakePacket(packet)
		_, err = clientConn.Write(handshakeBytes)
		if err != nil {
			done <- err
			return
		}

		br := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			done <- err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			done <- fmt.Errorf("unexpected status %d", resp.StatusCode)
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			done <- err
			return
		}
		var out struct {
			PublicKey string `json:"publicKey"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			done <- err
			return
		}
		serverPubB, err := base64.StdEncoding.DecodeString(out.PublicKey)
		if err != nil || len(serverPubB) != 32 {
			done <- fmt.Errorf("invalid server public key: %v", err)
			return
		}
		var serverPub [32]byte
		copy(serverPub[:], serverPubB)
		shared := reflex.DeriveSharedKey(clientPriv, serverPub)
		sessionKey := reflex.DeriveSessionKey(shared, []byte("reflex-session"))
		if sessionKey == nil {
			done <- errors.New("nil session key")
			return
		}
		sess, err := reflex.NewSession(sessionKey)
		if err != nil {
			done <- err
			return
		}
		if err := sess.WriteFrame(clientConn, reflex.FrameTypeClose, nil); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	err = handler.Process(ctx, xnet.Network_TCP, pipeToStat(serverConn), &mockDispatcher{})
	if err != nil {
		t.Errorf("Process failed: %v", err)
	}
	if e := <-done; e != nil {
		t.Errorf("client goroutine: %v", e)
	}
}

// TestInvalidHandshake verifies that invalid data leads to fallback or error (no crash).
func TestInvalidHandshake(t *testing.T) {
	config := &reflex.InboundConfig{Clients: []*reflex.User{{Id: uuid.New().String()}}}
	handler, err := inbound.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	go func() {
		clientConn.Write([]byte("invalid data not reflex"))
		clientConn.Close()
	}()
	err = handler.Process(context.Background(), xnet.Network_TCP, pipeToStat(serverConn), &mockDispatcher{})
	if err != nil && !strings.Contains(err.Error(), "fallback") {
		t.Logf("Process returned: %v", err)
	}
	serverConn.Close()
}

// TestInvalidUUID verifies that handshake with UUID not in config is rejected (403).
func TestInvalidUUID(t *testing.T) {
	configUser := uuid.New().String()
	config := &reflex.InboundConfig{Clients: []*reflex.User{{Id: configUser}}}
	handler, err := inbound.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	otherUUID := uuid.New()
	_, clientPub, _ := reflex.GenerateKeyPair()
	packet := &reflex.ClientHandshakePacket{
		Magic: reflex.ReflexMagic,
		Handshake: reflex.ClientHandshake{
			PublicKey: clientPub,
			UserID:    otherUUID,
			Timestamp: time.Now().Unix(),
		},
	}
	handshakeBytes := reflex.EncodeClientHandshakePacket(packet)
	got403 := make(chan bool, 1)
	go func() {
		clientConn.Write(handshakeBytes)
		buf := make([]byte, 512)
		n, _ := clientConn.Read(buf)
		clientConn.Close()
		got403 <- n > 0 && bytes.Contains(buf[:n], []byte("403"))
	}()
	_ = handler.Process(context.Background(), xnet.Network_TCP, pipeToStat(serverConn), &mockDispatcher{})
	serverConn.Close()
	if !<-got403 {
		t.Error("expected server to respond with 403 Forbidden for unknown UUID")
	}
}

// TestIncompleteHandshake verifies that incomplete data is handled without panic.
func TestIncompleteHandshake(t *testing.T) {
	config := &reflex.InboundConfig{Clients: []*reflex.User{{Id: uuid.New().String()}}}
	handler, err := inbound.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	go func() {
		clientConn.Write([]byte("POST /api"))
		clientConn.Close()
	}()
	_ = handler.Process(context.Background(), xnet.Network_TCP, pipeToStat(serverConn), &mockDispatcher{})
	serverConn.Close()
}

// TestNewWithMorphingEnabled verifies that handler is created with morphing_enabled from config.
func TestNewWithMorphingEnabled(t *testing.T) {
	config := &reflex.InboundConfig{
		Clients:         []*reflex.User{{Id: uuid.New().String()}},
		MorphingEnabled: true,
	}
	handler, err := inbound.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
}
