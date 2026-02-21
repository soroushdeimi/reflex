package reflex_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	stdnet "net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestInboundHandshakeDetection(t *testing.T) {
	h := &inbound.Handler{}

	// Test Magic Number
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, reflex.ReflexMagic)
	if !h.IsReflexMagic(magic) {
		t.Error("IsReflexMagic failed for valid magic")
	}

	// Test HTTP POST-like
	if !h.IsHTTPPostLike([]byte("POST /api HTTP/1.1")) {
		t.Error("IsHTTPPostLike failed for valid POST")
	}

	if h.IsHTTPPostLike([]byte("GET / HTTP/1.1")) {
		t.Error("IsHTTPPostLike succeeded for GET")
	}

	// Edge cases
	if h.IsReflexMagic([]byte{0x52, 0x45}) {
		t.Error("IsReflexMagic succeeded for short data")
	}
	if h.IsHTTPPostLike([]byte("POS")) {
		t.Error("IsHTTPPostLike succeeded for short data")
	}
}

func TestAuthenticateUser(t *testing.T) {
	uID := uuid.New()
	// Since clients is unexported, this test needs to use New() or I need to export clients.
	// Actually, I can't easily set clients field from another package.
	// I'll skip this test or fix it by using public New()

	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID.String()}},
	}
	h, _ := inbound.New(context.Background(), config)
	handler := h.(*inbound.Handler)

	var uIDBytes [16]byte
	copy(uIDBytes[:], uID[:])

	user, err := handler.AuthenticateUser(uIDBytes)
	if err != nil {
		t.Errorf("AuthenticateUser failed: %v", err)
	}
	if user == nil {
		t.Error("AuthenticateUser returned nil user")
	}
}

func TestMemoryAccount(t *testing.T) {
	acc := &inbound.MemoryAccount{Id: "test-id", Policy: "test-policy"}

	if !acc.Equals(&inbound.MemoryAccount{Id: "test-id", Policy: "test-policy"}) {
		t.Error("Equals failed for same account")
	}

	if acc.Equals(&inbound.MemoryAccount{Id: "other-id", Policy: "test-policy"}) {
		t.Error("Equals succeeded for different id")
	}

	proto := acc.ToProto()
	if proto == nil {
		t.Fatal("ToProto returned nil")
	}
}

func TestNetwork(t *testing.T) {
	h := &inbound.Handler{}
	networks := h.Network()
	if len(networks) != 2 {
		t.Errorf("expected 2 networks, got %d", len(networks))
	}
}

func TestPreloadedConn(t *testing.T) {
	data := []byte("peeked data")
	reader := bufio.NewReader(bytes.NewReader(data))
	conn := &inbound.PreloadedConn{
		Reader: reader,
	}

	buf := make([]byte, len(data))
	n, err := conn.Read(buf)
	if err != nil || n != len(data) || !bytes.Equal(buf, data) {
		t.Errorf("Read failed: n=%d, err=%v", n, err)
	}
}

func TestNewHandler(t *testing.T) {
	ctx := context.Background()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: uuid.New().String(), Policy: "youtube"},
		},
		Fallback: &reflex.Fallback{Dest: 80},
		Tls: &reflex.TLSSettings{
			Enabled:    true,
			ServerName: "example.com",
		},
	}

	h, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatalf("New handler failed: %v", err)
	}

	if h == nil {
		t.Error("handler is nil")
	}
}

func TestHandleReflexHTTP(t *testing.T) {
	uID := uuid.New().String()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	}
	h, _ := inbound.New(context.Background(), config)
	handler := h.(*inbound.Handler)

	clientHS := reflex.ClientHandshake{
		PublicKey: [32]byte{1},
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{3},
	}
	u, _ := uuid.Parse(uID)
	copy(clientHS.UserID[:], u[:])

	packet := &bytes.Buffer{}
	packet.WriteString("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	binary.Write(packet, binary.BigEndian, &clientHS)

	c1, s1 := stdnet.Pipe()
	go func() {
		c1.Write(packet.Bytes())
		var resp reflex.ServerHandshake
		binary.Read(c1, binary.BigEndian, &resp)
		c1.Close()
	}()

	reader := bufio.NewReader(s1)
	handler.HandleReflexHTTP(context.Background(), reader, s1.(stat.Connection), nil)
}

func TestHandleReflexMagic(t *testing.T) {
	uID := uuid.New().String()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	}
	h, _ := inbound.New(context.Background(), config)
	handler := h.(*inbound.Handler)

	clientHS := reflex.ClientHandshake{
		PublicKey: [32]byte{1},
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{2},
	}
	u, _ := uuid.Parse(uID)
	copy(clientHS.UserID[:], u[:])

	packet := &bytes.Buffer{}
	binary.Write(packet, binary.BigEndian, uint32(reflex.ReflexMagic))
	binary.Write(packet, binary.BigEndian, &clientHS)

	c1, s1 := stdnet.Pipe()
	go func() {
		c1.Write(packet.Bytes())
		// Server will try to write handshake response back
		var resp reflex.ServerHandshake
		binary.Read(c1, binary.BigEndian, &resp)
		c1.Close()
	}()

	reader := bufio.NewReader(s1)

	handler.HandleReflexMagic(context.Background(), reader, s1.(stat.Connection), nil)
}
