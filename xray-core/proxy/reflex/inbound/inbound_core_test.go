package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	stdnet "net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
)

// MockConnection implements stat.Connection
type MockConnection struct {
	stdnet.Conn
}

func (c *MockConnection) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, nil // Not used in these tests
}

func (c *MockConnection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		if _, err := c.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// MockDispatcher implements routing.Dispatcher
type MockDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *MockDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if d.OnDispatch != nil {
		return d.OnDispatch(ctx, dest)
	}
	return nil, nil
}

func (d *MockDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return nil
}

func (d *MockDispatcher) Start() error { return nil }
func (d *MockDispatcher) Close() error { return nil }
func (d *MockDispatcher) Type() interface{} {
	return (*routing.Dispatcher)(nil)
}

func TestEncryption(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	session, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	original := []byte("test data for encryption")

	// Test Write and Read through a pipe
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		err := session.WriteFrame(c1, reflex.FrameTypeData, original)
		if err != nil {
			t.Errorf("WriteFrame failed: %v", err)
		}
	}()

	s2, _ := reflex.NewSession(key)
	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if string(frame.Payload) != string(original) {
		t.Errorf("payload mismatch: expected %s, got %s", string(original), string(frame.Payload))
	}
}

func TestHandshakeLogic(t *testing.T) {
	userID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: userID.String(), Policy: "youtube"},
		},
	}

	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	// Prepare Handshake
	_, pub, _ := reflex.GenerateKeyPair()
	nonce := [16]byte{}
	rand.Read(nonce[:])

	var uID [16]byte
	copy(uID[:], userID.Bytes())
	clientHS := reflex.ClientHandshake{
		PublicKey: pub,
		UserID:    uID,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	// Mock Connection and Dispatcher
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	dispatcher := &MockDispatcher{}

	errChan := make(chan error, 1)
	go func() {
		errChan <- handler.processHandshake(context.Background(), bufio.NewReader(c2), &MockConnection{Conn: c2}, dispatcher, clientHS)
	}()

	// Read server response
	resp := make([]byte, 1024)
	n, err := c1.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("empty response")
	}
}

func TestReplayProtection(t *testing.T) {
	userID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: userID.String()},
		},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	nonce := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// First time - should pass
	if !handler.replayFilter.Check(nonce[:]) {
		t.Fatal("first check should pass")
	}

	// Second time - should fail
	if handler.replayFilter.Check(nonce[:]) {
		t.Fatal("replay should be detected")
	}
}

func TestEmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		session.WriteFrame(c1, reflex.FrameTypeData, []byte{})
	}()

	s2, _ := reflex.NewSession(key)
	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.Payload) != 0 {
		t.Fatal("payload should be empty")
	}
}

func TestLargeData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)

	largeData := make([]byte, 16384) // 16KB
	rand.Read(largeData)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		session.WriteFrame(c1, reflex.FrameTypeData, largeData)
	}()

	s2, _ := reflex.NewSession(key)
	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.Payload) != len(largeData) {
		t.Fatalf("size mismatch: %d != %d", len(frame.Payload), len(largeData))
	}
}

func TestFallbackIntegrated(t *testing.T) {
	// 1. Start a "real" web server for fallback
	fallbackListener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fallbackListener.Close()
	fallbackPort := uint32(fallbackListener.Addr().(*stdnet.TCPAddr).Port)

	go func() {
		for {
			conn, err := fallbackListener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nFallback Content"))
			conn.Close()
		}
	}()

	// 2. Setup Reflex Handler with Fallback
	config := &reflex.InboundConfig{
		Fallback: &reflex.Fallback{
			Dest: fallbackPort,
		},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	// 3. Connect with NON-Reflex traffic (e.g. standard HTTP GET)
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		handler.Process(context.Background(), net.Network_TCP, &MockConnection{Conn: c2}, nil)
	}()

	c1.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Test)\r\n\r\n"))

	resp := make([]byte, 1024)
	n, err := c1.Read(resp)
	if err != nil {
		t.Fatal(err)
	}

	if !stdnet.IP(resp[:4]).IsUnspecified() && string(resp[:n]) != "HTTP/1.1 200 OK\r\n\r\nFallback Content" {
		t.Errorf("expected fallback content, got %s", string(resp[:n]))
	}
}

func TestInvalidUserHandshake(t *testing.T) {
	u := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: u.String()},
		},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	// Prepare Handshake with WRONG UserID
	_, pub, _ := reflex.GenerateKeyPair()
	wrongUserID := uuid.New()
	var uID [16]byte
	copy(uID[:], wrongUserID.Bytes())

	clientHS := reflex.ClientHandshake{
		PublicKey: pub,
		UserID:    uID,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{1, 2, 3},
	}

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Since it's invalid, it SHOULD go to fallback.
	// We don't have fallback set here, so it should return error.
	err := handler.processHandshake(context.Background(), bufio.NewReader(c2), &MockConnection{Conn: c2}, nil, clientHS)
	if err == nil || !strings.Contains(err.Error(), "reflex: access denied (no fallback)") {
		t.Errorf("expected access denied error, got %v", err)
	}
}

func TestOldTimestampHandshake(t *testing.T) {
	u := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: u.String()},
		},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Write Handshake with OLD Timestamp
	go func() {
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, reflex.ReflexMagic)
		c1.Write(magic)
		c1.Write(make([]byte, 32))                                        // PK
		c1.Write(make([]byte, 16))                                        // UserID
		binary.Write(c1, binary.BigEndian, int64(time.Now().Unix()-1000)) // Old
		c1.Write(make([]byte, 16))                                        // Nonce
	}()

	err := handler.processWithReader(context.Background(), bufio.NewReader(c2), &MockConnection{Conn: c2}, nil)
	if err == nil || !strings.Contains(err.Error(), "reflex: access denied (no fallback)") {
		t.Errorf("expected fallback error due to old timestamp, got %v", err)
	}
}

func TestIncompleteHandshake(t *testing.T) {
	config := &reflex.InboundConfig{}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	c1, c2 := stdnet.Pipe()
	go func() {
		c1.Write([]byte("POST /api"))
		c1.Close()
	}()

	err := handler.Process(context.Background(), net.Network_TCP, &MockConnection{Conn: c2}, nil)
	if err == nil {
		t.Fatal("should handle incomplete handshake")
	}
}

func TestHandleControlFrame(t *testing.T) {
	profile := reflex.Profiles["youtube"]
	session, _ := reflex.NewSession(make([]byte, 32))

	// Test Padding Frame
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, 1337)
	frame := &reflex.Frame{Type: reflex.FrameTypePadding, Payload: payload}
	// HandleControlFrame is a method on Session. If Session is reflex.Session, we can call it.
	// BUT HandleControlFrame was defined in encoding.go which I recreated in reflex package.
	// So session.HandleControlFrame works.
	session.HandleControlFrame(frame, profile)
	if profile.GetPacketSize() != 1337 {
		t.Errorf("expected packet size 1337, got %d", profile.GetPacketSize())
	}

	// Test Timing Frame
	payload = make([]byte, 8)
	binary.BigEndian.PutUint64(payload, 500)
	frame = &reflex.Frame{Type: reflex.FrameTypeTiming, Payload: payload}
	session.HandleControlFrame(frame, profile)
	if profile.GetDelay() != 500*time.Millisecond {
		t.Errorf("expected delay 500ms, got %v", profile.GetDelay())
	}
}

func TestMorphingRecursion(t *testing.T) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)
	profile := reflex.Profiles["zoom"]

	data := make([]byte, 2000) // Much larger than target size
	rand.Read(data)

	c1, c2 := stdnet.Pipe()
	go func() {
		session.WriteFrameWithMorphing(c1, reflex.FrameTypeData, data, profile)
		c1.Close()
	}()

	// Read morphed frames
	s2, _ := reflex.NewSession(key)
	r2 := bufio.NewReader(c2)

	readTotal := 0
	for {
		frame, err := s2.ReadFrame(r2)
		if err != nil {
			break
		}
		readTotal += len(frame.Payload)
	}

	if readTotal < 2000 {
		t.Errorf("read total %d < 2000", readTotal)
	}
}

func BenchmarkEncryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)
	data := make([]byte, 1024)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.WriteFrame(c1, reflex.FrameTypeData, data)
	}
}

func BenchmarkEncryptionSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384}
	key := make([]byte, 32)
	rand.Read(key)

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			session, _ := reflex.NewSession(key)
			data := make([]byte, size)
			c1, c2 := stdnet.Pipe()
			defer c1.Close()
			defer c2.Close()

			go func() {
				buf := make([]byte, size+256)
				for {
					_, err := c2.Read(buf)
					if err != nil {
						return
					}
				}
			}()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				session.WriteFrame(c1, reflex.FrameTypeData, data)
			}
		})
	}
}

func BenchmarkMemoryAllocation(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)
	data := make([]byte, 1024)
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.WriteFrame(c1, reflex.FrameTypeData, data)
	}
}
