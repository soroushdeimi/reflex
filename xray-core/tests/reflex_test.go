package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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

// mockDispatcher implements routing.Dispatcher for tests. Dispatch returns (nil, err) so no real upstream.
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

	// Client: generate key pair, build handshake with userUUID, send handshake, read HTTP 200 + body, derive session key, send CLOSE frame.
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

		// Read HTTP response (status + headers + body).
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

// TestFallback verifies that non-Reflex traffic is forwarded to the fallback server.
func TestFallback(t *testing.T) {
	// Fallback server: accepts and responds with 200 OK.
	fallbackLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer fallbackLn.Close()
	fallbackPort := uint32(fallbackLn.Addr().(*net.TCPAddr).Port)
	go func() {
		conn, _ := fallbackLn.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 && strings.HasPrefix(string(buf[:n]), "GET ") {
			conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}
	}()

	config := &reflex.InboundConfig{
		Clients:  nil,
		Fallback: &reflex.Fallback{Dest: fallbackPort},
	}
	handler, err := inbound.New(context.Background(), config)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Reflex handler as TCP server so we can half-close the client.
	reflexLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen reflex: %v", err)
	}
	defer reflexLn.Close()
	go func() {
		conn, _ := reflexLn.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		_ = handler.Process(context.Background(), xnet.Network_TCP, pipeToStat(conn), &mockDispatcher{})
	}()

	clientConn, err := net.Dial("tcp", reflexLn.Addr().String())
	if err != nil {
		t.Fatalf("dial reflex: %v", err)
	}
	defer clientConn.Close()
	tcpConn := clientConn.(*net.TCPConn)

	// Handler peeks 64 bytes; send at least that, then half-close so handler sees EOF.
	req := []byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	if len(req) < 64 {
		req = append(req, make([]byte, 64-len(req))...)
	}
	_, err = tcpConn.Write(req)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = tcpConn.CloseWrite()
	resp, err := io.ReadAll(tcpConn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(resp, []byte("200")) || !bytes.Contains(resp, []byte("OK")) {
		t.Errorf("expected 200 OK from fallback, got: %s", resp)
	}
}

// TestReplayProtection verifies that replaying the same encrypted frame fails (wrong nonce).
func TestReplayProtection(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, []byte("once")); err != nil {
		t.Fatal(err)
	}
	frameBytes := buf.Bytes()

	readSess, _ := reflex.NewSession(key)
	// First read: must succeed.
	_, err = readSess.ReadFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	// Replay same bytes: must fail (nonce reuse).
	_, err = readSess.ReadFrame(bytes.NewReader(frameBytes))
	if err == nil {
		t.Fatal("replay should have failed (decrypt with wrong nonce)")
	}
}

// TestSessionEncryptDecrypt ensures that a single frame written by Session
// can be read back and decrypted to the original payload.
func TestSessionEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	payload := []byte("hello reflex")
	var buf bytes.Buffer

	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	readSess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession (read) failed: %v", err)
	}

	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("unexpected frame type: got %d, want %d", frame.Type, reflex.FrameTypeData)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, payload)
	}
}

// TestTrafficProfileBasic ensures the basic profile APIs return sane values
// and that morphing write still produces a readable frame. Uses a deterministic
// profile (single size) so that padded length is predictable.
func TestTrafficProfileBasic(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Single size/delay so GetPacketSize/GetDelay are deterministic.
	profile := &reflex.TrafficProfile{
		PacketSizes: []reflex.PacketSizeDist{{Size: 600, Weight: 1}},
		Delays:      []reflex.DelayDist{{Delay: 5 * time.Millisecond, Weight: 1}},
	}

	size := profile.GetPacketSize()
	if size != 600 {
		t.Fatalf("GetPacketSize returned %d, want 600", size)
	}

	var buf bytes.Buffer
	data := []byte("morph-test")
	if err := sess.WriteFrameWithMorphing(&buf, reflex.FrameTypeData, data, profile); err != nil {
		t.Fatalf("WriteFrameWithMorphing failed: %v", err)
	}

	readSess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession (read) failed: %v", err)
	}

	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("unexpected frame type: got %d, want %d", frame.Type, reflex.FrameTypeData)
	}
	// Morphed payload format: [2 bytes BE length][original data][padding]; total padded to target+2.
	if len(frame.Payload) != 602 {
		t.Fatalf("expected morphed payload size 602 (2+600), got %d", len(frame.Payload))
	}
	payload, ok := reflex.StripMorphingPrefix(frame.Payload)
	if !ok {
		t.Fatalf("StripMorphingPrefix failed")
	}
	if !bytes.Equal(payload, data) {
		t.Fatalf("stripped payload should equal original data %q, got %q", data, payload)
	}
}

// TestDecodeClientHandshakePacket verifies that encoding and then decoding
// a handshake packet round-trips correctly.
func TestDecodeClientHandshakePacket(t *testing.T) {
	var hs reflex.ClientHandshake
	copy(hs.PublicKey[:], bytes.Repeat([]byte{0x11}, 32))
	copy(hs.UserID[:], bytes.Repeat([]byte{0x22}, 16))
	hs.PolicyReq = []byte{0x33, 0x44}
	hs.Timestamp = 123456789

	packet := &reflex.ClientHandshakePacket{
		Magic:     reflex.ReflexMagic,
		Handshake: hs,
	}

	data := reflex.EncodeClientHandshakePacket(packet)
	decoded, err := reflex.DecodeClientHandshakePacket(data)
	if err != nil {
		t.Fatalf("DecodeClientHandshakePacket failed: %v", err)
	}

	if decoded.Magic != reflex.ReflexMagic {
		t.Fatalf("magic mismatch: got %x, want %x", decoded.Magic, reflex.ReflexMagic)
	}
	if decoded.Handshake.Timestamp != hs.Timestamp {
		t.Fatalf("timestamp mismatch: got %d, want %d", decoded.Handshake.Timestamp, hs.Timestamp)
	}
	if !bytes.Equal(decoded.Handshake.PolicyReq, hs.PolicyReq) {
		t.Fatalf("policyReq mismatch: got %v, want %v", decoded.Handshake.PolicyReq, hs.PolicyReq)
	}
}

// TestSessionControlFrames verifies that padding/timing control frames update
// the profile via HandleControlFrame.
func TestSessionControlFrames(t *testing.T) {
	profile := &reflex.TrafficProfile{
		PacketSizes: []reflex.PacketSizeDist{{Size: 1000, Weight: 1}},
		Delays:      []reflex.DelayDist{{Delay: 10 * time.Millisecond, Weight: 1}},
	}

	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Padding control frame: set size to 512
	paddingPayload := make([]byte, 2)
	binary.BigEndian.PutUint16(paddingPayload, 512)
	paddingFrame := &reflex.Frame{Type: reflex.FrameTypePadding, Payload: paddingPayload}
	sess.HandleControlFrame(paddingFrame, profile)

	if got := profile.GetPacketSize(); got != 512 {
		t.Fatalf("expected next packet size override 512, got %d", got)
	}
}

// TestEmptyData verifies WriteFrame/ReadFrame with empty payload does not crash.
func TestEmptyData(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, []byte{}); err != nil {
		t.Fatalf("WriteFrame empty: %v", err)
	}
	readSess, _ := reflex.NewSession(key)
	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(frame.Payload) != 0 {
		t.Fatalf("expected empty payload, got len %d", len(frame.Payload))
	}
}

// TestLargeData verifies a large payload within single-frame limit is handled.
// Frame length is uint16 (max 65535); encrypted = payload + 16, so max payload 65519.
func TestLargeData(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	const maxPayload = 65519
	largeData := make([]byte, maxPayload)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	var buf bytes.Buffer
	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, largeData); err != nil {
		t.Fatalf("WriteFrame large: %v", err)
	}
	readSess, _ := reflex.NewSession(key)
	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(frame.Payload, largeData) {
		t.Fatal("large payload mismatch")
	}
}

// TestClosedConnection verifies WriteFrame to a closed connection returns an error.
func TestClosedConnection(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	serverConn.Close()
	_, _ = clientConn.Write(nil)
	clientConn.Close()
	closedConn, _ := net.Pipe()
	closedConn.Close()
	err = sess.WriteFrame(closedConn, reflex.FrameTypeData, []byte("test"))
	if err == nil {
		t.Fatal("expected error when writing to closed connection")
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
	// No fallback configured, so we expect "no fallback configured" or similar.
	if err != nil && !strings.Contains(err.Error(), "fallback") {
		// Process might also return nil if fallback path runs and connection closes
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

// TestConnectionReset verifies that closing the connection during write is handled without panic.
func TestConnectionReset(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	go func() {
		_ = sess.WriteFrame(clientConn, reflex.FrameTypeData, []byte("test"))
	}()
	time.Sleep(10 * time.Millisecond)
	serverConn.Close()
	clientConn.Close()
	// Should not panic; goroutine may get write error.
}

// TestOversizedPayload verifies the maximum single-frame payload (65519 bytes) round-trips.
func TestOversizedPayload(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	const maxPayload = 65519
	hugeData := make([]byte, maxPayload)
	for i := range hugeData {
		hugeData[i] = byte(i & 0xff)
	}
	var buf bytes.Buffer
	err = sess.WriteFrame(&buf, reflex.FrameTypeData, hugeData)
	if err != nil {
		t.Fatalf("WriteFrame max payload: %v", err)
	}
	readSess, _ := reflex.NewSession(key)
	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(frame.Payload) != len(hugeData) {
		t.Fatalf("payload len %d, want %d", len(frame.Payload), len(hugeData))
	}
	if !bytes.Equal(frame.Payload, hugeData) {
		t.Fatal("payload content mismatch")
	}
}

// TestIncompleteHandshake verifies that incomplete data (e.g. "POST /api" then close) is handled.
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

// BenchmarkSessionWriteFrame measures encryption and frame write throughput.
func BenchmarkSessionWriteFrame(b *testing.B) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 1024)
	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = sess.WriteFrame(&buf, reflex.FrameTypeData, data)
	}
}

// BenchmarkEncryptionSizes runs WriteFrame for different payload sizes.
func BenchmarkEncryptionSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			key := make([]byte, 32)
			sess, err := reflex.NewSession(key)
			if err != nil {
				b.Fatal(err)
			}
			data := make([]byte, size)
			var buf bytes.Buffer
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				_ = sess.WriteFrame(&buf, reflex.FrameTypeData, data)
			}
		})
	}
}

// BenchmarkMemoryAllocation reports allocs per op for WriteFrame.
func BenchmarkMemoryAllocation(b *testing.B) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 1024)
	var buf bytes.Buffer
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = sess.WriteFrame(&buf, reflex.FrameTypeData, data)
	}
}
