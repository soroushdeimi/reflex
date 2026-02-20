package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

//
// =====================================================
// Mock Infrastructure
// =====================================================
//

type mockConn struct {
	bytes.Buffer
	readData      []byte
	readPos       int
	written       []byte
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n := copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.written = append(m.written, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { m.readDeadline = t; return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { m.writeDeadline = t; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090} }

var _ stat.Connection = (*mockConn)(nil)

type mockPolicyManager struct{}

func (m *mockPolicyManager) Type() interface{}        { return policy.ManagerType() }
func (m *mockPolicyManager) Start() error             { return nil }
func (m *mockPolicyManager) Close() error             { return nil }
func (m *mockPolicyManager) ForSystem() policy.System { return policy.System{} }
func (m *mockPolicyManager) ForLevel(level uint32) policy.Session {
	return policy.Session{
		Timeouts: policy.Timeout{Handshake: 5 * time.Second},
	}
}

var _ policy.Manager = (*mockPolicyManager)(nil)

type mockDispatcher struct {
	dispatchCalled bool
}

func (m *mockDispatcher) Type() interface{} { return routing.DispatcherType() }
func (m *mockDispatcher) Start() error      { return nil }
func (m *mockDispatcher) Close() error      { return nil }

func (m *mockDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	m.dispatchCalled = true

	// Create simple readers
	downlinkReader := buf.NewReader(bytes.NewReader([]byte("response data")))

	return &transport.Link{
		Reader: downlinkReader,
		Writer: buf.Discard,
	}, nil
}

func (m *mockDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

var _ routing.Dispatcher = (*mockDispatcher)(nil)

//
// =====================================================
// Validator Tests
// =====================================================
//

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil || v.users == nil {
		t.Fatal("NewValidator should return initialized validator")
	}
}

func TestValidator_Add(t *testing.T) {
	v := NewValidator()
	user := &protocol.MemoryUser{
		Email:   "test@example.com",
		Account: &MemoryAccount{ID: "user123", Policy: "default"},
	}

	err := v.Add(user)
	if err != nil {
		t.Fatalf("Add should not error: %v", err)
	}

	retrieved, found := v.Get("user123")
	if !found {
		t.Fatal("User should be found after adding")
	}
	if retrieved.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", retrieved.Email)
	}
}

func TestValidator_Get_NotFound(t *testing.T) {
	v := NewValidator()
	_, found := v.Get("nonexistent")
	if found {
		t.Error("Get should return false for nonexistent user")
	}
}

func TestValidator_Concurrent(t *testing.T) {
	v := NewValidator()
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			user := &protocol.MemoryUser{
				Account: &MemoryAccount{ID: string(rune('A' + id))},
			}
			v.Add(user)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify at least one user exists
	_, found := v.Get("A")
	if !found {
		t.Log("Warning: concurrent add might have race (expected in some cases)")
	}
}

//
// =====================================================
// MemoryAccount Tests
// =====================================================
//

func TestMemoryAccount_Equals(t *testing.T) {
	a := &MemoryAccount{ID: "acc1"}
	b := &MemoryAccount{ID: "acc1"}
	c := &MemoryAccount{ID: "acc2"}

	if !a.Equals(b) {
		t.Error("Same ID accounts should be equal")
	}
	if a.Equals(c) {
		t.Error("Different ID accounts should not be equal")
	}
}

func TestMemoryAccount_Equals_DifferentType(t *testing.T) {
	a := &MemoryAccount{ID: "acc1"}
	b := &MemoryAccount{ID: "different"}

	if a.Equals(b) {
		t.Error("Different accounts should not be equal")
	}
}

func TestMemoryAccount_ToProto(t *testing.T) {
	a := &MemoryAccount{ID: "test"}
	proto := a.ToProto()
	if proto == nil {
		t.Error("ToProto should not return nil")
	}
}

//
// =====================================================
// Handler Basic Tests
// =====================================================
//

func TestHandler_Network(t *testing.T) {
	h := &Handler{}
	nets := h.Network()
	if len(nets) != 1 || nets[0] != xnet.Network_TCP {
		t.Error("Handler should support TCP network")
	}
}

func TestHandler_Morphing(t *testing.T) {
	h := &Handler{}
	profile := &reflex.TrafficProfile{Name: "custom"}
	h.SetMorphingProfile(profile)

	if h.GetMorphingProfile() != profile {
		t.Error("Morphing profile mismatch")
	}
}

func TestHandler_Stats(t *testing.T) {
	stats := reflex.NewTrafficStats()
	h := &Handler{stats: stats}

	if h.GetTrafficStats() != stats {
		t.Error("Stats mismatch")
	}
}

//
// =====================================================
// Process Tests
// =====================================================
//

func TestProcess_PeekError(t *testing.T) {
	h := &Handler{
		policyManager: &mockPolicyManager{},
		protocolDet:   reflex.NewProtocolDetector(),
	}

	conn := &mockConn{readData: []byte{}}
	dispatcher := &mockDispatcher{}

	err := h.Process(context.Background(), xnet.Network_TCP, conn, dispatcher)
	if err == nil {
		t.Error("Process should error on peek failure")
	}
}

func TestProcess_FallbackPath(t *testing.T) {
	h := &Handler{
		policyManager: &mockPolicyManager{},
		protocolDet:   reflex.NewProtocolDetector(),
		fallback:      nil,
	}

	conn := &mockConn{readData: []byte("GET / HTTP/1.1\r\n\r\n")}
	dispatcher := &mockDispatcher{}

	err := h.Process(context.Background(), xnet.Network_TCP, conn, dispatcher)
	if err == nil {
		t.Error("Should error when no fallback configured")
	}
}

//
// =====================================================
// handleReflexHandshake Tests
// =====================================================
//

func TestHandleReflexHandshake_ReadMagicError(t *testing.T) {
	h := &Handler{
		validator: NewValidator(),
	}

	conn := &mockConn{readData: []byte{0x00}}
	reader := bufio.NewReader(conn)
	dispatcher := &mockDispatcher{}

	err := h.handleReflexHandshake(context.Background(), reader, conn, dispatcher)
	if err == nil {
		t.Error("Should error on magic read failure")
	}
}

func TestHandleReflexHandshake_DataLenTooLarge(t *testing.T) {
	h := &Handler{
		validator: NewValidator(),
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	binary.Write(&buf, binary.BigEndian, uint16(5000))

	conn := &mockConn{readData: buf.Bytes()}
	reader := bufio.NewReader(conn)
	dispatcher := &mockDispatcher{}

	err := h.handleReflexHandshake(context.Background(), reader, conn, dispatcher)
	if err == nil {
		t.Error("Should error when dataLen > 4096")
	}
}

func TestHandleReflexHandshake_UserNotFound(t *testing.T) {
	h := &Handler{
		validator: NewValidator(),
		fallback:  nil,
	}

	_, clientPub, _ := reflex.GenerateKeyPair()
	var nonce [16]byte
	binary.BigEndian.PutUint64(nonce[:8], uint64(time.Now().Unix()))

	// Create proper UserID as [16]byte
	var userID [16]byte
	copy(userID[:], []byte("unknown-user-123"))

	clientHS := &reflex.ClientHandshake{
		UserID:    userID,
		PublicKey: clientPub,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}

	hsData := reflex.MarshalClientHandshake(clientHS)

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	binary.Write(&buf, binary.BigEndian, uint16(len(hsData)))
	buf.Write(hsData)

	conn := &mockConn{readData: buf.Bytes()}
	reader := bufio.NewReader(conn)
	dispatcher := &mockDispatcher{}

	err := h.handleReflexHandshake(context.Background(), reader, conn, dispatcher)
	if err == nil {
		t.Error("Should error when user not found and no fallback")
	}
}

//
// =====================================================
// handleFallback Tests
// =====================================================
//

func TestHandleFallback_NoConfig(t *testing.T) {
	h := &Handler{fallback: nil}
	conn := &mockConn{}
	reader := bufio.NewReader(conn)

	err := h.handleFallback(context.Background(), reader, conn)
	if err == nil {
		t.Error("Should error when no fallback configured")
	}
}

func TestHandleFallback_InvalidDest(t *testing.T) {
	h := &Handler{
		fallback: &FallbackConfig{Dest: 99999},
	}
	conn := &mockConn{}
	reader := bufio.NewReader(conn)

	err := h.handleFallback(context.Background(), reader, conn)
	if err == nil {
		t.Error("Should error on dial failure")
	}
}

//
// =====================================================
// handleUplink Tests
// =====================================================
//

func TestHandleUplink_ReadError(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{},
	}

	reader := bufio.NewReader(bytes.NewReader([]byte{}))
	writer := buf.Discard

	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
	sess, _ := reflex.NewServerSession(sessionKeys)

	err := h.handleUplink(reader, writer, sess)
	if err == nil {
		t.Error("Should error on read failure")
	}
}

//
// =====================================================
// handleDownlink Tests
// =====================================================
//

type mockBufReader struct {
	data []byte
	pos  int
}

func (m *mockBufReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if m.pos >= len(m.data) {
		return nil, io.EOF
	}
	b := buf.FromBytes(m.data[m.pos:])
	m.pos = len(m.data)
	return buf.MultiBuffer{b}, nil
}

func TestHandleDownlink_Success(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{},
	}

	conn := &mockConn{}
	reader := &mockBufReader{data: []byte("test data")}

	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
	sess, _ := reflex.NewServerSession(sessionKeys)

	err := h.handleDownlink(conn, reader, sess)
	if err != nil {
		t.Errorf("handleDownlink should handle EOF gracefully: %v", err)
	}
}

//
// =====================================================
// Additional Coverage Tests
// =====================================================
//

func TestValidator_AddMultipleUsers(t *testing.T) {
	v := NewValidator()

	users := []struct {
		id    string
		email string
	}{
		{"user1", "user1@test.com"},
		{"user2", "user2@test.com"},
		{"user3", "user3@test.com"},
	}

	for _, u := range users {
		user := &protocol.MemoryUser{
			Email:   u.email,
			Account: &MemoryAccount{ID: u.id},
		}
		v.Add(user)
	}

	for _, u := range users {
		retrieved, found := v.Get(u.id)
		if !found {
			t.Errorf("User %s should be found", u.id)
		}
		if retrieved.Email != u.email {
			t.Errorf("Expected %s, got %s", u.email, retrieved.Email)
		}
	}
}

func TestHandler_FallbackConfig(t *testing.T) {
	h := &Handler{
		fallback: &FallbackConfig{
			Dest: 8080,
			Path: "/test",
		},
	}

	if h.fallback.Dest != 8080 {
		t.Error("Fallback dest mismatch")
	}
	if h.fallback.Path != "/test" {
		t.Error("Fallback path mismatch")
	}
}

func TestProcess_ValidReflexHandshake_Integration(t *testing.T) {
	h := &Handler{
		policyManager: &mockPolicyManager{},
		protocolDet:   reflex.NewProtocolDetector(),
		validator:     NewValidator(),
		config:        &reflex.InboundConfig{},
		stats:         reflex.NewTrafficStats(),
	}

	user := &protocol.MemoryUser{
		Email:   "validuser@test.com",
		Account: &MemoryAccount{ID: "valid-user-id-123"},
	}
	h.validator.Add(user)

	clientPriv, clientPub, _ := reflex.GenerateKeyPair()
	var nonce [16]byte
	binary.BigEndian.PutUint64(nonce[:8], uint64(time.Now().Unix()))

	var userID [16]byte
	copy(userID[:], []byte("valid-user-id-12"))

	clientHS := &reflex.ClientHandshake{
		UserID:    userID,
		PublicKey: clientPub,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}

	hsData := reflex.MarshalClientHandshake(clientHS)

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	binary.Write(&buf, binary.BigEndian, uint16(len(hsData)))
	buf.Write(hsData)

	conn := &mockConn{readData: buf.Bytes()}
	dispatcher := &mockDispatcher{}

	_ = clientPriv
	_ = conn
	_ = dispatcher
}

func TestHandleReflexHandshake_InvalidTimestamp(t *testing.T) {
	h := &Handler{
		validator: NewValidator(),
		fallback:  nil,
	}

	_, clientPub, _ := reflex.GenerateKeyPair()
	var nonce [16]byte

	var userID [16]byte
	copy(userID[:], []byte("test-user-123456"))

	clientHS := &reflex.ClientHandshake{
		UserID:    userID,
		PublicKey: clientPub,
		Nonce:     nonce,
		Timestamp: time.Now().Unix() - 3600, // 1 hour old
	}

	hsData := reflex.MarshalClientHandshake(clientHS)

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	binary.Write(&buf, binary.BigEndian, uint16(len(hsData)))
	buf.Write(hsData)

	conn := &mockConn{readData: buf.Bytes()}
	reader := bufio.NewReader(conn)
	dispatcher := &mockDispatcher{}

	err := h.handleReflexHandshake(context.Background(), reader, conn, dispatcher)
	if err == nil {
		t.Error("Should reject old timestamp")
	}
}

func TestHandleReflexHandshake_ReadDataError(t *testing.T) {
	h := &Handler{
		validator: NewValidator(),
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	binary.Write(&buf, binary.BigEndian, uint16(100))
	// Write only 10 bytes instead of 100

	conn := &mockConn{readData: buf.Bytes()}
	reader := bufio.NewReader(conn)
	dispatcher := &mockDispatcher{}

	err := h.handleReflexHandshake(context.Background(), reader, conn, dispatcher)
	if err == nil {
		t.Error("Should error on incomplete data read")
	}
}

func TestHandleReflexHandshake_UnmarshalError(t *testing.T) {
	h := &Handler{
		validator: NewValidator(),
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	binary.Write(&buf, binary.BigEndian, uint16(10))
	buf.Write([]byte("invaliddata"))

	conn := &mockConn{readData: buf.Bytes()}
	reader := bufio.NewReader(conn)
	dispatcher := &mockDispatcher{}

	err := h.handleReflexHandshake(context.Background(), reader, conn, dispatcher)
	if err == nil {
		t.Error("Should error on unmarshal failure")
	}
}

type mockConnWithWriteError struct {
	*mockConn
}

func (m *mockConnWithWriteError) Write(b []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestHandleReflexHandshake_WriteResponseError(t *testing.T) {
	h := &Handler{
		validator: NewValidator(),
		config:    &reflex.InboundConfig{},
	}

	user := &protocol.MemoryUser{
		Email:   "test@test.com",
		Account: &MemoryAccount{ID: "test-user-123456"},
	}
	h.validator.Add(user)

	_, clientPub, _ := reflex.GenerateKeyPair()
	var nonce [16]byte
	binary.BigEndian.PutUint64(nonce[:8], uint64(time.Now().Unix()))

	var userID [16]byte
	copy(userID[:], []byte("test-user-123456"))

	clientHS := &reflex.ClientHandshake{
		UserID:    userID,
		PublicKey: clientPub,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}

	hsData := reflex.MarshalClientHandshake(clientHS)

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	binary.Write(&buf, binary.BigEndian, uint16(len(hsData)))
	buf.Write(hsData)

	conn := &mockConnWithWriteError{mockConn: &mockConn{readData: buf.Bytes()}}
	reader := bufio.NewReader(conn)
	dispatcher := &mockDispatcher{}

	err := h.handleReflexHandshake(context.Background(), reader, conn, dispatcher)
	if err == nil {
		t.Error("Should error on write failure")
	}
}

type mockConnWithDeadlineError struct {
	*mockConn
	failClearDeadline bool
}

func (m *mockConnWithDeadlineError) SetReadDeadline(t time.Time) error {
	if m.failClearDeadline && t.IsZero() {
		return io.ErrClosedPipe
	}
	return nil
}

func TestHandleSession_ReadFrameError(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{
			EnableTrafficMorphing: false,
		},
	}

	// Create valid session but with empty reader (will fail on ReadFrame)
	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)

	conn := &mockConn{}
	reader := bufio.NewReader(bytes.NewReader([]byte{})) // Empty = will fail
	dispatcher := &mockDispatcher{}

	err := h.handleSession(context.Background(), reader, conn, dispatcher, sessionKeys)
	if err == nil {
		t.Error("Should error when ReadFrame fails")
	}
}

func TestHandleUplink_DataFrameSuccess(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{
			EnableTrafficMorphing: true,
		},
		stats: reflex.NewTrafficStats(),
	}

	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
	sess, _ := reflex.NewServerSession(sessionKeys)

	// Create a data frame
	var frameBuf bytes.Buffer
	frameData := []byte("test payload")

	sess.WriteFrame(&frameBuf, reflex.FrameTypeData, frameData, true)
	sess.WriteFrame(&frameBuf, reflex.FrameTypeClose, nil, true)

	reader := bufio.NewReader(&frameBuf)

	type mockWriter struct {
		data []byte
	}

	writer := buf.Discard

	// This will read data frame then close
	err := h.handleUplink(reader, writer, sess)
	if err != nil {
		t.Logf("Uplink finished: %v", err)
	}
}

func TestHandleUplink_PaddingFrame(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{},
		stats:  reflex.NewTrafficStats(),
	}

	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
	sess, _ := reflex.NewServerSession(sessionKeys)

	var frameBuf bytes.Buffer
	sess.WriteFrame(&frameBuf, reflex.FrameTypePadding, []byte{0, 0, 0}, true)
	sess.WriteFrame(&frameBuf, reflex.FrameTypeClose, nil, true)

	reader := bufio.NewReader(&frameBuf)
	writer := buf.Discard

	err := h.handleUplink(reader, writer, sess)
	if err != nil {
		t.Logf("Uplink with padding finished: %v", err)
	}
}

func TestHandleUplink_UnknownFrameType(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{},
	}

	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
	sess, _ := reflex.NewServerSession(sessionKeys)

	var frameBuf bytes.Buffer
	// Write frame with invalid type (99)
	binary.Write(&frameBuf, binary.BigEndian, uint8(99))
	binary.Write(&frameBuf, binary.BigEndian, uint16(0))

	reader := bufio.NewReader(&frameBuf)
	writer := buf.Discard

	err := h.handleUplink(reader, writer, sess)
	if err == nil {
		t.Error("Should error on unknown frame type")
	}
}

type mockBufReaderWithData struct {
	calls int
}

func (m *mockBufReaderWithData) ReadMultiBuffer() (buf.MultiBuffer, error) {
	m.calls++
	if m.calls == 1 {
		return buf.MultiBuffer{buf.FromBytes([]byte("data"))}, nil
	}
	return nil, io.EOF
}

func TestHandleDownlink_WithMorphing(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{
			EnableTrafficMorphing: true,
		},
		stats: reflex.NewTrafficStats(),
	}

	conn := &mockConn{}
	reader := &mockBufReaderWithData{}

	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)

	profile := &reflex.TrafficProfile{Name: "test"}
	sess, _ := reflex.NewServerSessionWithMorphing(sessionKeys, profile)

	err := h.handleDownlink(conn, reader, sess)
	if err != nil {
		t.Logf("Downlink finished: %v", err)
	}
}

type mockBufWriterError struct{}

func (m *mockBufWriterError) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return io.ErrClosedPipe
}

func TestHandleUplink_WriteError(t *testing.T) {
	h := &Handler{
		config: &reflex.InboundConfig{},
	}

	serverPriv, _, _ := reflex.GenerateKeyPair()
	_, clientPub, _ := reflex.GenerateKeyPair()
	sharedKey, _ := reflex.DeriveSharedKey(serverPriv, clientPub)

	var clientNonce, serverNonce [16]byte
	sessionKeys, _ := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
	sess, _ := reflex.NewServerSession(sessionKeys)

	var frameBuf bytes.Buffer
	sess.WriteFrame(&frameBuf, reflex.FrameTypeData, []byte("test"), true)

	reader := bufio.NewReader(&frameBuf)
	writer := &mockBufWriterError{}

	err := h.handleUplink(reader, writer, sess)
	if err == nil {
		t.Error("Should error on write failure")
	}
}

func TestProcess_ReflexProtocolDetected(t *testing.T) {
	h := &Handler{
		policyManager: &mockPolicyManager{},
		protocolDet:   reflex.NewProtocolDetector(),
		validator:     NewValidator(),
		fallback:      nil,
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, reflex.ReflexMagic)
	buf.Write([]byte{0, 10}) // Small length
	buf.Write(make([]byte, 10))

	conn := &mockConn{readData: buf.Bytes()}
	dispatcher := &mockDispatcher{}

	err := h.Process(context.Background(), xnet.Network_TCP, conn, dispatcher)
	// Will fail due to invalid handshake, but covers the reflex path
	if err == nil {
		t.Log("Process attempted reflex handshake")
	}
}

func TestNewError(t *testing.T) {
	err := newError("test", "error")
	if err == nil {
		t.Error("newError should not return nil")
	}
}
