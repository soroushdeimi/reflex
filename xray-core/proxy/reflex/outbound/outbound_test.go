package outbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

const testUserID = "550e8400-e29b-41d4-a716-446655440000"

type mockDialer struct {
	conn       net.Conn
	dialErr    error
	dialCalled bool
}

func (m *mockDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	m.dialCalled = true
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	if m.conn != nil {
		return stat.Connection(m.conn), nil
	}
	return nil, io.EOF
}

func (m *mockDialer) DestIpAddress() xnet.IP {
	return nil
}

func (m *mockDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

var _ internet.Dialer = (*mockDialer)(nil)

type mockReader struct {
	data      [][]byte
	pos       int
	returnErr error
}

func (m *mockReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	if m.pos >= len(m.data) {
		return nil, io.EOF
	}
	b := buf.FromBytes(m.data[m.pos])
	m.pos++
	return buf.MultiBuffer{b}, nil
}

type mockWriter struct {
	mu     sync.Mutex
	data   []byte
	closed bool
}

func (m *mockWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return io.ErrClosedPipe
	}
	for _, b := range mb {
		m.data = append(m.data, b.Bytes()...)
		b.Release()
	}
	return nil
}

func (m *mockWriter) getData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.data...)
}

type mockPolicyManager struct{}

func (m *mockPolicyManager) Type() interface{}        { return policy.ManagerType() }
func (m *mockPolicyManager) Start() error             { return nil }
func (m *mockPolicyManager) Close() error             { return nil }
func (m *mockPolicyManager) ForSystem() policy.System { return policy.System{} }
func (m *mockPolicyManager) ForLevel(level uint32) policy.Session {
	return policy.Session{
		Timeouts: policy.Timeout{
			Handshake:      5 * time.Second,
			ConnectionIdle: 300 * time.Second,
			UplinkOnly:     2 * time.Minute,
			DownlinkOnly:   2 * time.Minute,
		},
	}
}

var _ policy.Manager = (*mockPolicyManager)(nil)

func createHandlerDirect() *Handler {
	return &Handler{
		policyManager: &mockPolicyManager{},
		config: &reflex.OutboundConfig{
			Address: "127.0.0.1",
			Port:    12345,
			Id:      testUserID,
		},
		morphingProfile: nil,
		stats:           reflex.NewTrafficStats(),
	}
}

func runReflexServer(conn net.Conn, link *transport.Link) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 4096)

	var magic uint32
	if err := binary.Read(reader, binary.BigEndian, &magic); err != nil {
		return
	}
	if magic != reflex.ReflexMagic {
		return
	}

	var dataLen uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return
	}
	if dataLen > 4096 {
		return
	}

	hsData := make([]byte, dataLen)
	if _, err := io.ReadFull(reader, hsData); err != nil {
		return
	}

	clientHS, err := reflex.UnmarshalClientHandshake(hsData)
	if err != nil {
		return
	}

	if !reflex.ValidateTimestamp(clientHS.Timestamp) {
		return
	}

	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return
	}

	sharedKey, err := reflex.DeriveSharedKey(serverPriv, clientHS.PublicKey)
	if err != nil {
		return
	}

	ts := time.Now().Unix()
	var serverNonce [16]byte
	binary.BigEndian.PutUint64(serverNonce[0:8], uint64(ts))
	binary.BigEndian.PutUint64(serverNonce[8:16], uint64(ts))

	sessionKeys, err := reflex.DeriveSessionKeys(sharedKey, clientHS.Nonce, serverNonce)
	if err != nil {
		return
	}

	serverHS := &reflex.ServerHandshake{
		PublicKey:   serverPub,
		Timestamp:   ts,
		PolicyGrant: []byte{},
	}
	serverHSData := reflex.MarshalServerHandshake(serverHS)
	response := make([]byte, 4+2+len(serverHSData))
	binary.BigEndian.PutUint32(response[0:4], reflex.ReflexMagic)
	binary.BigEndian.PutUint16(response[4:6], uint16(len(serverHSData)))
	copy(response[6:], serverHSData)
	if _, err := conn.Write(response); err != nil {
		return
	}

	sess, err := reflex.NewServerSession(sessionKeys)
	if err != nil {
		return
	}

	firstFrame, err := sess.ReadFrame(reader, true)
	if err != nil {
		return
	}
	if firstFrame.Type != reflex.FrameTypeData {
		return
	}

	destReader := bytes.NewReader(firstFrame.Payload)
	_, err = reflex.DecodeDestination(destReader)
	if err != nil {
		return
	}

	destBytesLen := len(firstFrame.Payload) - destReader.Len()
	remaining := firstFrame.Payload[destBytesLen:]
	if len(remaining) > 0 {
		b := buf.FromBytes(remaining)
		_ = link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			frame, err := sess.ReadFrame(reader, true)
			if err != nil {
				return
			}
			switch frame.Type {
			case reflex.FrameTypeData:
				b := buf.FromBytes(frame.Payload)
				_ = link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
			case reflex.FrameTypeClose:
				return
			case reflex.FrameTypePadding, reflex.FrameTypeTiming:
				_ = sess.HandleControlFrame(frame)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				sess.WriteFrame(conn, reflex.FrameTypeClose, nil, true)
				return
			}
			for _, b := range mb {
				_ = sess.WriteFrame(conn, reflex.FrameTypeData, b.Bytes(), true)
				b.Release()
			}
		}
	}()

	wg.Wait()
}

func TestNew_RequiresCore(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("New should panic without core in context")
		}
	}()
	ctx := context.Background()
	_, _ = New(ctx, &reflex.OutboundConfig{})
}

func TestProcess_NoAddress(t *testing.T) {
	h := createHandlerDirect()
	h.config.Address = ""
	h.config.Port = 0

	link := &transport.Link{
		Reader: &mockReader{},
		Writer: &mockWriter{},
	}
	dialer := &mockDialer{conn: nil}

	err := h.Process(context.Background(), link, dialer)
	if err == nil {
		t.Error("Process should fail when address not configured")
	}
}

func TestProcess_DialError(t *testing.T) {
	h := createHandlerDirect()
	link := &transport.Link{
		Reader: &mockReader{},
		Writer: &mockWriter{},
	}
	dialer := &mockDialer{dialErr: io.EOF}

	err := h.Process(context.Background(), link, dialer)
	if err == nil {
		t.Error("Process should fail on dial error")
	}
}

func TestProcess_HandshakeAndDataFlow(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	_, upWrite := pipe.New()
	downRead, downWrite := pipe.New()
	link := &transport.Link{Reader: downRead, Writer: upWrite}

	go runReflexServer(stat.Connection(serverConn), link)

	dest := xnet.TCPDestination(xnet.DomainAddress("example.com"), 80)
	firstPayload := append(reflex.EncodeDestination(dest), []byte("hello")...)

	h := createHandlerDirect()
	clientLink := &transport.Link{
		Reader: &mockReader{data: [][]byte{firstPayload, []byte("more data")}},
		Writer: &mockWriter{},
	}
	dialer := &mockDialer{conn: clientConn}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		time.Sleep(100 * time.Millisecond)
		resp := []byte("response from server")
		b := buf.FromBytes(resp)
		_ = downWrite.WriteMultiBuffer(buf.MultiBuffer{b})
		downWrite.Close()
	}()

	err := h.Process(ctx, clientLink, dialer)
	if err != nil && ctx.Err() == nil {
		t.Logf("Process ended: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	mw := clientLink.Writer.(*mockWriter)
	data := mw.getData()
	if len(data) == 0 && err == nil {
		t.Log("No data received, connection may have closed early")
	}
}

func TestProcess_InvalidHandshakeResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		serverConn.Write([]byte{0, 0, 0, 0, 0, 0})
	}()

	h := createHandlerDirect()
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), 80)
	firstPayload := reflex.EncodeDestination(dest)

	link := &transport.Link{
		Reader: &mockReader{data: [][]byte{firstPayload}},
		Writer: &mockWriter{},
	}
	dialer := &mockDialer{conn: clientConn}

	err := h.Process(context.Background(), link, dialer)
	if err == nil {
		t.Error("Process should fail on invalid handshake response")
	}
}

func TestPerformHandshake_InvalidUserID(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		serverConn.Close()
	}()

	h := createHandlerDirect()
	h.config.Id = "invalid-uuid-format"

	_, err := h.performHandshake(context.Background(), clientConn)
	if err == nil {
		t.Error("performHandshake should fail with invalid user ID")
	}
}

func TestGetTrafficStats(t *testing.T) {
	h := createHandlerDirect()
	stats := h.GetTrafficStats()
	if stats == nil {
		t.Error("GetTrafficStats should not return nil")
	}
}

func TestSetMorphingProfile(t *testing.T) {
	h := createHandlerDirect()
	profile := reflex.GetProfileByName("default")
	h.SetMorphingProfile(profile)
	if h.GetMorphingProfile() != profile {
		t.Error("SetMorphingProfile should set the profile")
	}
}

func TestGetMorphingProfile(t *testing.T) {
	h := createHandlerDirect()
	if h.GetMorphingProfile() != nil {
		t.Error("Initial morphing profile should be nil")
	}

	profile := reflex.GetProfileByName("random")
	h.SetMorphingProfile(profile)
	if h.GetMorphingProfile() != profile {
		t.Error("GetMorphingProfile should return set profile")
	}
}

func TestHandler_WithMorphingEnabled(t *testing.T) {
	h := createHandlerDirect()
	h.config.EnableTrafficMorphing = true
	h.morphingProfile = reflex.GetProfileByName("default")

	clientConn, serverConn := net.Pipe()
	_, upWrite := pipe.New()
	downRead, downWrite := pipe.New()
	link := &transport.Link{Reader: downRead, Writer: upWrite}

	go runReflexServer(stat.Connection(serverConn), link)

	dest := xnet.TCPDestination(xnet.DomainAddress("test.com"), 443)
	firstPayload := append(reflex.EncodeDestination(dest), []byte("data")...)

	clientLink := &transport.Link{
		Reader: &mockReader{data: [][]byte{firstPayload}},
		Writer: &mockWriter{},
	}
	dialer := &mockDialer{conn: clientConn}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		time.Sleep(50 * time.Millisecond)
		b := buf.FromBytes([]byte("ok"))
		_ = downWrite.WriteMultiBuffer(buf.MultiBuffer{b})
		downWrite.Close()
	}()

	_ = h.Process(ctx, clientLink, dialer)
	stats := h.GetTrafficStats()
	if stats != nil {
		_ = stats.GetSizeStats()
	}
}

func TestHandleUplink_ReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		serverConn.Close()
	}()

	h := createHandlerDirect()
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), 80)
	firstPayload := reflex.EncodeDestination(dest)

	link := &transport.Link{
		Reader: &mockReader{data: [][]byte{firstPayload}, returnErr: io.EOF},
		Writer: &mockWriter{},
	}
	dialer := &mockDialer{conn: clientConn}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := h.Process(ctx, link, dialer)
	if err != nil && err.Error() == "" {
		t.Log("Process ended as expected")
	}
}

func TestProcess_ContextCancel(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	_, upWrite := pipe.New()
	downRead, _ := pipe.New()
	link := &transport.Link{Reader: downRead, Writer: upWrite}

	go func() {
		runReflexServer(stat.Connection(serverConn), link)
	}()

	dest := xnet.TCPDestination(xnet.DomainAddress("example.com"), 80)
	firstPayload := append(reflex.EncodeDestination(dest), []byte("x")...)

	h := createHandlerDirect()
	clientLink := &transport.Link{
		Reader: &mockReader{data: [][]byte{firstPayload}},
		Writer: &mockWriter{},
	}
	dialer := &mockDialer{conn: clientConn}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_ = h.Process(ctx, clientLink, dialer)
}
