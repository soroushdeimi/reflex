package tests

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// MockDialer implements internet.Dialer
type MockDialer struct {
	Dest net.Conn
}

func (d *MockDialer) Dial(ctx context.Context, dest xraynet.Destination) (stat.Connection, error) {
	return &MockConnection{Conn: d.Dest}, nil
}
func (d *MockDialer) Address() xraynet.Address                                     { return nil }
func (d *MockDialer) DestIpAddress() xraynet.IP                                    { return nil }
func (d *MockDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

type MockConnection struct {
	net.Conn
}

func (c *MockConnection) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }
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
	ReceivedData []byte
	Done         chan bool
}

func (d *MockDispatcher) Dispatch(ctx context.Context, dest xraynet.Destination) (*transport.Link, error) {
	// Create separate pipes for request and response
	// Inbound Handler writes to reqW -> Dispatcher reads from reqR
	reqR, reqW := pipe.New(pipe.WithSizeLimit(1024))
	// Dispatcher writes to respW -> Inbound Handler reads from respR
	respR, respW := pipe.New(pipe.WithSizeLimit(1024))

	// Link returned to Inbound handler
	inLink := &transport.Link{
		Reader: respR,
		Writer: reqW,
	}

	go func() {
		// Close pipes when done to prevent leaks
		defer respW.Close()

		for {
			mb, err := reqR.ReadMultiBuffer()
			if err != nil {
				// EOF or error
				break
			}
			for _, b := range mb {
				d.ReceivedData = append(d.ReceivedData, b.Bytes()...)
				b.Release()
			}
			// Signal we got data
			select {
			case d.Done <- true:
			default:
			}
		}
	}()
	return inLink, nil
}
func (d *MockDispatcher) DispatchLink(ctx context.Context, dest xraynet.Destination, link *transport.Link) error {
	return nil
}
func (d *MockDispatcher) Start() error      { return nil }
func (d *MockDispatcher) Close() error      { return nil }
func (d *MockDispatcher) Type() interface{} { return nil }

func TestReflexFullIntegration(t *testing.T) {
	// 1. Setup
	userID := uuid.New()

	// Server Config
	serverConfig := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: userID.String(), Policy: "youtube"},
		},
	}

	// Client Config
	clientConfig := &reflex.OutboundConfig{
		Id:      userID.String(),
		Address: "127.0.0.1",
		Port:    443,
	}

	// 2. Create Handlers
	ctx := context.Background()

	// Server Handler
	serverHandler, err := inbound.New(ctx, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server handler: %v", err)
	}

	// Client Handler
	clientHandler, err := outbound.New(ctx, clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client handler: %v", err)
	}

	// 3. Connect via Pipe
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// 4. Start Server Processing
	dispatcher := &MockDispatcher{Done: make(chan bool, 1)}
	// Inject dispatcher manually (assuming internal field or context)
	// Since we can't inject privately, we rely on context or test helper in inbound package.
	// But `inbound.Handler` uses `routing.Dispatcher` from core.
	// We'll mimic `Process` manually or use `Process` method if exposed.
	// `inbound.Handler` has `Process(ctx, network, conn, dispatcher)`.

	go func() {
		// Mimic server listening on c2
		// We need to wrap c2 in a stat.Connection/reader
		conn := &MockConnection{Conn: c2}
		if err := serverHandler.Process(ctx, xraynet.Network_TCP, conn, dispatcher); err != nil {
			t.Logf("Server Process Error: %v", err)
		}
		// Close dispatcher pipe when server done
		// But in this test, serverHandler never returns unless error or connection closed.
	}()

	// 5. Start Client Processing
	// Client handler `Process` takes a Link (input/output from user) and Dialer (to internet).
	// Create TWO pipes for User <-> Client communication
	// 1. User -> Client (Request)
	userReqR, userReqW := pipe.New(pipe.WithSizeLimit(1024))
	// 2. Client -> User (Response)
	// We use _ for userRespR as we don't verify response here, but keep it open
	_, userRespW := pipe.New(pipe.WithSizeLimit(1024))

	// Close unused ends to prevent leaks if test ends early
	defer userRespW.Close()

	userLink := &transport.Link{Reader: userReqR, Writer: userRespW}
	dialer := &MockDialer{Dest: c1}

	go func() {
		if err := clientHandler.Process(ctx, userLink, dialer); err != nil {
			t.Logf("Client Process Error: %v", err)
		}
	}()

	// 6. Send Data from Client User -> Server Dispatcher
	testPayload := []byte("Hello Reflex World")
	b := buf.New()
	b.Write(testPayload)
	userReqW.WriteMultiBuffer(buf.MultiBuffer{b})
	userReqW.Close() // Signal EOF to client input so requestFunc finishes reading

	// 7. Verify
	select {
	case <-dispatcher.Done:
		if string(dispatcher.ReceivedData) != string(testPayload) {
			t.Errorf("Data mismatch. Got %s, want %s", string(dispatcher.ReceivedData), string(testPayload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for data")
	}
}

func TestReflexFallback(t *testing.T) {
	// 1. Start a dummy fallback server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start fallback server: %v", err)
	}
	defer listener.Close()

	fallbackPort := listener.Addr().(*net.TCPAddr).Port
	fallbackReceived := make(chan []byte, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		fallbackReceived <- buf[:n]
	}()

	// 2. Configure Inbound with Fallback
	ctx := context.Background()
	config := &reflex.InboundConfig{
		Fallback: &reflex.Fallback{Dest: uint32(fallbackPort)},
	}

	handler, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// 3. Send Junk Data
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		// Mimic inbound process
		// We use a real pipe for conn to ensure bufio works
		// but MockConnection wraps it
		defer c2.Close()
		_, pw := pipe.New(pipe.WithSizeLimit(1024))
		defer pw.Close()

		conn := &MockConnection{Conn: c2}
		// Dispatcher shouldn't be called for fallback, but we provide a mock anyway
		dispatcher := &MockDispatcher{}
		if err := handler.Process(ctx, xraynet.Network_TCP, conn, dispatcher); err != nil {
			t.Logf("Process error: %v", err)
		}
	}()

	junkData := []byte("NOT A REFLEX HANDSHAKE")

	go func() {
		if _, err := c1.Write(junkData); err != nil {
			t.Errorf("Write failed: %v", err)
		}
		c1.Close()
	}()

	// 4. Verify Fallback Server received it
	select {
	case data := <-fallbackReceived:
		if string(data) != string(junkData) {
			t.Errorf("Fallback mismatch. Got %s, want %s", string(data), string(junkData))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for fallback data")
	}
}
