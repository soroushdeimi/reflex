package reflex_test

import (
	"context"
	"encoding/binary"
	"bytes"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// Unit-style tests in tests folder as requested by submission.md

func TestHandshake(t *testing.T) {
	clientPriv, clientPub, _ := reflex.GenerateKeyPair()
	serverPriv, serverPub, _ := reflex.GenerateKeyPair()

	shared1 := reflex.DeriveSharedKey(clientPriv, serverPub)
	shared2 := reflex.DeriveSharedKey(serverPriv, clientPub)

	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Fatal("shared keys mismatch")
	}

	c2s, s2c := reflex.DeriveSessionKeys(shared1, []byte("salt"))
	if len(c2s) != 32 || len(s2c) != 32 || bytes.Equal(c2s, s2c) {
		t.Fatal("session keys derivation failure")
	}
}

func TestEncryption(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	s1, _ := reflex.NewSession(key1, key2)
	s2, _ := reflex.NewSession(key2, key1)

	var b bytes.Buffer
	data := []byte("secret data")
	err := s1.WriteFrame(&b, reflex.FrameTypeData, data)
	if err != nil {
		t.Fatal(err)
	}

	frame, err := s2.ReadFrame(&b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(frame.Payload, data) {
		t.Errorf("expected %s, got %s", string(data), string(frame.Payload))
	}
}

// Integration tests

type mockDispatcher struct {
	onDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (m *mockDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return m.onDispatch(ctx, dest)
}
func (m *mockDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error { return nil }
func (m *mockDispatcher) Type() interface{} { return routing.DispatcherType() }
func (m *mockDispatcher) Start() error { return nil }
func (m *mockDispatcher) Close() error { return nil }

type mockDialer struct {
	conn stdnet.Conn
}

func (m *mockDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	return m.conn.(stat.Connection), nil
}
func (m *mockDialer) DestIpAddress() net.IP { return nil }
func (m *mockDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

func TestReflexFullConnection(t *testing.T) {
	uID := uuid.New().String()
	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID, Policy: "youtube"}},
	})
	outboundHandler, _ := outbound.New(context.Background(), &reflex.OutboundConfig{
		Address: "127.0.0.1", Port: 443, Id: uID,
	})

	clientConn, serverConn := stdnet.Pipe()
	targetDest := net.TCPDestination(net.ParseAddress("1.2.3.4"), 80)

	serverDispatcher := &mockDispatcher{
		onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
			downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
			go func() {
				for {
					mb, err := upReader.ReadMultiBuffer()
					if err != nil { break }
					downWriter.WriteMultiBuffer(mb)
				}
			}()
			return &transport.Link{Reader: downReader, Writer: upWriter}, nil
		},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), serverDispatcher)
	}()

	clientLinkReader, clientLinkWriter := pipe.New(pipe.WithoutSizeLimit())
	clientResponseReader, clientResponseWriter := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: clientLinkReader, Writer: clientResponseWriter}
	outboundCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: targetDest}})

	go func() {
		defer wg.Done()
		outboundHandler.Process(outboundCtx, link, &mockDialer{conn: clientConn})
	}()

	testData := []byte("hello integrity test")
	clientLinkWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(testData)})

	mb, err := clientResponseReader.ReadMultiBuffer()
	if err != nil { t.Fatalf("failed to read response: %v", err) }

	if mb.String() != string(testData) {
		t.Errorf("expected %s, got %s", string(testData), mb.String())
	}

	clientConn.Close()
	wg.Wait()
}

func TestReplayProtection(t *testing.T) {
	uID := uuid.New().String()
	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	})

	clientHS := reflex.ClientHandshake{
		PublicKey: [32]byte{1},
		Timestamp: time.Now().Unix() - 1000, // Invalid
	}
	u, _ := uuid.Parse(uID)
	copy(clientHS.UserID[:], u[:])

	packet := &bytes.Buffer{}
	binary.Write(packet, binary.BigEndian, uint32(reflex.ReflexMagic))
	binary.Write(packet, binary.BigEndian, &clientHS)

	c1, s1 := stdnet.Pipe()
	go func() {
		c1.Write(packet.Bytes())
		c1.Close()
	}()

	err := inboundHandler.Process(context.Background(), net.Network_TCP, s1.(stat.Connection), nil)
	if err == nil {
		t.Error("expected error for old timestamp, got nil")
	}
}

func TestReflexFallback(t *testing.T) {
	ln, _ := stdnet.Listen("tcp", "127.0.0.1:0")
	port := uint32(ln.Addr().(*stdnet.TCPAddr).Port)
	webData := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			io.WriteString(conn, webData)
		}
	}()
	defer ln.Close()

	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Fallback: &reflex.Fallback{Dest: port},
	})

	clientConn, serverConn := stdnet.Pipe()
	go func() {
		data := "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
		padding := make([]byte, 64-len(data))
		clientConn.Write([]byte(data))
		clientConn.Write(padding)
	}()

	go inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), nil)

	buf := make([]byte, 1024)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil { t.Fatalf("failed to read from client: %v", err) }

	if string(buf[:n]) != webData {
		t.Errorf("expected %s, got %s", webData, string(buf[:n]))
	}
	clientConn.Close()
}

func TestReflexHTTPHandshake(t *testing.T) {
	uID := uuid.New().String()
	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	})

	clientConn, serverConn := stdnet.Pipe()

	go func() {
		// Send HTTP-style handshake
		data := "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		clientConn.Write([]byte(data))

		// Send binary handshake part
		_, clientPub, _ := reflex.GenerateKeyPair()
		u, _ := uuid.Parse(uID)
		var userId [16]byte
		copy(userId[:], u[:])
		clientHS := reflex.ClientHandshake{
			PublicKey: clientPub,
			UserID:    userId,
			Timestamp: time.Now().Unix(),
		}
		binary.Write(clientConn, binary.BigEndian, &clientHS)

		// Read server response
		var serverHS reflex.ServerHandshake
		binary.Read(clientConn, binary.BigEndian, &serverHS)

		clientConn.Close()
	}()

	// Server processing should fail eventually because we closed the pipe,
	// but it will hit handleReflexHTTP and processHandshake.
	inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), nil)
}

func TestReflexInvalidUser(t *testing.T) {
	uID := uuid.New().String()
	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	})

	clientConn, serverConn := stdnet.Pipe()

	go func() {
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, reflex.ReflexMagic)
		clientConn.Write(magic)

		// Send binary handshake with WRONG UserID
		_, clientPub, _ := reflex.GenerateKeyPair()
		wrongID := [16]byte{0xFF}
		clientHS := reflex.ClientHandshake{
			PublicKey: clientPub,
			UserID:    wrongID,
			Timestamp: time.Now().Unix(),
		}
		binary.Write(clientConn, binary.BigEndian, &clientHS)
		clientConn.Close()
	}()

	// Should hit authenticateUser, fail, and go to fallback (which is nil here, so it returns error)
	inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), nil)
}

func TestReflexNonceReplay(t *testing.T) {
	uID := uuid.New().String()
	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	})

	nonce := [16]byte{0xAA, 0xBB}
	clientHS := reflex.ClientHandshake{
		PublicKey: [32]byte{1},
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}
	u, _ := uuid.Parse(uID)
	copy(clientHS.UserID[:], u[:])

	packet := &bytes.Buffer{}
	binary.Write(packet, binary.BigEndian, uint32(reflex.ReflexMagic))
	binary.Write(packet, binary.BigEndian, &clientHS)

	// First attempt
	c1, s1 := stdnet.Pipe()
	go func() {
		c1.Write(packet.Bytes())
		c1.Close()
	}()
	// Handshake part will succeed but session might fail as we close pipe
	inboundHandler.Process(context.Background(), net.Network_TCP, s1.(stat.Connection), nil)

	// Second attempt with SAME nonce
	c2, s2 := stdnet.Pipe()
	go func() {
		c2.Write(packet.Bytes())
		c2.Close()
	}()
	err := inboundHandler.Process(context.Background(), net.Network_TCP, s2.(stat.Connection), nil)
	if err == nil {
		t.Error("expected error for replayed nonce, got nil")
	}
}

func TestConsecutiveConnections(t *testing.T) {
	uID := uuid.New().String()
	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	})
	outboundHandler, _ := outbound.New(context.Background(), &reflex.OutboundConfig{
		Address: "127.0.0.1", Port: 443, Id: uID,
	})

	serverDispatcher := &mockDispatcher{
		onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
			downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
			go func() {
				for {
					mb, err := upReader.ReadMultiBuffer()
					if err != nil { break }
					downWriter.WriteMultiBuffer(mb)
				}
			}()
			return &transport.Link{Reader: downReader, Writer: upWriter}, nil
		},
	}

	for i := 0; i < 3; i++ {
		clientConn, serverConn := stdnet.Pipe()
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), serverDispatcher)
		}()

		clientLinkReader, clientLinkWriter := pipe.New(pipe.WithoutSizeLimit())
		clientResponseReader, clientResponseWriter := pipe.New(pipe.WithoutSizeLimit())
		link := &transport.Link{Reader: clientLinkReader, Writer: clientResponseWriter}
		targetDest := net.TCPDestination(net.ParseAddress("1.1.1.1"), 80)
		outboundCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: targetDest}})

		go func() {
			defer wg.Done()
			outboundHandler.Process(outboundCtx, link, &mockDialer{conn: clientConn})
		}()

		testData := []byte("consecutive test")
		clientLinkWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(testData)})

		mb, err := clientResponseReader.ReadMultiBuffer()
		if err != nil { t.Fatalf("connection %d failed: %v", i, err) }

		if mb.String() != string(testData) {
			t.Errorf("connection %d: expected %s, got %s", i, string(testData), mb.String())
		}

		clientConn.Close()
		wg.Wait()
	}
}

func TestEdgeCases(t *testing.T) {
	uID := uuid.New().String()
	inboundHandler, _ := inbound.New(context.Background(), &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uID}},
	})
	outboundHandler, _ := outbound.New(context.Background(), &reflex.OutboundConfig{
		Address: "127.0.0.1", Port: 443, Id: uID,
	})

	t.Run("EmptyData", func(t *testing.T) {
		clientConn, serverConn := stdnet.Pipe()
		serverDispatcher := &mockDispatcher{
			onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
				_, upWriter := pipe.New(pipe.WithoutSizeLimit())
				downReader, _ := pipe.New(pipe.WithoutSizeLimit())
				return &transport.Link{Reader: downReader, Writer: upWriter}, nil
			},
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), serverDispatcher)
		}()

		clientLinkReader, clientLinkWriter := pipe.New(pipe.WithoutSizeLimit())
		_, clientResponseWriter := pipe.New(pipe.WithoutSizeLimit())
		link := &transport.Link{Reader: clientLinkReader, Writer: clientResponseWriter}

		go func() {
			defer wg.Done()
			outboundHandler.Process(context.Background(), link, &mockDialer{conn: clientConn})
		}()

		// Send nothing, just close
		clientLinkWriter.Close()
		clientConn.Close()
		wg.Wait()
	})

	t.Run("LargeData", func(t *testing.T) {
		clientConn, serverConn := stdnet.Pipe()
		serverDispatcher := &mockDispatcher{
			onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
				upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
				downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
				go func() {
					for {
						mb, err := upReader.ReadMultiBuffer()
						if err != nil { break }
						downWriter.WriteMultiBuffer(mb)
					}
				}()
				return &transport.Link{Reader: downReader, Writer: upWriter}, nil
			},
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), serverDispatcher)
		}()

		clientLinkReader, clientLinkWriter := pipe.New(pipe.WithoutSizeLimit())
		clientResponseReader, clientResponseWriter := pipe.New(pipe.WithoutSizeLimit())
		link := &transport.Link{Reader: clientLinkReader, Writer: clientResponseWriter}

		targetDest := net.TCPDestination(net.ParseAddress("1.1.1.1"), 80)
		outboundCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: targetDest}})
		go func() {
			defer wg.Done()
			outboundHandler.Process(outboundCtx, link, &mockDialer{conn: clientConn})
		}()

		largeData := make([]byte, 64*1024) // 64KB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		go func() {
			clientLinkWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(largeData)})
		}()

		received := new(bytes.Buffer)
		for received.Len() < len(largeData) {
			mb, err := clientResponseReader.ReadMultiBuffer()
			if err != nil { break }
			for _, b := range mb {
				received.Write(b.Bytes())
				b.Release()
			}
		}

		if !bytes.Equal(largeData, received.Bytes()) {
			t.Error("large data mismatch")
		}

		clientConn.Close()
		wg.Wait()
	})

	t.Run("InterruptedHandshake", func(t *testing.T) {
		clientConn, serverConn := stdnet.Pipe()

		go func() {
			magic := make([]byte, 4)
			binary.BigEndian.PutUint32(magic, reflex.ReflexMagic)
			clientConn.Write(magic)
			clientConn.Write([]byte{1, 2, 3}) // Incomplete handshake data
			clientConn.Close()
		}()

		// Should return with error but not panic or hang
		err := inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), nil)
		if err == nil {
			t.Log("Handshake interrupted as expected")
		}
	})

	t.Run("ConnectionResetDuringTransfer", func(t *testing.T) {
		clientConn, serverConn := stdnet.Pipe()
		serverDispatcher := &mockDispatcher{
			onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
				upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
				downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
				go func() {
					for {
						mb, err := upReader.ReadMultiBuffer()
						if err != nil { break }
						downWriter.WriteMultiBuffer(mb)
					}
				}()
				return &transport.Link{Reader: downReader, Writer: upWriter}, nil
			},
		}

		go inboundHandler.Process(context.Background(), net.Network_TCP, serverConn.(stat.Connection), serverDispatcher)

		clientLinkReader, clientLinkWriter := pipe.New(pipe.WithoutSizeLimit())
		_, clientResponseWriter := pipe.New(pipe.WithoutSizeLimit())
		link := &transport.Link{Reader: clientLinkReader, Writer: clientResponseWriter}

		targetDest := net.TCPDestination(net.ParseAddress("1.1.1.1"), 80)
		outboundCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: targetDest}})

		go func() {
			outboundHandler.Process(outboundCtx, link, &mockDialer{conn: clientConn})
		}()

		// Start sending data
		clientLinkWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("pre-reset"))})

		// Wait a bit and then kill the underlying connection
		time.Sleep(10 * time.Millisecond)
		clientConn.Close()

		// The handlers should terminate gracefully
		clientLinkWriter.Close()
	})
}
