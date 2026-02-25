package tests

import (
	"bufio"
	"context"
	"errors"
	stdnet "net"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	reflexout "github.com/xtls/xray-core/proxy/reflex/outbound"
	"github.com/xtls/xray-core/proxy/reflex/tunnel"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type fakeDialer struct {
	conn     stat.Connection
	called   int
	lastDest xnet.Destination
}

func (d *fakeDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	d.called++
	d.lastDest = destination
	if d.conn == nil {
		return nil, errors.New("dial failed (fake)")
	}
	return d.conn, nil
}
func (d *fakeDialer) DestIpAddress() xnet.IP { return nil }
func (d *fakeDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

// --- Success path: outbound does handshake + sends initial destination + relays ping/pong ---
func TestReflex_Outbound_Success(t *testing.T) {
	idStr := "d89d6641-3b1a-4f51-a194-9c9109fd21b6"
	id, err := uuid.ParseString(idStr)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    12345,
		Id:      idStr,
	}
	h, err := reflexout.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("outbound.New: %v", err)
	}

	// server validator accepts this client
	mv := reflex.NewMemoryValidator()
	if err := mv.Add(&reflex.ClientInfo{ID: id, Policy: "default"}); err != nil {
		t.Fatal(err)
	}
	serverEng := reflex.NewHandshakeEngine(mv)

	// ✅ use stdlib net.Pipe (NOT xnet.Pipe)
	clientConn, serverConn := stdnet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	_ = clientConn.SetDeadline(time.Now().Add(4 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(4 * time.Second))

	dialer := &fakeDialer{conn: clientConn}

	wantTarget := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443))

	// link: request is "ping", response should be "pong"
	w := &recordWriter{}
	r := &staticReader{data: []byte("ping")}
	link := &transport.Link{Reader: r, Writer: w}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: wantTarget},
	})

	// Server: handshake + read initial destination + read DATA until CLOSE, then reply "pong" + CLOSE
	serverErrCh := make(chan error, 1)
	serverGotReq := make(chan []byte, 1)
	serverGotDest := make(chan xnet.Destination, 1)

	go func() {
		defer serverConn.Close()

		br := bufio.NewReader(serverConn)

		info, e := serverEng.ServerDoHandshake(br, serverConn)
		if e != nil {
			serverErrCh <- e
			return
		}
		sess, e := tunnel.NewSession(info.SessionKey[:])
		if e != nil {
			serverErrCh <- e
			return
		}

		dest, initPayload, e := tunnel.ReadInitialDestination(sess, br, tunnel.SocksAddrCodec{})
		if e != nil {
			serverErrCh <- e
			return
		}
		if len(initPayload) != 0 {
			serverErrCh <- errors.New("expected empty init payload")
			return
		}
		serverGotDest <- dest

		gotReq := make([]byte, 0, 32)
		for {
			f, e := sess.ReadFrame(br)
			if e != nil {
				serverErrCh <- e
				return
			}
			switch f.Type {
			case tunnel.FrameTypeData:
				gotReq = append(gotReq, f.Payload...)
			case tunnel.FrameTypeClose:
				serverGotReq <- gotReq
				_ = sess.WriteFrame(serverConn, tunnel.FrameTypeData, []byte("pong"))
				_ = tunnel.WriteClose(sess, serverConn)
				serverErrCh <- nil
				return
			default:
				continue
			}
		}
	}()

	if err := h.Process(ctx, link, dialer); err != nil {
		t.Fatalf("outbound.Process failed: %v", err)
	}

	if dialer.called != 1 {
		t.Fatalf("expected dialer called once, got %d", dialer.called)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server err: %v", err)
	}

	gotDest := <-serverGotDest
	if gotDest.Network != wantTarget.Network || gotDest.Port != wantTarget.Port || gotDest.Address.String() != wantTarget.Address.String() {
		t.Fatalf("initial destination mismatch: got=%v want=%v", gotDest, wantTarget)
	}

	gotReq := <-serverGotReq
	if string(gotReq) != "ping" {
		t.Fatalf("request payload mismatch: got=%q want=%q", string(gotReq), "ping")
	}

	if string(w.Bytes()) != "pong" {
		t.Fatalf("response payload mismatch: got=%q want=%q", string(w.Bytes()), "pong")
	}
}

// --- Error 1: dial fails (covers "dial failed" branch) ---
func TestReflex_Outbound_DialFail(t *testing.T) {
	idStr := "d89d6641-3b1a-4f51-a194-9c9109fd21b6"
	cfg := &reflex.OutboundConfig{Address: "127.0.0.1", Port: 12345, Id: idStr}
	h, err := reflexout.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("outbound.New: %v", err)
	}

	dialer := &fakeDialer{conn: nil} // will fail

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443))},
	})

	link := &transport.Link{Reader: &staticReader{data: []byte("x")}, Writer: &recordWriter{}}

	err = h.Process(ctx, link, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if dialer.called != 1 {
		t.Fatalf("expected dialer called once, got %d", dialer.called)
	}
	if !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Error 2: handshake fails (covers "handshake failed" branch) ---
func TestReflex_Outbound_HandshakeFail(t *testing.T) {
	idStr := "d89d6641-3b1a-4f51-a194-9c9109fd21b6"
	cfg := &reflex.OutboundConfig{Address: "127.0.0.1", Port: 12345, Id: idStr}
	h, err := reflexout.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("outbound.New: %v", err)
	}

	clientConn, serverConn := stdnet.Pipe()
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))

	// close server immediately so client handshake fails quickly
	go func() {
		_ = serverConn.Close()
	}()

	dialer := &fakeDialer{conn: clientConn}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443))},
	})

	link := &transport.Link{Reader: &staticReader{data: []byte("x")}, Writer: &recordWriter{}}

	err = h.Process(ctx, link, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if dialer.called != 1 {
		t.Fatalf("expected dialer called once, got %d", dialer.called)
	}
	if !strings.Contains(err.Error(), "handshake failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
