package tests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// reflexMagic is the Reflex handshake magic number (REFX).
const reflexMagic uint32 = 0x5246584C

func buildReflexMagicHandshake(userID uuid.UUID, ts int64) []byte {
	var buf bytes.Buffer

	_ = binary.Write(&buf, binary.BigEndian, reflexMagic)

	var pub [32]byte
	_, _ = rand.Read(pub[:])
	buf.Write(pub[:])

	var userBytes [16]byte
	copy(userBytes[:], userID[:])
	buf.Write(userBytes[:])

	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(ts))
	buf.Write(tsBytes[:])

	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	buf.Write(nonce[:])

	policy := []byte("policy")
	var plen [2]byte
	binary.BigEndian.PutUint16(plen[:], uint16(len(policy)))
	buf.Write(plen[:])
	buf.Write(policy)

	return buf.Bytes()
}

func newReflexTestHandlerWithClient(t *testing.T) (handler proxy.Inbound, userID uuid.UUID) {
	t.Helper()

	u := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: u.String()},
		},
	}

	h, err := inbound.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New handler failed: %v", err)
	}

	return h, u
}

func TestReflexMagicHandshakeSuccess(t *testing.T) {
	handler, userID := newReflexTestHandlerWithClient(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.Process(ctx, xnet.Network_TCP, stat.Connection(serverConn), nil)
	}()

	hs := buildReflexMagicHandshake(userID, time.Now().Unix())
	if _, err := clientConn.Write(hs); err != nil {
		t.Fatalf("client write handshake failed: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(clientConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read status line: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected HTTP 200 in status line, got: %q", statusLine)
	}

	_ = clientConn.Close()
	if err := <-errCh; err != nil {
		if !errors.Is(err, io.ErrClosedPipe) && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("handler.Process returned error: %v", err)
		}
	}
}

func TestReflexHandshakeOldTimestampRejected(t *testing.T) {
	handler, userID := newReflexTestHandlerWithClient(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.Process(ctx, xnet.Network_TCP, stat.Connection(serverConn), nil)
	}()

	oldTs := time.Now().Add(-10 * time.Minute).Unix()
	hs := buildReflexMagicHandshake(userID, oldTs)
	if _, err := clientConn.Write(hs); err != nil {
		t.Fatalf("client write handshake failed: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(clientConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read status line: %v", err)
	}
	if !strings.Contains(statusLine, "403") {
		t.Fatalf("expected HTTP 403 in status line for old timestamp, got: %q", statusLine)
	}

	_ = clientConn.Close()
	if err := <-errCh; err != nil {
		if !errors.Is(err, io.ErrClosedPipe) && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("handler.Process returned error: %v", err)
		}
	}
}

func TestReflexFallbackForPlainHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	hostPort := strings.Split(u.Host, ":")
	if len(hostPort) != 2 {
		t.Fatalf("unexpected host:port format: %q", u.Host)
	}
	port, err := strconv.Atoi(hostPort[1])
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	cfg := &reflex.InboundConfig{
		Fallback: &reflex.Fallback{
			Dest: uint32(port),
		},
	}

	rawHandler, err := inbound.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New handler failed: %v", err)
	}
	handler := rawHandler

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.Process(ctx, xnet.Network_TCP, stat.Connection(serverConn), nil)
	}()

	req := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-client/1.0\r\nAccept: */*\r\n\r\n"
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(clientConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read status line from fallback response: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected HTTP 200 from fallback server, got: %q", statusLine)
	}

	var contentLen int
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read header line: %v", err)
		}
		if line == "\r\n" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				contentLen, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		}
	}

	if contentLen > 0 {
		body := make([]byte, contentLen)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		if !strings.Contains(string(body), "OK") {
			t.Fatalf("expected body to contain OK, got: %q", string(body))
		}
	}

	_ = clientConn.Close()
	if err := <-errCh; err != nil {
		if !errors.Is(err, io.ErrClosedPipe) && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("handler.Process returned error: %v", err)
		}
	}
}

func TestReflexFallbackPeekedBytesReachServer(t *testing.T) {
	firstLineCh := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstLine := r.Method + " " + r.URL.RequestURI() + " " + r.Proto
		select {
		case firstLineCh <- firstLine:
		default:
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	port, err := strconv.Atoi(strings.Split(u.Host, ":")[1])
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	cfg := &reflex.InboundConfig{
		Fallback: &reflex.Fallback{Dest: uint32(port)},
	}
	rawHandler, err := inbound.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New handler: %v", err)
	}
	handler := rawHandler

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	requestLine := "GET /peeked-bytes-test HTTP/1.1"
	req := requestLine + "\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"

	go func() {
		_ = handler.Process(ctx, xnet.Network_TCP, stat.Connection(serverConn), nil)
	}()

	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 1024)
	n, _ := clientConn.Read(respBuf)
	if n == 0 {
		t.Fatal("no response from fallback")
	}
	if !bytes.Contains(respBuf[:n], []byte("OK")) {
		t.Fatalf("expected OK in response, got: %s", respBuf[:n])
	}

	select {
	case got := <-firstLineCh:
		if got != requestLine {
			t.Fatalf("fallback server received wrong first line: %q (expected %q)", got, requestLine)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("fallback server did not receive request (peeked bytes may not have been forwarded)")
	}
}
