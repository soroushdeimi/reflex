package tests

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
)

const testUUID = "11111111-1111-1111-1111-111111111111"

func TestSessionEncryptionRoundTrip(t *testing.T) {
	var key [32]byte
	for i := 0; i < len(key); i++ {
		key[i] = byte(i)
	}
	s1, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	msg := []byte("hello reflex")
	if err := s1.WriteFrame(buf, reflex.FrameTypeData, msg); err != nil {
		t.Fatal(err)
	}

	f, err := s2.ReadFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != reflex.FrameTypeData {
		t.Fatalf("unexpected frame type %d", f.Type)
	}
	if !bytes.Equal(f.Payload, msg) {
		t.Fatalf("payload mismatch: got %q want %q", string(f.Payload), string(msg))
	}
}

func TestReplayProtection(t *testing.T) {
	cache := inbound.NewNonceCache(1000, 10*time.Minute)

	var userID [16]byte
	var nonce [16]byte
	userID[0] = 1
	nonce[0] = 2

	now := time.Now()
	if !cache.Check(userID, nonce, now) {
		t.Fatal("expected first nonce use to pass")
	}
	if cache.Check(userID, nonce, now.Add(time.Second)) {
		t.Fatal("expected replay nonce to be rejected")
	}
}

func TestMorphingSplit(t *testing.T) {
	var key [32]byte
	for i := 0; i < len(key); i++ {
		key[i] = byte(0x42 + i)
	}
	s1, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	profile := reflex.CloneProfile("http2-api")
	if profile == nil {
		t.Fatal("profile not found")
	}

	payload := bytes.Repeat([]byte("A"), 1500)

	profile.SetNextPacketSize(200)

	buf := new(bytes.Buffer)
	if err := s1.WriteFrameWithMorphing(buf, reflex.FrameTypeData, payload, profile); err != nil {
		t.Fatal(err)
	}

	var got []byte
readLoop:
	for len(got) < len(payload) {
		f, err := s2.ReadFrame(buf)
		if err != nil {
			t.Fatal(err)
		}
		switch f.Type {
		case reflex.FrameTypeData:
			got = append(got, f.Payload...)
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			continue
		case reflex.FrameTypeClose:
			break readLoop
		default:
			t.Fatalf("unexpected frame type %d", f.Type)
		}
	}

	if len(got) < len(payload) || !bytes.Equal(got[:len(payload)], payload) {
		t.Fatalf("morphing split mismatch: got(%d) want(%d)", len(got), len(payload))
	}
}

func TestHandshakeMagic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	inCfg := &reflex.InboundConfig{Clients: []*reflex.User{{Id: testUUID, Policy: "http2-api"}}}
	h, err := inbound.New(ctx, inCfg)
	if err != nil {
		t.Fatal(err)
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Process(ctx, xnet.Network_TCP, serverConn, nil)
	}()

	outCfg := &reflex.OutboundConfig{Address: "pipe", Port: 0, Id: testUUID, Policy: "http2-api", UseHttpHandshake: false}
	c, err := outbound.NewClient(outCfg)
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := c.Handshake(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.WriteFrame(clientConn, reflex.FrameTypeClose, nil); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("server error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
}

func TestFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	fallbackPort := uint32(ln.Addr().(*net.TCPAddr).Port)

	var received bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(conn)

		for received.Len() < 8192 {
			line, rerr := br.ReadString('\n')
			if len(line) > 0 {
				received.WriteString(line)
			}
			if rerr != nil {
				break
			}
			if line == "\r\n" { // end of headers
				break
			}
		}

		// پاسخ سریع
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()

	inCfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{{Id: testUUID}},
		Fallback: &reflex.Fallback{Dest: fallbackPort},
	}
	h, err := inbound.New(ctx, inCfg)
	if err != nil {
		t.Fatal(err)
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Process(ctx, xnet.Network_TCP, serverConn, nil)
	}()

	req := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: reflex-test\r\nAccept: */*\r\nX-Padding: 012345678901234567890123456789\r\n\r\n"
	if len(req) < reflex.MinHandshakePeek {
		t.Fatalf("test request too short")
	}
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 256)
	n, err := clientConn.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.Contains(resp[:n], []byte("200 OK")) {
		t.Fatalf("unexpected response: %q", string(resp[:n]))
	}

	_ = clientConn.Close()
	wg.Wait()

	if !bytes.HasPrefix(received.Bytes(), []byte("GET / HTTP/1.1")) {
		t.Fatalf("fallback server did not receive request, got: %q", received.String())
	}

	select {
	case <-errCh:
	case <-ctx.Done():
	}
}

func TestIntegrationProxying(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Echo upstream
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoLn.Close() }()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if _, err := io.Copy(conn, conn); err != nil {
					return
				}
			}(c)
		}
	}()

	// Reflex inbound listener
	refLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = refLn.Close() }()
	refAddr := refLn.Addr().(*net.TCPAddr)

	inCfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{{Id: testUUID, Policy: "http2-api"}},
		Fallback: &reflex.Fallback{Dest: uint32(echoAddr.Port)},
	}
	h, err := inbound.New(ctx, inCfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			c, err := refLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if err := h.Process(ctx, xnet.Network_TCP, conn, nil); err != nil &&
					!errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					// ignore (best-effort)
					return
				}
			}(c)
		}
	}()

	outCfg := &reflex.OutboundConfig{
		Address:          refAddr.IP.String(),
		Port:             uint32(refAddr.Port),
		Id:               testUUID,
		Policy:           "http2-api",
		UseHttpHandshake: true,
	}
	client, err := outbound.NewClient(outCfg)
	if err != nil {
		t.Fatal(err)
	}

	conn, sess, profile, err := client.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if err := client.SendRequest(sess, conn, echoAddr.IP.String(), uint16(echoAddr.Port), nil, profile); err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello over reflex")
	if err := sess.WriteFrameWithMorphing(conn, reflex.FrameTypeData, msg, profile); err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(conn)
	var got []byte
readLoop:
	for len(got) < len(msg) {
		f, err := sess.ReadFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		switch f.Type {
		case reflex.FrameTypeData:
			got = append(got, f.Payload...)
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			sess.HandleControlFrame(f, profile)
		case reflex.FrameTypeClose:
			break readLoop
		default:
			t.Fatalf("unexpected frame type %d", f.Type)
		}
	}
	if !bytes.Equal(got[:len(msg)], msg) {
		t.Fatalf("echo mismatch: got %q want %q", string(got), string(msg))
	}
}

func TestConfigProtoAndPbGoExist(t *testing.T) {
	// ✅ مسیر درست از داخل xray-core/tests اینه: ../proxy/reflex/...
	if !fileExists("../proxy/reflex/config.proto") {
		t.Fatal("config.proto not found")
	}
	if !fileExists("../proxy/reflex/config.pb.go") {
		t.Fatal("config.pb.go not found")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
