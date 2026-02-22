package inbound

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
)

const testUUID = "11111111-1111-1111-1111-111111111111"

// echo tcp server helper
func startEcho(t *testing.T) (ln net.Listener, port uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = uint16(ln.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 32*1024)
				for {
					n, rerr := conn.Read(buf)
					if n > 0 {
						_, _ = conn.Write(buf[:n])
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	return ln, port
}

func TestInbound_FullSession_ProxyEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	echoLn, echoPort := startEcho(t)
	defer func() { _ = echoLn.Close() }()

	// inbound listener
	refLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = refLn.Close() }()
	refAddr := refLn.Addr().(*net.TCPAddr)

	inCfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{{Id: testUUID, Policy: "http2-api"}},
		Fallback: &reflex.Fallback{Dest: uint32(echoPort)},
	}
	inH, err := New(ctx, inCfg)
	if err != nil {
		t.Fatal(err)
	}

	// accept loop
	go func() {
		for {
			c, aerr := refLn.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = inH.(*Handler).Process(ctx, xnet.Network_TCP, conn, nil)
			}(c)
		}
	}()

	// outbound client
	outCfg := &reflex.OutboundConfig{
		Address:          refAddr.IP.String(),
		Port:             uint32(refAddr.Port),
		Id:               testUUID,
		Policy:           "http2-api",
		UseHttpHandshake: true,
	}
	cli, err := outbound.NewClient(outCfg)
	if err != nil {
		t.Fatal(err)
	}

	conn, sess, profile, err := cli.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// send destination request to echo server
	if err := cli.SendRequest(sess, conn, "127.0.0.1", echoPort, nil, profile); err != nil {
		t.Fatal(err)
	}

	msg := bytes.Repeat([]byte("A"), 512)
	if err := sess.WriteFrameWithMorphing(conn, reflex.FrameTypeData, msg, profile); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)

	var got []byte
	for len(got) < len(msg) {
		f, rerr := sess.ReadFrame(r)
		if rerr != nil {
			t.Fatal(rerr)
		}
		switch f.Type {
		case reflex.FrameTypeData:
			got = append(got, f.Payload...)
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			sess.HandleControlFrame(f, profile)
		case reflex.FrameTypeClose:
			t.Fatalf("closed before receiving echo")
		}
	}

	if !bytes.Equal(got[:len(msg)], msg) {
		t.Fatalf("echo mismatch: got %d bytes want %d bytes", len(got), len(msg))
	}
}

func TestInbound_DetectsPOSTLike(t *testing.T) {
	h := &Handler{}
	if !h.isHTTPPostLike([]byte("POST / HTTP/1.1\r\n")) {
		t.Fatal("expected POST-like true")
	}
	if h.isHTTPPostLike([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("expected GET false")
	}
}

func TestInbound_TimestampFreshness(t *testing.T) {
	now := time.Now().Unix()
	if !isTimestampFresh(now, 5*time.Minute) {
		t.Fatal("expected fresh")
	}
	old := time.Now().Add(-10 * time.Minute).Unix()
	if isTimestampFresh(old, 5*time.Minute) {
		t.Fatal("expected not fresh")
	}
}
