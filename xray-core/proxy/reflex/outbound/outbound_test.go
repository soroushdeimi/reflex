package outbound

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
)

func TestOutbound_DialAndEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// echo upstream
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoLn.Close() }()
	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, aerr := echoLn.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// reflex inbound listener
	refLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = refLn.Close() }()
	refAddr := refLn.Addr().(*net.TCPAddr)

	inCfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{{Id: "11111111-1111-1111-1111-111111111111", Policy: "http2-api"}},
		Fallback: &reflex.Fallback{Dest: uint32(echoPort)}, // not used on success, but keeps fallback safe
	}
	h, err := inbound.New(ctx, inCfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			c, aerr := refLn.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = h.Process(ctx, xnet.Network_TCP, conn, nil)
			}(c)
		}
	}()

	outCfg := &reflex.OutboundConfig{
		Address:          refAddr.IP.String(),
		Port:             uint32(refAddr.Port),
		Id:               "11111111-1111-1111-1111-111111111111",
		Policy:           "http2-api",
		UseHttpHandshake: true,
	}
	c, err := NewClient(outCfg)
	if err != nil {
		t.Fatal(err)
	}

	conn, sess, profile, err := c.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if err := c.SendRequest(sess, conn, "127.0.0.1", echoPort, nil, profile); err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello")
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
		if f.Type == reflex.FrameTypeData {
			got = append(got, f.Payload...)
		}
	}

	if !bytes.Equal(got[:len(msg)], msg) {
		t.Fatalf("echo mismatch: got %q want %q", string(got), string(msg))
	}
}
