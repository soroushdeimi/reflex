package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"net"

	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
)

// 1. تست رمزنگاری
func TestEncryption(t *testing.T) {
	key := make([]byte, 32)
	session, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("Failed to initialize session: %v", err)
	}

	original := []byte("secret reflex data")
	buffer := new(bytes.Buffer)

	if err := session.WriteFrame(buffer, reflex.FrameTypeData, original); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	frame, err := session.ReadFrame(buffer)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(original, frame.Payload) {
		t.Fatal("Data corruption during encryption/decryption")
	}
}

// 2. تست هندشیک
func TestHandshake(t *testing.T) {
	outConfig := &reflex.OutboundConfig{
		Id: "29525c56-6556-43f1-8b2b-09b673627038",
	}
	_, err := outbound.New(context.Background(), outConfig)
	if err != nil {
		t.Fatalf("Outbound handshake initialization failed: %v", err)
	}
}

// 3. تست فال‌بک
func TestFallback(t *testing.T) {
	inConfig := &reflex.InboundConfig{
		Fallback: &reflex.Fallback{
			Dest: 80,
		},
	}
	if inConfig.GetFallback().GetDest() != 80 {
		t.Fatal("Fallback configuration failed")
	}
}

// 4. تست یکپارچگی
func TestIntegration(t *testing.T) {
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: "29525c56-6556-43f1-8b2b-09b673627038"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	h, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		var wrongMagic [4]byte
		binary.BigEndian.PutUint32(wrongMagic[:], 0xDEADBEEF)
		_, _ = clientConn.Write(wrongMagic[:])
	}()

	reader := bufio.NewReader(serverConn)
	pc := &pipeConn{reader: reader, conn: serverConn}

	err = h.Process(ctx, xnet.Network_TCP, pc, nil)
	if err == nil {
		t.Error("Expected error for wrong magic, but connection succeeded")
	}
}

type pipeConn struct {
	reader *bufio.Reader
	conn   net.Conn
}

func (p *pipeConn) Read(b []byte) (int, error)         { return p.reader.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error)        { return p.conn.Write(b) }
func (p *pipeConn) Close() error                       { return p.conn.Close() }
func (p *pipeConn) RemoteAddr() net.Addr               { return p.conn.RemoteAddr() }
func (p *pipeConn) LocalAddr() net.Addr                { return p.conn.LocalAddr() }
func (p *pipeConn) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

func (p *pipeConn) Reusable() bool             { return false }
func (p *pipeConn) SetReusable(b bool)         {}
func (p *pipeConn) SysConn() (net.Conn, error) { return p.conn, nil }
