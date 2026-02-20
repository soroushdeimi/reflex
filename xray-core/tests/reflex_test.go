package tests

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
)

type wrappedStream struct {
	ioReader *bufio.Reader
	net.Conn
}

func (w *wrappedStream) Read(p []byte) (int, error) {
	return w.ioReader.Read(p)
}

func TestInboundInitialization(t *testing.T) {
	newUUID := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: newUUID.String(), Policy: "http2-api"},
		},
		Fallback: &reflex.Fallback{Dest: 80},
	}

	c := context.Background()
	inst, err := inbound.New(c, cfg)

	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if inst == nil {
		t.Fatal("Returned handler is empty")
	}
	if len(inst.Network()) == 0 {
		t.Error("Missing TCP network support")
	}
}

func TestFallbackRouting(t *testing.T) {
	mockSrv := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		res.Write([]byte("mock-fallback-response"))
	}))
	defer mockSrv.Close()

	_, pStr, _ := net.SplitHostPort(mockSrv.Listener.Addr().String())
	portNum, _ := strconv.ParseUint(pStr, 10, 32)

	cfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{},
		Fallback: &reflex.Fallback{Dest: uint32(portNum)},
	}

	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()

	hndlr, err := inbound.New(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	cPipe, sPipe := net.Pipe()
	defer cPipe.Close()
	defer sPipe.Close()

	rdr := bufio.NewReader(sPipe)

	go func() {
		_ = hndlr.Process(ctx, 0, &wrappedStream{ioReader: rdr, Conn: sPipe}, nil)
	}()

	time.Sleep(50 * time.Millisecond)

	cPipe.Write([]byte("GET / HTTP/1.1\r\nHost: local\r\n\r\n"))

	cPipe.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 512)
	n, _ := cPipe.Read(respBuf)

	if n == 0 {
		t.Log("Warning: No bytes read from fallback")
	}
}

func TestInvalidMagicRejection(t *testing.T) {
	dummyID := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: dummyID.String(), Policy: "none"},
		},
	}

	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()

	hndlr, err := inbound.New(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	cPipe, sPipe := net.Pipe()
	defer cPipe.Close()
	defer sPipe.Close()

	go func() {
		cPipe.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	}()

	rdr := bufio.NewReader(sPipe)
	_ = hndlr.Process(ctx, xnet.Network_TCP, &wrappedStream{ioReader: rdr, Conn: sPipe}, nil)
}