package tunnel

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestBootstrap_ReadWriteInitialDestination(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}

	sA, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession A: %v", err)
	}
	sB, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession B: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c2.Close()

	dc := SocksAddrCodec{}
	wantDest := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443))
	wantInit := []byte("hello")

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c1.Close()

		// IMPORTANT: Do NOT send CLOSE frame here, because ReadInitialDestination stops after first DATA
		// and net.Pipe is unbuffered. Sending more frames can deadlock the writer.
		if err := WriteInitialDestination(sA, c1, dc, wantDest, wantInit); err != nil {
			t.Errorf("WriteInitialDestination: %v", err)
			return
		}
	}()

	gotDest, gotInit, err := ReadInitialDestination(sB, c2, dc)
	if err != nil {
		t.Fatalf("ReadInitialDestination: %v", err)
	}
	<-done

	assertDestEqual(t, gotDest, wantDest)
	if !bytes.Equal(gotInit, wantInit) {
		t.Fatalf("initial payload mismatch: got %q want %q", string(gotInit), string(wantInit))
	}
}

func TestBootstrap_ReadInitialDestination_SkipsPaddingTiming(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}

	sA, _ := NewSession(key)
	sB, _ := NewSession(key)

	c1, c2 := net.Pipe()
	defer c2.Close()

	dc := SocksAddrCodec{}
	wantDest := xnet.TCPDestination(xnet.DomainAddress("xray.example"), xnet.Port(80))
	wantInit := []byte("GET /")

	go func() {
		defer c1.Close()
		_ = sA.WriteFrame(c1, FrameTypePadding, []byte("pad"))
		_ = sA.WriteFrame(c1, FrameTypeTiming, []byte("tim"))
		_ = WriteInitialDestination(sA, c1, dc, wantDest, wantInit)
	}()

	gotDest, gotInit, err := ReadInitialDestination(sB, c2, dc)
	if err != nil {
		t.Fatalf("ReadInitialDestination: %v", err)
	}

	assertDestEqual(t, gotDest, wantDest)
	if !bytes.Equal(gotInit, wantInit) {
		t.Fatalf("initial payload mismatch: got %q want %q", string(gotInit), string(wantInit))
	}
}

func TestBootstrap_ReadInitialDestination_CloseBeforeData(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}

	sA, _ := NewSession(key)
	sB, _ := NewSession(key)

	c1, c2 := net.Pipe()
	defer c2.Close()

	dc := SocksAddrCodec{}

	go func() {
		defer c1.Close()
		_ = WriteClose(sA, c1) // This is safe: ReadInitialDestination will keep reading until it sees CLOSE.
	}()

	_, _, err := ReadInitialDestination(sB, c2, dc)
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
}
