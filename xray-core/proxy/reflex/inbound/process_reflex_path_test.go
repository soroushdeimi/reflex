package inbound

import (
	"context"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
	"github.com/xtls/xray-core/proxy/reflex/tunnel"
	"github.com/xtls/xray-core/transport"
)

// --- Helpers for dispatcher/link ---

type recordWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (w *recordWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, b := range mb {
		if b == nil || b.IsEmpty() {
			continue
		}
		w.buf = append(w.buf, b.Bytes()...)
	}
	return nil
}

func (w *recordWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, len(w.buf))
	copy(out, w.buf)
	return out
}

type eofReader struct{}

func (eofReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, io.EOF
}

type recordDispatcher struct {
	gotDest xnet.Destination
	once    sync.Once

	link *transport.Link
}

func (d *recordDispatcher) Type() interface{} { return (*recordDispatcher)(nil) }
func (d *recordDispatcher) Start() error      { return nil }
func (d *recordDispatcher) Close() error      { return nil }

func (d *recordDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.once.Do(func() { d.gotDest = dest })
	return d.link, nil
}

func (d *recordDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	// Not used by inbound.Process
	return nil
}

func TestProcess_ReflexTrafficDoesNotFallbackAndDispatches(t *testing.T) {
	// ---- Arrange inbound with one allowed user ----
	id, err := uuid.ParseString("d89d6641-3b1a-4f51-a194-9c9109fd21b6")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: id.String(), Policy: "default"},
		},
		// fallback can exist; we just prove it won't be used for valid reflex traffic
		Fallback: &reflex.Fallback{Dest: 8080},
	}

	h, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// ---- Prepare dispatcher that records destination and captures initial payload ----
	w := &recordWriter{}
	dsp := &recordDispatcher{
		link: &transport.Link{
			Reader: eofReader{}, // outbound produces no data -> response path ends and server sends CLOSE
			Writer: w,           // inbound will write initial payload here
		},
	}

	// stdnet.Pipe simulates client <-> inbound tcp conn
	clientConn, inboundConn := stdnet.Pipe()
	defer clientConn.Close()
	// inboundConn will be closed by Process's defer.

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Run Process concurrently
	procErrCh := make(chan error, 1)
	go func() {
		procErrCh <- h.Process(ctx, xnet.Network_TCP, inboundConn, routing.Dispatcher(dsp))
	}()

	// ---- Client: Step2 handshake (HTTP flavor) ----
	var userID [handshake.UserIDSize]byte
	copy(userID[:], id.Bytes())

	clientEngine := reflex.NewClientHandshakeEngine(userID, "example.com")
	siClient, err := clientEngine.DoHandshakeHTTP(clientConn)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	// IMPORTANT: after handshake, Process will later write encrypted CLOSE to clientConn.
	// stdnet.Pipe is synchronous, so we must keep reading to avoid blocking server writes.
	drainDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
		close(drainDone)
	}()

	// ---- Client: Step3 first DATA frame = destination + initial payload ----
	sess, err := tunnel.NewSession(siClient.SessionKey[:])
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	wantDest := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(80))
	wantInit := []byte("hello")

	if err := tunnel.WriteInitialDestination(sess, clientConn, tunnel.SocksAddrCodec{}, wantDest, wantInit); err != nil {
		t.Fatalf("WriteInitialDestination: %v", err)
	}

	// Then close stream from client side (so requestDone finishes)
	if err := tunnel.WriteClose(sess, clientConn); err != nil {
		t.Fatalf("WriteClose: %v", err)
	}

	// ---- Assert Process returns cleanly ----
	select {
	case err := <-procErrCh:
		if err != nil {
			t.Fatalf("Process returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Process to return")
	}

	// ---- Assert dispatcher got the correct destination ----
	if dsp.gotDest.Network != wantDest.Network ||
		dsp.gotDest.Port != wantDest.Port ||
		dsp.gotDest.Address.String() != wantDest.Address.String() {
		t.Fatalf("dest mismatch: got=%v want=%v", dsp.gotDest, wantDest)
	}

	// ---- Assert initial payload forwarded to link.Writer ----
	gotInit := w.Bytes()
	if string(gotInit) != string(wantInit) {
		t.Fatalf("initial payload mismatch: got=%q want=%q", string(gotInit), string(wantInit))
	}

	// Drain goroutine should finish (server closes conn)
	select {
	case <-drainDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for client drain to finish")
	}
}
