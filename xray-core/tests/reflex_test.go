package tests

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"strings"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
	reflexin "github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/tunnel"
	"github.com/xtls/xray-core/transport"
)

// --- Helpers (dispatcher/link) ---

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

type staticReader struct {
	mu   sync.Mutex
	data []byte
	done bool
}

func (r *staticReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return nil, io.EOF
	}
	r.done = true
	if len(r.data) == 0 {
		return nil, io.EOF
	}
	return buf.MergeBytes(nil, r.data), nil
}

type recordDispatcher struct {
	mu      sync.Mutex
	gotDest xnet.Destination
	link    *transport.Link
}

func (d *recordDispatcher) Type() interface{} { return (*recordDispatcher)(nil) }
func (d *recordDispatcher) Start() error      { return nil }
func (d *recordDispatcher) Close() error      { return nil }

func (d *recordDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.mu.Lock()
	d.gotDest = dest
	d.mu.Unlock()
	return d.link, nil
}

func (d *recordDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

func (d *recordDispatcher) GotDest() xnet.Destination {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gotDest
}

// --- Stage 1 (submission.md): integration tests in xray-core/tests/reflex_test.go ---

func TestReflex_HandshakeIntegration(t *testing.T) {
	// Known UUID
	id, err := uuid.ParseString("d89d6641-3b1a-4f51-a194-9c9109fd21b6")
	if err != nil {
		t.Fatal(err)
	}
	var userID [handshake.UserIDSize]byte
	copy(userID[:], id.Bytes())

	// Server validator with one client
	mv := reflex.NewMemoryValidator()
	if err := mv.Add(&reflex.ClientInfo{ID: id, Policy: "default"}); err != nil {
		t.Fatal(err)
	}
	serverEng := reflex.NewHandshakeEngine(mv)

	clientConn, serverConn := stdnet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverResCh := make(chan *reflex.SessionInfo, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		r := bufio.NewReader(serverConn)
		si, e := serverEng.ServerDoHandshake(r, serverConn)
		if e != nil {
			serverErrCh <- e
			return
		}
		serverResCh <- si
	}()

	clientEng := reflex.NewClientHandshakeEngine(userID, "example.com")
	siClient, err := clientEng.DoHandshakeHTTP(clientConn)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	select {
	case e := <-serverErrCh:
		t.Fatalf("server handshake failed: %v", e)
	case siServer := <-serverResCh:
		if siServer == nil {
			t.Fatal("nil server session info")
		}
		if siServer.Flavor != reflex.WireHTTP {
			t.Fatalf("expected WireHTTP, got %v", siServer.Flavor)
		}
		if siServer.SessionKey != siClient.SessionKey {
			t.Fatal("session keys mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server handshake")
	}
}

func TestReflex_EncryptionIntegration(t *testing.T) {
	// ثابت (برای تست رمزنگاری/فریم)
	key := make([]byte, handshake.SessionKeySize)
	for i := 0; i < len(key); i++ {
		key[i] = byte(i)
	}

	clientSess, err := tunnel.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}
	serverSess, err := tunnel.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	clientConn, serverConn := stdnet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// جلوگیری از hang بی‌نهایت
	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))

	wantDest := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443))
	wantInit := []byte("hello")
	wantNext := []byte("ping")
	wantResp := []byte("pong")

	// سرور: destination + payloadها را بخواند، سپس پاسخ بدهد و CLOSE بفرستد
	serverErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()

		dest, initPayload, e := tunnel.ReadInitialDestination(serverSess, serverConn, tunnel.SocksAddrCodec{})
		if e != nil {
			serverErrCh <- e
			return
		}
		if dest.Address.String() != wantDest.Address.String() || dest.Port != wantDest.Port || dest.Network != wantDest.Network {
			serverErrCh <- errors.New("destination mismatch")
			return
		}
		if string(initPayload) != string(wantInit) {
			serverErrCh <- errors.New("initial payload mismatch")
			return
		}

		f, e := serverSess.ReadFrame(serverConn)
		if e != nil {
			serverErrCh <- e
			return
		}
		if f.Type != tunnel.FrameTypeData || string(f.Payload) != string(wantNext) {
			serverErrCh <- errors.New("next data frame mismatch")
			return
		}

		// پاسخ + close (فقط سرور close می‌فرستد)
		if e := serverSess.WriteFrame(serverConn, tunnel.FrameTypeData, wantResp); e != nil {
			serverErrCh <- e
			return
		}
		_ = tunnel.WriteClose(serverSess, serverConn)

		serverErrCh <- nil
	}()

	// کلاینت: initial destination + یک فریم دیتا (بدون close)
	if err := tunnel.WriteInitialDestination(clientSess, clientConn, tunnel.SocksAddrCodec{}, wantDest, wantInit); err != nil {
		t.Fatalf("WriteInitialDestination: %v", err)
	}
	if err := clientSess.WriteFrame(clientConn, tunnel.FrameTypeData, wantNext); err != nil {
		t.Fatalf("WriteFrame(data): %v", err)
	}

	// کلاینت: پاسخ را بخواند تا CLOSE
	got := make([]byte, 0, 64)
	for {
		f, err := clientSess.ReadFrame(clientConn)
		if err != nil {
			break // deadline/EOF
		}
		switch f.Type {
		case tunnel.FrameTypeData:
			got = append(got, f.Payload...)
		case tunnel.FrameTypeClose:
			goto done
		}
	}
done:
	if string(got) != string(wantResp) {
		t.Fatalf("response mismatch: got=%q want=%q", string(got), string(wantResp))
	}

	select {
	case err := <-serverErrCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting server goroutine")
	}
}

func TestReflex_FallbackIntegration(t *testing.T) {
	// یک fallback server محلی که درخواست را کامل می‌گیرد و پاسخ می‌دهد
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*stdnet.TCPAddr).Port

	serverGotCh := make(chan []byte, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()

		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		rd := bufio.NewReader(c)

		var reqBuf bytes.Buffer
		for {
			line, err := rd.ReadBytes('\n')
			if len(line) > 0 {
				reqBuf.Write(line)
			}
			if bytes.Equal(line, []byte("\r\n")) { // end of headers
				break
			}
			if err != nil {
				break
			}
		}

		serverGotCh <- reqBuf.Bytes()

		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"))
	}()

	// inbound handler با fallback
	cfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{},
		Fallback: &reflex.Fallback{Dest: uint32(port)},
	}
	h, err := reflexin.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("inbound.New: %v", err)
	}

	clientConn, inboundConn := stdnet.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	procErrCh := make(chan error, 1)
	go func() {
		procErrCh <- h.Process(ctx, xnet.Network_TCP, inboundConn, nil)
	}()

	// ترافیک غیر-Reflex (HTTP GET)
    pad := strings.Repeat("a", 200)
    req := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nX-Pad: " + pad + "\r\n\r\n"

    // بررسی اطمینان از طول درخواست
    if len(req) < 80 {
        t.Fatalf("request too short: %d", len(req))
    }

    if _, err := clientConn.Write([]byte(req)); err != nil {
        t.Fatalf("client write: %v", err)
    }
	// اول مطمئن شو fallback واقعاً اتصال را گرفته و prefix درخواست را دیده
	select {
	case got := <-serverGotCh:
		if !bytes.Contains(got, []byte("GET / HTTP/1.1")) {
			t.Fatalf("fallback server did not receive request prefix; got=%q", string(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: fallback server did not accept/receive request")
	}

	// پاسخ را "به اندازه کافی" بخوان (ReadAll نزن چون EOF نمی‌آید)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var respBuf bytes.Buffer
	tmp := make([]byte, 64)
	for {
		n, err := clientConn.Read(tmp)
		if n > 0 {
			respBuf.Write(tmp[:n])
			if strings.Contains(respBuf.String(), "HELLO") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	resp := respBuf.String()

	if !strings.Contains(resp, "HELLO") {
		t.Fatalf("expected fallback response containing HELLO, got=%q", resp)
	}

	// حالا اتصال را ببند تا Process هم بتواند تمام شود
	_ = clientConn.Close()

	select {
	case err := <-procErrCh:
		// ممکن است با بسته‌شدن کانکشن/کانتکست سریع‌تر خارج شود؛
		// ولی نباید hang کند.
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			t.Fatalf("Process returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Process to exit")
	}
}

func TestReflex_IntegrityIntegration_EndToEndProcess(t *testing.T) {
	// inbound با یک کاربر مجاز
	id, err := uuid.ParseString("d89d6641-3b1a-4f51-a194-9c9109fd21b6")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{{Id: id.String(), Policy: "default"}},
		Fallback: &reflex.Fallback{Dest: 8080},
	}
	inH, err := reflexin.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("inbound.New: %v", err)
	}

	// dispatcher: مقصد را ضبط کند، payload ها را جمع کند و یک پاسخ ساده برگرداند
	w := &recordWriter{}
	r := &staticReader{data: []byte("pong")}
	dsp := &recordDispatcher{link: &transport.Link{Reader: r, Writer: w}}

	clientConn, inboundConn := stdnet.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	procErrCh := make(chan error, 1)
	go func() {
		procErrCh <- inH.Process(ctx, xnet.Network_TCP, inboundConn, dsp)
	}()

	// --- Client Step2: handshake ---
	var userID [handshake.UserIDSize]byte
	copy(userID[:], id.Bytes())
	clientEng := reflex.NewClientHandshakeEngine(userID, "example.com")
	siClient, err := clientEng.DoHandshakeHTTP(clientConn)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	// --- Client Step3: encrypted transport ---
	clientSess, err := tunnel.NewSession(siClient.SessionKey[:])
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}

	wantDest := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(80))
	initPayload := []byte("hello")
	morePayload := []byte("ping")

	// برای جلوگیری از deadlock روی net.Pipe: همزمان پاسخ‌ها را بخوانیم
	respCh := make(chan []byte, 1)
	go func() {
		out := make([]byte, 0, 64)
		for {
			f, e := clientSess.ReadFrame(clientConn)
			if e != nil {
				break
			}
			if f.Type == tunnel.FrameTypeData {
				out = append(out, f.Payload...)
			}
			if f.Type == tunnel.FrameTypeClose {
				break
			}
		}
		respCh <- out
	}()

	if err := tunnel.WriteInitialDestination(clientSess, clientConn, tunnel.SocksAddrCodec{}, wantDest, initPayload); err != nil {
		t.Fatalf("WriteInitialDestination: %v", err)
	}
	if err := clientSess.WriteFrame(clientConn, tunnel.FrameTypeData, morePayload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if err := tunnel.WriteClose(clientSess, clientConn); err != nil {
		t.Fatalf("WriteClose: %v", err)
	}

	// --- Assert server side (dispatcher) got destination + payload ---
	select {
	case err := <-procErrCh:
		if err != nil {
			t.Fatalf("Process returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for Process")
	}

	gotDest := dsp.GotDest()
	if gotDest.Network != wantDest.Network || gotDest.Port != wantDest.Port || gotDest.Address.String() != wantDest.Address.String() {
		t.Fatalf("dest mismatch: got=%v want=%v", gotDest, wantDest)
	}

	gotPayload := w.Bytes()
	// recordWriter شامل initPayload و morePayload می‌شود (init جداگانه و بقیه در کپی)
	if !bytes.Contains(gotPayload, initPayload) || !bytes.Contains(gotPayload, morePayload) {
		t.Fatalf("payload not forwarded; got=%q", string(gotPayload))
	}

	select {
	case resp := <-respCh:
		if string(resp) != "pong" {
			t.Fatalf("client response mismatch: got=%q want=%q", string(resp), "pong")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for client response")
	}
}
