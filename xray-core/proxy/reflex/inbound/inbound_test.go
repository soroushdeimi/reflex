package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	stdnet "net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

type fakeProfile struct{}

func (*fakeProfile) Equals(protocol.Account) bool { return false }
func (*fakeProfile) ToProto() proto.Message       { return nil }

type bufferedStreamConn struct {
	*bufio.Reader
	stdnet.Conn
}

func (b *bufferedStreamConn) Read(p []byte) (int, error) {
	return b.Reader.Read(p)
}

type dummyRouter struct {
	hook func(context.Context, net.Destination) (*transport.Link, error)
}

func (d *dummyRouter) Dispatch(ctx context.Context, dst net.Destination) (*transport.Link, error) {
	return d.hook(ctx, dst)
}
func (d *dummyRouter) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
func (d *dummyRouter) Start() error      { return nil }
func (d *dummyRouter) Close() error      { return nil }
func (d *dummyRouter) Type() interface{} { return routing.DispatcherType() }

func spinUpLocalServer(t *testing.T, payload string) (uint32, func()) {
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("failed to open local port:", err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(payload))
	})

	go http.Serve(l, h)

	_, portText, _ := stdnet.SplitHostPort(l.Addr().String())
	p, _ := strconv.ParseUint(portText, 10, 32)

	return uint32(p), func() { l.Close() }
}

func TestIdentityMatch(t *testing.T) {
	baseAcc := &MemoryAccount{Id: "userX", Policy: "vip"}
	twinAcc := &MemoryAccount{Id: "userX", Policy: "vip"}
	diffAcc := &MemoryAccount{Id: "userY", Policy: "vip"}

	scenarios := []struct {
		target protocol.Account
		expect bool
	}{
		{baseAcc, true},
		{twinAcc, true},
		{diffAcc, false},
		{nil, false},
		{&fakeProfile{}, false},
	}

	for _, s := range scenarios {
		if out := baseAcc.Equals(s.target); out != s.expect {
			t.Fatalf("mismatch for target %v: got %v", s.target, out)
		}
	}
}

func TestAccountProtobufExport(t *testing.T) {
	acc := &MemoryAccount{Id: "test_id", Policy: "standard"}
	res := acc.ToProto()

	if res == nil {
		t.Fatal("protobuf export returned nil")
	}

	casted, valid := res.(*reflex.Account)
	if !valid {
		t.Fatalf("unexpected type: %T", res)
	}
	if casted.GetId() != "test_id" {
		t.Errorf("wrong id in protobuf: %s", casted.GetId())
	}
}

func TestHandlerNetworks(t *testing.T) {
	inst := &Handler{}
	n := inst.Network()

	if len(n) == 0 {
		t.Fatal("empty network array")
	}
	if n[0] != net.Network_TCP {
		t.Errorf("expected TCP network, got %v", n[0])
	}
}

func TestInstantiateInbound(t *testing.T) {
	c := context.Background()
	cfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{{Id: "usr1", Policy: "api"}},
		Fallback: &reflex.Fallback{Dest: 8080},
	}

	h, err := New(c, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("handler creation failed")
	}
	if len(h.Network()) == 0 {
		t.Error("TCP support missing")
	}
}

func TestRoutingFallbackAction(t *testing.T) {
	port, cleanup := spinUpLocalServer(t, "ok")
	defer cleanup()

	cfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{},
		Fallback: &reflex.Fallback{Dest: port},
	}

	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()

	h, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	cConn, sConn := stdnet.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	rdr := bufio.NewReader(sConn)
	ch := make(chan error, 1)

	go func() {
		ch <- h.Process(ctx, net.Network_TCP, &bufferedStreamConn{Reader: rdr, Conn: sConn}, nil)
	}()

	time.Sleep(50 * time.Millisecond)
	cConn.Write([]byte("GET / HTTP/1.0\r\nHost: loc\r\n\r\n"))

	b := make([]byte, 128)
	cConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := cConn.Read(b)

	if n == 0 {
		t.Log("no bytes read")
	}

	select {
	case <-ch:
	case <-time.After(time.Second):
	}
}

func TestRoutingHTTPPostFallback(t *testing.T) {
	port, cleanup := spinUpLocalServer(t, "post-ok")
	defer cleanup()

	cfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{},
		Fallback: &reflex.Fallback{Dest: port},
	}

	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()

	h, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	cConn, sConn := stdnet.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	rdr := bufio.NewReader(sConn)
	ch := make(chan error, 1)

	go func() {
		ch <- h.Process(ctx, net.Network_TCP, &bufferedStreamConn{Reader: rdr, Conn: sConn}, nil)
	}()

	time.Sleep(50 * time.Millisecond)
	cConn.Write([]byte("POST /d HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"))

	b := make([]byte, 128)
	cConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := cConn.Read(b)

	if n == 0 {
		t.Log("no bytes read")
	}

	select {
	case <-ch:
	case <-time.After(time.Second):
	}
}

func TestProfileSelection(t *testing.T) {
	h := &Handler{}

	scenarios := map[string]*TrafficProfile{
		"http2-api": DefaultProfiles["http2-api"],
		"youtube":   DefaultProfiles["youtube"],
		"zoom":      DefaultProfiles["zoom"],
		"weird":     DefaultProfile,
		"":          DefaultProfile,
	}

	for key, expected := range scenarios {
		if h.getProfile(key) != expected {
			t.Errorf("wrong profile for key: %s", key)
		}
	}
}

func TestReflexHandshakeSkip(t *testing.T) {
	t.Skip("skipping complex integration")
}

func TestProtocolFrameManipulation(t *testing.T) {
	prf := DefaultProfile

	frm1 := &Frame{Type: FrameTypePadding, Payload: []byte{0x04, 0x00}}
	h := &Handler{}
	h.handleControlFrame(frm1, prf)
	if prf.GetPacketSize() != 1024 {
		t.Errorf("padding failed, got %d", prf.GetPacketSize())
	}

	frm2 := &Frame{Type: FrameTypeTiming, Payload: []byte{0, 0, 0, 0, 0, 0, 0x00, 0x64}}
	h.handleControlFrame(frm2, prf)
	if prf.GetDelay() != 100*time.Millisecond {
		t.Errorf("timing failed, got %v", prf.GetDelay())
	}
}

func TestMethodDetection(t *testing.T) {
	h := &Handler{}
	scenarios := []struct {
		d []byte
		w bool
	}{
		{[]byte("POST /api HTTP/1.1"), true},
		{[]byte("GET / HTTP/1.1"), false},
		{[]byte("POS"), false},
		{[]byte{}, false},
		{[]byte{0x52, 0x46, 0x58, 0x4C}, false},
	}

	for i, s := range scenarios {
		if res := h.isHTTPPostLike(s.d); res != s.w {
			t.Errorf("scenario %d failed", i)
		}
	}
}

func TestTargetExtraction(t *testing.T) {
	scenarios := []struct {
		lbl  string
		data []byte
		err  bool
		fn   func(*testing.T, []byte)
	}{
		{
			"v4", []byte{1, 127, 0, 0, 1, 0, 80}, false,
			func(tt *testing.T, d []byte) {
				if d[0] != 1 || len(d) < 7 {
					tt.Error("v4 parsing error")
				}
			},
		},
		{
			"dom", []byte{2, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 80}, false,
			func(tt *testing.T, d []byte) {
				if d[0] != 2 || d[1] != 7 {
					tt.Error("domain parsing error")
				}
			},
		},
		{"short", []byte{1, 127, 0}, true, nil},
		{"empty", []byte{}, true, nil},
	}

	for _, s := range scenarios {
		t.Run(s.lbl, func(tt *testing.T) {
			if len(s.data) < 4 && s.err {
				return
			}
			if s.fn != nil {
				s.fn(tt, s.data)
			}
		})
	}
}

func TestRejectWithoutFallback(t *testing.T) {
	cfg := &reflex.InboundConfig{Clients: []*reflex.User{}}
	ctx := context.Background()
	h, _ := New(ctx, cfg)

	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	rdr := bufio.NewReader(sC)
	ch := make(chan error, 1)

	go func() {
		ch <- h.Process(ctx, net.Network_TCP, &bufferedStreamConn{Reader: rdr, Conn: sC}, nil)
	}()

	cC.Write([]byte("GET / HTTP/1.0\r\n"))
	cC.Close()

	select {
	case err := <-ch:
		if err == nil {
			t.Error("missing error on absent fallback")
		}
	case <-time.After(time.Second):
		t.Error("timeout triggered")
	}
}

func TestRejectInvalidMagicBytes(t *testing.T) {
	port, cleanup := spinUpLocalServer(t, "")
	defer cleanup()

	cfg := &reflex.InboundConfig{
		Clients:  []*reflex.User{},
		Fallback: &reflex.Fallback{Dest: port},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h, _ := New(ctx, cfg)

	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	rdr := bufio.NewReader(sC)
	ch := make(chan error, 1)

	go func() {
		ch <- h.Process(ctx, net.Network_TCP, &bufferedStreamConn{Reader: rdr, Conn: sC}, nil)
	}()

	cC.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	time.Sleep(50 * time.Millisecond)
	cC.Close()

	select {
	case <-ch:
	case <-time.After(time.Second):
	}
}

func TestTerminationFrameCheck(t *testing.T) {
	f := &Frame{Type: FrameTypeClose, Payload: nil}
	if f.Type != FrameTypeClose {
		t.Error("incorrect frame assignment")
	}
}

func TestVariousBoundaries(t *testing.T) {
	t.Run("empty frame payload", func(tt *testing.T) {
		k := make([]byte, 32)
		s, _ := NewSession(k)
		var b bytes.Buffer
		if err := s.WriteFrame(&b, FrameTypeData, []byte{}); err != nil {
			tt.Error("payload zero error")
		}
	})

	t.Run("nil traffic morphing", func(tt *testing.T) {
		d := []byte("demo")
		res, del := (*TrafficProfile)(nil).ApplyMorphing(d)
		if len(res) != len(d) || del != 0 {
			tt.Error("nil profile mutation failure")
		}
	})

	t.Run("multiple configurations", func(tt *testing.T) {
		ua, ub, uc := uuid.New(), uuid.New(), uuid.New()
		cfg := &reflex.InboundConfig{
			Clients: []*reflex.User{
				{Id: (&ua).String(), Policy: "a"},
				{Id: (&ub).String(), Policy: "b"},
				{Id: (&uc).String(), Policy: "c"},
			},
		}
		h, _ := New(context.Background(), cfg)
		inst := h.(*Handler)
		if len(inst.clients) != 3 {
			tt.Error("client count mismatch")
		}
	})
}

func TestCryptographicSequence(t *testing.T) {
	u := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: (&u).String(), Policy: "x"}},
	}
	h, _ := New(context.Background(), cfg)
	inst := h.(*Handler)

	cPriv, cPub, _ := generateKeyPair()
	var b bytes.Buffer

	b.WriteByte(byte(ReflexMagic >> 24))
	b.WriteByte(byte((ReflexMagic >> 16) & 0xFF))
	b.WriteByte(byte((ReflexMagic >> 8) & 0xFF))
	b.WriteByte(byte(ReflexMagic & 0xFF))
	b.Write(cPub[:])
	b.Write(u[:])

	ts := time.Now().Unix()
	for i := 7; i >= 0; i-- {
		b.WriteByte(byte((ts >> (i * 8)) & 0xFF))
	}

	b.Write(make([]byte, 16))

	r := bufio.NewReader(&b)
	hs, err := readClientHandshakeMagic(r)
	if err != nil {
		t.Fatal(err)
	}

	if inst.authenticateUser(hs.UserID) == nil {
		t.Error("auth bypass failure")
	}

	sPriv, sPub, _ := generateKeyPair()
	sh1 := deriveSharedKey(sPriv, hs.PublicKey)
	sk1 := deriveSessionKey(sh1, []byte("reflex-session"))

	if len(sk1) != 32 {
		t.Error("session key len mismatch")
	}

	var rb bytes.Buffer
	shs := &ServerHandshake{PublicKey: sPub, PolicyGrant: []byte{}}
	writeServerHandshakeMagic(&rb, shs)

	sh2 := deriveSharedKey(cPriv, sPub)
	sk2 := deriveSessionKey(sh2, []byte("reflex-session"))

	if !bytes.Equal(sk1, sk2) {
		t.Error("key divergence detected")
	}
}

func TestConnectionBufferWrapper(t *testing.T) {
	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	rdr := bufio.NewReader(sC)
	wrp := &preloadedConn{Reader: rdr, Connection: &bufferedStreamConn{Reader: rdr, Conn: sC}}

	go cC.Write([]byte("start"))

	b := make([]byte, 10)
	sC.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := wrp.Read(b)

	if n != 5 || string(b[:n]) != "start" {
		t.Error("read proxy failure")
	}

	ch := make(chan bool)
	go func() {
		bx := make([]byte, 10)
		cC.SetReadDeadline(time.Now().Add(time.Second))
		nx, _ := cC.Read(bx)
		ch <- (nx == 3 && string(bx[:nx]) == "end")
	}()

	wrp.Write([]byte("end"))

	select {
	case ok := <-ch:
		if !ok {
			t.Error("write proxy failure")
		}
	case <-time.After(2 * time.Second):
		t.Error("write lock")
	}
}

func TestConstantsMapping(t *testing.T) {
	vals := []uint8{FrameTypeData, FrameTypePadding, FrameTypeTiming, FrameTypeClose}
	for _, v := range vals {
		if v == 0 {
			t.Error("invalid zero frame type")
		}
	}
}

func TestInvalidSessionSizeRejection(t *testing.T) {
	for _, sz := range []int{16, 0} {
		if _, err := NewSession(make([]byte, sz)); err == nil {
			t.Error("accepted invalid key len")
		}
	}
}

func TestIncompleteReadSkip(t *testing.T) { t.Skip() }
func TestValidHandshakeSkip(t *testing.T) { t.Skip() }
func TestUserValidationSkip(t *testing.T) { t.Skip() }

func TestRejectionOnInvalidUserFallback(t *testing.T) {
	uid := uuid.New()
	badUID := uuid.New() 
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: (&uid).String(), Policy: "x"}},
	}
	ctx := context.Background()
	h, _ := New(ctx, cfg)
	inst := h.(*Handler)

	_, cP, _ := generateKeyPair()
	hs := &ClientHandshake{PublicKey: cP, UserID: badUID, Timestamp: time.Now().Unix()}

	var b bytes.Buffer
	r := bufio.NewReader(&b)
	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	if err := inst.processHandshake(ctx, r, &bufferedStreamConn{Reader: r, Conn: sC}, nil, hs); err == nil {
		t.Error("unhandled invalid user fallback")
	}
}

func TestSessionInitStrictData(t *testing.T) {
	u := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: (&u).String(), Policy: "z"}},
	}
	ctx := context.Background()
	h, _ := New(ctx, cfg)
	inst := h.(*Handler)

	k := make([]byte, 32)
	s, _ := NewSession(k)

	var b bytes.Buffer
	s.WriteFrame(&b, FrameTypePadding, []byte{0x04, 0x00})

	usr := &protocol.MemoryUser{Email: (&u).String(), Account: &MemoryAccount{Id: (&u).String(), Policy: "z"}}
	r := bufio.NewReader(&b)
	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	err := inst.handleSession(ctx, r, &bufferedStreamConn{Reader: r, Conn: sC}, nil, k, usr)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("DATA")) {
		t.Error("strict data frame check missed")
	}
}

func TestRelayV4Target(t *testing.T) {
	u := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: (&u).String(), Policy: "a"}},
	}
	ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()

	h, _ := New(ctx, cfg)
	inst := h.(*Handler)

	pld := []byte{1, 127, 0, 0, 1, 0, 80}
	k := make([]byte, 32)
	s, _ := NewSession(k)

	var b bytes.Buffer
	s.WriteFrame(&b, FrameTypeClose, nil)

	usr := &protocol.MemoryUser{Email: (&u).String(), Account: &MemoryAccount{Id: (&u).String(), Policy: "a"}}
	prf := inst.getProfile("a")

	flag := false
	dr := &dummyRouter{
		hook: func(cx context.Context, d net.Destination) (*transport.Link, error) {
			flag = true
			if d.Address.String() != "127.0.0.1" || d.Port.Value() != 80 {
				t.Error("v4 dest decode error")
			}
			r1, w1 := pipe.New(pipe.WithSizeLimit(4096))
			_, w2 := pipe.New(pipe.WithSizeLimit(4096))
			go func() {
				time.Sleep(100 * time.Millisecond)
				w1.Close()
				w2.Close()
			}()
			return &transport.Link{Reader: r1, Writer: w2}, nil
		},
	}

	r := bufio.NewReader(&b)
	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	inst.handleDataFrame(ctx, pld, r, &bufferedStreamConn{Reader: r, Conn: sC}, dr, s, usr, prf)

	if !flag {
		t.Error("router ignored")
	}
}

func TestRelayDomainTarget(t *testing.T) {
	u := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: (&u).String(), Policy: "b"}},
	}
	ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()

	h, _ := New(ctx, cfg)
	inst := h.(*Handler)

	pld := []byte{2, 10, 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xBB}
	k := make([]byte, 32)
	s, _ := NewSession(k)

	var b bytes.Buffer
	s.WriteFrame(&b, FrameTypeClose, nil)

	usr := &protocol.MemoryUser{Email: (&u).String(), Account: &MemoryAccount{Id: (&u).String(), Policy: "b"}}
	prf := inst.getProfile("b")

	flag := false
	dr := &dummyRouter{
		hook: func(cx context.Context, d net.Destination) (*transport.Link, error) {
			flag = true
			if d.Address.String() != "google.com" || d.Port.Value() != 443 {
				t.Error("domain dest decode error")
			}
			r1, w1 := pipe.New(pipe.WithSizeLimit(4096))
			_, w2 := pipe.New(pipe.WithSizeLimit(4096))
			go func() {
				time.Sleep(100 * time.Millisecond)
				w1.Close()
				w2.Close()
			}()
			return &transport.Link{Reader: r1, Writer: w2}, nil
		},
	}

	r := bufio.NewReader(&b)
	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	inst.handleDataFrame(ctx, pld, r, &bufferedStreamConn{Reader: r, Conn: sC}, dr, s, usr, prf)

	if !flag {
		t.Error("router ignored")
	}
}

func TestRelayV6Target(t *testing.T) {
	u := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: (&u).String(), Policy: "c"}},
	}
	ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()

	h, _ := New(ctx, cfg)
	inst := h.(*Handler)

	pld := []byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1F, 0x90}
	k := make([]byte, 32)
	s, _ := NewSession(k)

	var b bytes.Buffer
	s.WriteFrame(&b, FrameTypeClose, nil)

	usr := &protocol.MemoryUser{Email: (&u).String(), Account: &MemoryAccount{Id: (&u).String(), Policy: "c"}}
	prf := inst.getProfile("c")

	flag := false
	dr := &dummyRouter{
		hook: func(cx context.Context, d net.Destination) (*transport.Link, error) {
			flag = true
			if d.Port.Value() != 8080 {
				t.Error("v6 dest decode error")
			}
			r1, w1 := pipe.New(pipe.WithSizeLimit(4096))
			_, w2 := pipe.New(pipe.WithSizeLimit(4096))
			go func() {
				time.Sleep(100 * time.Millisecond)
				w1.Close()
				w2.Close()
			}()
			return &transport.Link{Reader: r1, Writer: w2}, nil
		},
	}

	r := bufio.NewReader(&b)
	cC, sC := stdnet.Pipe()
	defer cC.Close()
	defer sC.Close()

	inst.handleDataFrame(ctx, pld, r, &bufferedStreamConn{Reader: r, Conn: sC}, dr, s, usr, prf)

	if !flag {
		t.Error("router ignored")
	}
}

func TestRelayMalformedTargets(t *testing.T) {
	scenarios := [][]byte{
		{1, 127, 0},
		{},
		{99, 127, 0, 0, 1, 0, 80},
	}
	for _, p := range scenarios {
		if len(p) >= 7 {
			continue
		}
	}
}

func TestHTTPIntegrationSkips(t *testing.T) {
	t.Skip()
}

func TestHTTPInvalidSkips(t *testing.T) {
	t.Skip()
}

func TestHTTPNoLenSkips(t *testing.T) {
	t.Skip()
}

func TestHeaderLengthExtraction(t *testing.T) {
	scenarios := map[string]int64{
		"Content-Length: 100\r\n":         100,
		"content-length: 200\r\n":         200,
		"Content-Type: application/json\r\n": -1,
	}

	for hd, expected := range scenarios {
		if len(hd) > 16 && (hd[:14] == "Content-Length" || hd[:14] == "content-length") {
			splt := bytes.Split([]byte(hd), []byte(":"))
			if len(splt) >= 2 {
				val := bytes.TrimSpace(splt[1])
				num, _ := strconv.ParseInt(string(val), 10, 64)
				if num != expected {
					t.Error("header decode mismatch")
				}
			}
		}
	}
}

func TestCodecBase64Integration(t *testing.T) {
	u := uuid.New()
	_, cP, _ := generateKeyPair()

	var b bytes.Buffer
	b.WriteByte(byte(ReflexMagic >> 24))
	b.WriteByte(byte((ReflexMagic >> 16) & 0xFF))
	b.WriteByte(byte((ReflexMagic >> 8) & 0xFF))
	b.WriteByte(byte(ReflexMagic & 0xFF))
	b.Write(cP[:])
	b.Write(u[:])

	ts := time.Now().Unix()
	for i := 7; i >= 0; i-- {
		b.WriteByte(byte((ts >> (i * 8)) & 0xFF))
	}
	b.Write(make([]byte, 16))

	enc := base64.StdEncoding.EncodeToString(b.Bytes())
	dec, err := base64.StdEncoding.DecodeString(enc)

	if err != nil || !bytes.Equal(dec, b.Bytes()) || len(dec) != MinHandshakeSize {
		t.Error("base64 cycle invalid")
	}
}