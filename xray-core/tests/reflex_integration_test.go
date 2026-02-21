package tests

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// echoDispatcher returns a Link that echoes everything: data written to the link's Writer
// is read back from the link's Reader (so the Reflex server sends it back to the client).
type echoDispatcher struct {
	routing.Dispatcher
}

func (e *echoDispatcher) Type() interface{} { return (*routing.Dispatcher)(nil) }
func (e *echoDispatcher) Start() error      { return nil }
func (e *echoDispatcher) Close() error      { return nil }
func (e *echoDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	// Two pipes: inbound writes to w1 (upstream), reads from r2 (from upstream).
	// We copy r1 -> w2 so whatever inbound sends "upstream" comes back.
	r1, w1 := pipe.New(pipe.WithoutSizeLimit())
	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: r2, Writer: w1}
	go func() {
		_ = buf.Copy(r1, w2)
		common.Close(w2)
	}()
	return link, nil
}
func (e *echoDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return errors.New("not used")
}

// integrationDialer dials a fixed address (used by outbound to connect to our test server).
type integrationDialer struct {
	addr string
	conn net.Conn
}

func (d *integrationDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	c, err := net.DialTimeout("tcp", d.addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	d.conn = c
	return &pipeConn{c}, nil
}
func (d *integrationDialer) DestIpAddress() net.IP                                        { return nil }
func (d *integrationDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

// TestXrayReflexIntegration runs a full integration test: TCP server with Reflex inbound,
// echo dispatcher (upstream echoes back), Reflex outbound client; send data and verify echo.
func TestXrayReflexIntegration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()

	userUUID := uuid.New().String()
	inboundConfig := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: userUUID}},
	}
	inHandler, err := inbound.New(context.Background(), inboundConfig)
	if err != nil {
		t.Fatalf("inbound New: %v", err)
	}

	dispatcher := &echoDispatcher{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = inHandler.Process(context.Background(), xnet.Network_TCP, pipeToStat(c), dispatcher)
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	tcpAddr := ln.Addr().(*net.TCPAddr)
	outboundConfig := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    uint32(tcpAddr.Port),
		Id:      userUUID,
	}
	outHandler, err := outbound.New(context.Background(), outboundConfig)
	if err != nil {
		t.Fatalf("outbound New: %v", err)
	}

	dialer := &integrationDialer{addr: addr}
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: downlinkReader, Writer: downlinkWriter}

	target := xnet.TCPDestination(xnet.DomainAddress("echo.local"), 80)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})

	processDone := make(chan error, 1)
	go func() {
		processDone <- outHandler.Process(ctx, link, dialer)
	}()

	// Send test data (app -> proxy -> server -> echo -> server -> proxy -> app)
	data := []byte("test data")
	b := buf.New()
	_, _ = b.Write(data)
	if err := downlinkWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("write to link: %v", err)
	}

	// Receive echoed data
	mb, err := downlinkReader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read from link: %v", err)
	}
	var response []byte
	for _, buffer := range mb {
		response = append(response, buffer.Bytes()...)
		buffer.Release()
	}

	if !bytes.Equal(data, response) {
		t.Fatalf("data mismatch: sent %q, got %q", data, response)
	}

	// Close writer so outbound exits
	common.Close(downlinkWriter)
	<-processDone
}
