package outbound

import (
	"bufio"
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/tunnel"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return New(ctx, cfg.(*reflex.OutboundConfig))
	}))
}

var _ proxy.Outbound = (*Handler)(nil)

// Handler is a Reflex outbound handler (Step3: handshake + encrypted transport).
type Handler struct {
	config   *reflex.OutboundConfig
	dest     net.Destination
	clientID [16]byte
	engine   *reflex.ClientHandshakeEngine
}

func New(ctx context.Context, cfg *reflex.OutboundConfig) (*Handler, error) {
	_ = ctx

	// Parse UUID once (fast + safer).
	id, err := uuid.ParseString(cfg.GetId())
	if err != nil {
		return nil, errors.New("reflex outbound: invalid id uuid").Base(err)
	}
	var idBytes [16]byte
	copy(idBytes[:], id.Bytes())

	dest := net.TCPDestination(net.ParseAddress(cfg.GetAddress()), net.Port(cfg.GetPort()))
	eng := reflex.NewClientHandshakeEngine(idBytes, cfg.GetAddress())

	return &Handler{
		config:   cfg,
		dest:     dest,
		clientID: idBytes,
		engine:   eng,
	}, nil
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// Get real target from context (standard Xray pattern).
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("reflex outbound: target not specified").AtError()
	}
	if ob.Target.Network != net.Network_TCP {
		return errors.New("reflex outbound: only supports TCP target").AtError()
	}
	ob.Name = "reflex"

	var conn stat.Connection
	var err error
	conn, err = dialer.Dial(ctx, h.dest)
	if err != nil {
		return errors.New("reflex outbound: dial failed").Base(err).AtWarning()
	}
	defer conn.Close()

	// --- Step2: Handshake ---
	info, err := h.engine.DoHandshakeHTTP(conn)
	if err != nil {
		return errors.New("reflex outbound: handshake failed").Base(err).AtInfo()
	}

	// --- Step3: Encrypted transport ---
	sess, err := tunnel.NewSession(info.SessionKey[:])
	if err != nil {
		return errors.New("reflex outbound: session init failed").Base(err)
	}

	// Use a buffered reader for encrypted frames (performance).
	encReader := bufio.NewReader(conn)

	// Send the initial destination frame immediately (payload can be empty).
	dc := tunnel.SocksAddrCodec{}
	if err := tunnel.WriteInitialDestination(sess, conn, dc, ob.Target, nil); err != nil {
		return errors.New("reflex outbound: failed to write initial destination").Base(err).AtInfo()
	}

	// Client -> Server: link.Reader => encrypted DATA frames => conn
	requestDone := func() error {
		return tunnel.CopyToEncryptedConn(sess, conn, link.Reader)
	}

	// Server -> Client: conn => decrypted DATA frames => link.Writer
	responseDone := func() error {
		return tunnel.CopyFromEncryptedConn(sess, encReader, link.Writer)
	}

	// When request finishes normally, notify server with CLOSE.
	requestDonePost := task.OnSuccess(requestDone, func() error {
		return tunnel.WriteClose(sess, conn)
	})

	// When response finishes normally, close link.Writer.
	responseDonePost := task.OnSuccess(responseDone, task.Close(link.Writer))

	if err := task.Run(ctx, requestDonePost, responseDonePost); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("reflex outbound: connection ends").Base(err)
	}

	return nil
}
