package inbound

import (
	"bufio"
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/codec"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
	"github.com/xtls/xray-core/proxy/reflex/tunnel"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return New(ctx, cfg.(*reflex.InboundConfig))
	}))
}

var _ proxy.Inbound = (*Handler)(nil)

// Handler is a Reflex inbound handler.
type Handler struct {
	config    *reflex.InboundConfig
	validator reflex.Validator
	engine    *reflex.HandshakeEngine
}

func New(ctx context.Context, cfg *reflex.InboundConfig) (*Handler, error) {
	_ = ctx

	// Build an in-memory validator from config.
	mv := reflex.NewMemoryValidator()
	for _, c := range cfg.GetClients() {
		if c == nil {
			continue
		}
		if err := mv.AddFromConfig(c.GetId(), c.GetPolicy()); err != nil {
			return nil, errors.New("reflex inbound: invalid client").Base(err)
		}
	}

	eng := reflex.NewHandshakeEngine(mv)

	return &Handler{
		config:    cfg,
		validator: mv,
		engine:    eng,
	}, nil
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network != net.Network_TCP {
		_ = conn.Close()
		return errors.New("reflex inbound: only supports TCP")
	}

	// IMPORTANT:
	// We must keep using this bufio.Reader after handshake,
	// otherwise any buffered bytes (already read from conn) will be lost.
	reader := bufio.NewReader(conn)

	peeked, _ := reader.Peek(64)
	looksHTTP := codec.LooksLikeHTTPPost(peeked)

	// --- Step2: Handshake ---
	info, err := h.engine.ServerDoHandshake(reader, conn)
	if err != nil {

		if handshake.IsKind(err, handshake.KindNotReflex) {
			return h.handleFallback(ctx, reader, conn)
		}

		if looksHTTP {
			switch {
			case handshake.IsKind(err, handshake.KindUnauthenticated),
				handshake.IsKind(err, handshake.KindReplay):
				_ = reflex.WriteHTTPForbidden(conn)
			case handshake.IsKind(err, handshake.KindInvalidHandshake):
				_ = reflex.WriteHTTPBadRequest(conn)
			default:
				_, _ = conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"))
			}
		}
		_ = conn.Close()
		return errors.New("reflex inbound: handshake failed").Base(err).AtInfo()
	}
	defer conn.Close()

	// --- Step3: Encrypted transport + dispatch ---
	sess, err := tunnel.NewSession(info.SessionKey[:])
	if err != nil {
		return errors.New("reflex inbound: session init failed").Base(err)
	}

	// 1) Read destination from the first DATA frame.
	dc := tunnel.SocksAddrCodec{}
	dest, initialPayload, err := tunnel.ReadInitialDestination(sess, reader, dc)
	if err != nil {
		return errors.New("reflex inbound: failed to read destination").Base(err).AtInfo()
	}

	// 2) Dispatch to outbound.
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return errors.New("reflex inbound: failed to dispatch to ", dest).Base(err)
	}

	// If the first DATA frame carried extra payload after the destination header,
	// forward it to outbound before starting the bidirectional copy.
	if len(initialPayload) > 0 {
		if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, initialPayload)); err != nil {
			common.Must(common.Interrupt(link.Reader))
			common.Must(common.Interrupt(link.Writer))
			return errors.New("reflex inbound: failed to write initial payload").Base(err)
		}
	}

	// 3) Bidirectional piping.
	// Client -> Outbound: encrypted frames -> link.Writer
	requestDone := func() error {
		return tunnel.CopyFromEncryptedConn(sess, reader, link.Writer)
	}

	// Outbound -> Client: link.Reader -> encrypted frames
	responseDone := func() error {
		return tunnel.CopyToEncryptedConn(sess, conn, link.Reader)
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	responseDonePost := task.OnSuccess(responseDone, func() error { return tunnel.WriteClose(sess, conn) })

	if err := task.Run(ctx, requestDonePost, responseDonePost); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("reflex inbound: connection ends").Base(err)
	}

	return nil
}
