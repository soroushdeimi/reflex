package inbound

import (
	"bufio"
	"context"
	"errors"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	reflexcrypto "github.com/xtls/xray-core/proxy/reflex/crypto"
	reflexproto "github.com/xtls/xray-core/proxy/reflex/protocol"
	"github.com/xtls/xray-core/proxy/reflex/session"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.Id}
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

func (h *Handler) Process(
	ctx context.Context,
	network xnet.Network,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
) error {

	reader := bufio.NewReader(conn)

	sess, user, err := reflexcrypto.ServerHandshake(reader, conn, h.clients)
	if err != nil {
		if h.fallback != nil {
			return h.handleFallback(ctx, conn)
		}
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sess, user)
}

func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sess *session.Session,
	user *protocol.MemoryUser,
) error {

	// First frame must contain destination
	frame, err := sess.ReadFrame(reader)
	if err != nil {
		return err
	}

	if frame.Type != reflexproto.FrameTypeData {
		return errors.New("first frame must be DATA")
	}

	dest, payload, err := reflexproto.ParseDestination(frame.Payload)
	if err != nil {
		return err
	}

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	// Send initial payload upstream
	if len(payload) > 0 {
		buffer := buf.FromBytes(payload)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
			return err
		}
	}

	// Upstream → Client
	go func() {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				sess.WriteFrame(conn, reflexproto.FrameTypeData, b.Bytes())
				b.Release()
			}
		}
	}()

	// Client → Upstream
	for {
		frame, err := sess.ReadFrame(reader)
		if err != nil {
			return err
		}

		switch frame.Type {

		case reflexproto.FrameTypeData:
			buffer := buf.FromBytes(frame.Payload)
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
				return err
			}

		case reflexproto.FrameTypeClose:
			return nil

		default:
			continue
		}
	}
}

func (h *Handler) handleFallback(ctx context.Context, conn stat.Connection) error {
	conn.Close()
	return nil
}

func init() {
	common.Must(common.RegisterConfig(
		(*reflex.InboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.InboundConfig))
		},
	))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {

	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}
