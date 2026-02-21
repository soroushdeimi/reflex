package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	stdnet "net"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/crypto"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

const ReflexMinPeekSize = 64

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type FallbackConfig struct {
	Dest uint32
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
	return &reflex.Account{
		Id: a.Id,
	}
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

	peeked, err := reader.Peek(ReflexMinPeekSize)
	if err != nil && err != io.EOF {
		return err
	}

	if h.isReflexHandshake(peeked) {
		session, user, err := crypto.ServerHandshake(reader, conn, h.clients)
		if err != nil {
			return h.handleFallback(ctx, reader, conn)
		}

		// بعداً Step 3 full tunnel اینجا اجرا میشه
		_ = session
		_ = user

		return nil
	}

	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) isReflexHandshake(data []byte) bool {
	if h.isReflexMagic(data) {
		return true
	}
	if h.isHTTPPostLike(data) {
		return true
	}
	return false
}

func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[:4])
	return magic == crypto.ReflexMagic
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[:4]) == "POST"
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errors.New("no fallback configured")
	}

	target, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return err
	}
	defer target.Close()

	wrapped := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	go io.Copy(target, wrapped)
	io.Copy(wrapped, target)

	return nil
}

type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (p *preloadedConn) Read(b []byte) (int, error) {
	return p.Reader.Read(b)
}

func (p *preloadedConn) Write(b []byte) (int, error) {
	return p.Connection.Write(b)
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
