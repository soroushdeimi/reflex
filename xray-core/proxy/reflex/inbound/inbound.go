// Package inbound implements the Reflex inbound handler.
// This is a stub; replace with full implementation per step docs.
package inbound

import (
	"bufio"
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

// MemoryAccount is the in-memory Reflex user account.
type MemoryAccount struct {
	ID     string
	Policy string
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	other, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID == other.ID
}

// ToProto implements protocol.Account.
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.ID}
}

// Handler is the Reflex inbound handler.
type Handler struct {
	clients       []*protocol.MemoryUser
	fallback      *reflex.Fallback
	seenNonces    map[[16]byte]int64
	nonceLifetime time.Duration
	nonceMu       sync.Mutex
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network != net.Network_TCP {
		return errors.New("reflex inbound supports tcp only")
	}

	reader := bufio.NewReader(conn)
	peeked, err := peekForDetection(reader, 5)
	if err != nil && err.Error() != "EOF" {
		return err
	}
	if len(peeked) == 0 {
		return nil
	}

	if h.isReflexMagic(peeked) {
		return h.handleReflexMagic(ctx, reader, conn, dispatcher)
	}
	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(ctx, reader, conn, dispatcher)
	}
	return h.handleFallback(ctx, reader, conn)
}

// New creates a new Reflex inbound handler from config.
func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	_ = ctx
	h := &Handler{
		fallback:      config.GetFallback(),
		seenNonces:    make(map[[16]byte]int64),
		nonceLifetime: defaultNonceLifetime,
	}
	for _, c := range config.GetClients() {
		h.clients = append(h.clients, &protocol.MemoryUser{
			Email: c.GetId(),
			Account: &MemoryAccount{
				ID:     c.GetId(),
				Policy: c.GetPolicy(),
			},
		})
	}
	return h, nil
}
