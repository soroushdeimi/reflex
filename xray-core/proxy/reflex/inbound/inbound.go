package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"google.golang.org/protobuf/proto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/features/routing"
)

// Config is an alias for reflex.InboundConfig
type Config = reflex.InboundConfig

type Handler struct {
	clients []*protocol.MemoryUser
	fallback *FallbackConfig
	userPolicies map[string]string // Map user ID to policy name
}

// MemoryAccount برای ذخیره اطلاعات کاربر
// باید protocol.Account interface رو implement کنه
type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

// ToProto implements protocol.Account
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Wrap connection in bufio.Reader for peek
	reader := bufio.NewReader(conn)
	
	// Peek first few bytes
	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil {
		// If we can't peek, try fallback
		if h.fallback != nil {
			return h.handleFallback(ctx, reader, conn)
		}
		return err
	}
	
	// Check for magic number (faster)
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == ReflexMagic {
			// Magic number found - handle Reflex handshake
			return h.handleReflexMagic(reader, conn, dispatcher, ctx)
		}
	}
	
	// Check for HTTP POST-like
	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
	}
	
	// Neither found - send to fallback
	return h.handleFallback(ctx, reader, conn)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

func New(ctx context.Context, config *Config) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
		userPolicies: make(map[string]string),
	}
	
	// تبدیل config به handler
	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email: client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
		// Store user policy
		if client.Policy != "" {
			handler.userPolicies[client.Id] = client.Policy
		}
	}
	
	// تنظیم fallback اگر وجود داشته باشه
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}
	
	return handler, nil
}

