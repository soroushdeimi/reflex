package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"strconv"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

type Handler struct {
    clients []*protocol.MemoryUser
    fallback *FallbackConfig
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

const (
    ReflexMinHandshakeSize = 64
)

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
    // Wrap connection در bufio.Reader برای peek
    reader := bufio.NewReader(conn)
    
    // Peek کردن چند بایت اول
    peeked, err := reader.Peek(ReflexMinHandshakeSize) // حداقل برای magic number یا HTTP header
    if err != nil {
        return err
    }

    if h.isReflexMagic(peeked) {
        if len(peeked) >= 4 {
            magic := binary.BigEndian.Uint32(peeked[0:4])
            if magic == ReflexMagic {
                return h.handleReflexMagic(reader, conn, dispatcher, ctx)
            }
        }

        // Go to fallback if not magic
        return h.handleFallback(ctx, reader, conn)
    } else {
        // Go to fallback if not reflex
        return h.handleFallback(ctx, reader, conn)
    }
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
    // خواندن magic number (4 بایت)
    magic := make([]byte, 4)
    io.ReadFull(reader, magic)
    
    // خواندن handshake packet
	clientHS := &ClientHandshake{}

	if _, err := io.ReadFull(reader, clientHS.PublicKey[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(reader, clientHS.UserID[:]); err != nil {
		return err
	}

	prLen := make([]byte, 2)
	if _, err := io.ReadFull(reader, prLen); err != nil {
		return err
	}
	policyReqLen := binary.BigEndian.Uint16(prLen)
	clientHS.PolicyReq = make([]byte, policyReqLen)
	if policyReqLen > 0 {
		if _, err := io.ReadFull(reader, clientHS.PolicyReq); err != nil {
			return err
		}
	}

	if err := binary.Read(reader, binary.BigEndian, &clientHS.Timestamp); err != nil {
		return err
	}

	if _, err := io.ReadFull(reader, clientHS.Nonce[:]); err != nil {
		return err
	}
    
    return h.processHandshake(reader, conn, dispatcher, ctx, *clientHS)
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS ClientHandshake) error {
    // تولید کلید موقت سرور
    serverPrivateKey, serverPublicKey, _ := generateKeyPair()
    
    // محاسبه کلید مشترک
    sharedKey := deriveSharedKey(serverPrivateKey, clientHS.PublicKey)
    sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))
    
    // احراز هویت
    user, err := h.authenticateUser(clientHS.UserID)
    if err != nil {
        // Go to fallback if not authorized
        return h.handleFallback(ctx, reader, conn)
    }
    
    // ارسال پاسخ handshake (شبیه HTTP 200)
    serverHS := ServerHandshake{
        PublicKey: serverPublicKey,
        PolicyGrant: []byte{},
    }

	// Send HTTP response of ServerHandshake
	body, _ := json.Marshal(serverHS)
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"\r\n"

	conn.Write([]byte(response))
	conn.Write(body)
    
    // حالا جلسه برقرار شده، می‌تونیم داده‌ها رو پردازش کنیم
    return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func init() {
    common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
        return New(ctx, config.(*reflex.InboundConfig))
    }))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
    handler := &Handler{
        clients: make([]*protocol.MemoryUser, 0),
    }
    
    // تبدیل config به handler
    for _, client := range config.Clients {
        handler.clients = append(handler.clients, &protocol.MemoryUser{
            Email: client.Id,
            Account: &MemoryAccount{Id: client.Id},
        })
    }
    
    // تنظیم fallback اگر وجود داشته باشه
    if config.Fallback != nil {
        handler.fallback = &FallbackConfig{
            Dest: config.Fallback.Dest,
        }
    }
    
    return handler, nil
}