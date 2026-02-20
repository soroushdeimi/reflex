package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"

	"github.com/google/uuid"
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
	clients  []*protocol.MemoryUser
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

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Wrap connection در bufio.Reader برای peek
	reader := bufio.NewReader(conn)

	// Peek کردن چند بایت اول
	peeked, err := reader.Peek(64) // حداقل برای magic number یا HTTP header
	if err != nil {
		return err
	}

	// چک کردن magic number (سریع‌تر)
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == reflex.ReflexMagic {
			// Magic number پیدا شد - parse کن
			return h.handleReflexMagic(reader, conn, dispatcher, ctx)
		}
	}

	// چک کردن HTTP POST-like
	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
	} //TODO Step 4

	// هیچکدوم نبود - به fallback بفرست
	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	// خواندن magic number (4 بایت)
	magic := make([]byte, 4)
	_, err := io.ReadFull(reader, magic)
	if err != nil {
		return err
	}

	// خواندن handshake packet
	var packet reflex.ClientHandshakePacket

	// خواندن بقیه
	if err := binary.Read(reader, binary.BigEndian, &packet.Handshake); err != nil {
		return errors.New("failed to read client handshake: " + err.Error())
	}
	return h.processHandshake(reader, conn, dispatcher, ctx, packet.Handshake)
}

func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	// Parse کردن HTTP POST request
	// استخراج base64 encoded data
	// decode کردن و parse کردن ClientHandshake

	// اینجا باید HTTP request رو parse کنی
	// برای سادگی، می‌تونی از یه HTTP parser استفاده کنی
	// یا خودت parse کنی

	var clientHS reflex.ClientHandshake
	// ... parse کردن از HTTP POST

	//todo Step 4

	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS reflex.ClientHandshake) error {
	// احراز هویت
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		// اگر احراز هویت ناموفق بود، به fallback برو
		return h.handleFallback(ctx, reader, conn)
	}

	// تولید کلید موقت سرور
	serverPrivateKey, serverPublicKey, err2 := reflex.GenerateKeyPair()
	if err2 != nil {
		return err2
	}

	// محاسبه کلید مشترک
	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	sessionKey, err := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))

	// ارسال پاسخ handshake (شبیه HTTP 200)
	serverHS := reflex.ServerHandshake{
		PublicKey: serverPublicKey,
		// باید این تابع رو خودت پیاده‌سازی کنی:
		PolicyGrant: h.encryptPolicyGrant(user, sessionKey), // policy grant رو رمزنگاری کن
		//PolicyGrant: []byte{}, // placeholder - باید پیاده‌سازی بشه
	}

	// ارسال پاسخ (شبیه HTTP 200)
	response := h.formatHTTPResponse(serverHS)
	_, err3 := conn.Write(response)
	if err3 != nil {
		return err3
	}

	// حالا جلسه برقرار شده، می‌تونیم داده‌ها رو پردازش کنیم
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, key []byte, user any) error {
	return nil
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	return nil
}

func (h *Handler) authenticateUser(id [16]byte) (interface{}, interface{}) {
	// تبدیل [16]byte به string UUID
	userIDStr := uuid.UUID(id).String()

	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) encryptPolicyGrant(user interface{}, key []byte) []byte {
	return nil
}

func (h *Handler) formatHTTPResponse(hs reflex.ServerHandshake) []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
}

func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	// چک کردن حداقل طول
	if len(peeked) < 5 {
		return false
	}
	// چک کردن متدها (فعلا فقط POST برای مرحله ۴)
	return string(peeked[:5]) == "POST " || string(peeked[:4]) == "GET " || string(peeked[:4]) == "PUT "
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
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
			Email:   client.Id,
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
