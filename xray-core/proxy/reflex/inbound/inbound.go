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
	// رد کردن ۴ بایت مجیک (چون قبلاً Peek شده)
	reader.Discard(4)

	// خواندن ۶۴ بایت دیتای هندشیک
	hsBuf := make([]byte, 64)
	if _, err := io.ReadFull(reader, hsBuf); err != nil {
		return err
	}

	// باز کردن بایت‌ها در استراکت
	var clientHS reflex.ClientHandshake
	copy(clientHS.PublicKey[:], hsBuf[0:32])
	copy(clientHS.UserID[:], hsBuf[32:48])
	clientHS.Timestamp = int64(binary.BigEndian.Uint64(hsBuf[48:56]))
	copy(clientHS.Nonce[:], hsBuf[56:64])

	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
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
	// ۱. احراز هویت
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// ۲. تولید کلید موقت سرور
	serverPrivateKey, serverPublicKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	// ۳. محاسبه کلید مشترک و Session Key
	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)

	// نکته مهم: سالت باید دقیقاً مشابه کلاینت باشد (Nonce + UserID)
	salt := append(clientHS.Nonce[:], clientHS.UserID[:]...)
	sessionKey, err := reflex.DeriveSessionKey(sharedKey, salt)
	if err != nil {
		return err
	}

	// ۴. آماده‌سازی و رمزنگاری Policy Grant
	// یک پالیسی فرضی (مثلاً "access:all")
	policyData := []byte("access:granted")
	encryptedPolicy, err := h.encryptPolicyGrant(policyData, sessionKey)
	if err != nil {
		return err
	}

	// ۵. ارسال پاسخ باینری به کلاینت (طبق انتظار Outbound)
	// فرمت: [32B ServerPubKey][2B PolicyLen][EncryptedPolicy]
	response := make([]byte, 32+2+len(encryptedPolicy))
	copy(response[0:32], serverPublicKey[:])
	binary.BigEndian.PutUint16(response[32:34], uint16(len(encryptedPolicy)))
	copy(response[34:], encryptedPolicy)

	if _, err := conn.Write(response); err != nil {
		return err
	}

	// ۶. ورود به مرحله تبادل دیتای رمز شده (Step 3)
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, key []byte, user any) error {
	return nil
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	return nil
}

func (h *Handler) authenticateUser(id [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(id).String()
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) encryptPolicyGrant(data []byte, key []byte) ([]byte, error) {
	aead, err := reflex.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// استفاده از نانس صفر برای اولین بسته (طبق توافق با کلاینت)
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, data, nil), nil
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
