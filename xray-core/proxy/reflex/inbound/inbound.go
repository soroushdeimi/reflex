package inbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"

	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"

	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	"time"

	"golang.org/x/crypto/chacha20poly1305"
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

// This func needs to be completed in step 4.
func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	if len(peeked) < 4 {
		return false
	}
	return string(peeked[:4]) == "POST"
}

// تشخیص فالبک
func (h *Handler) handleFallback(
	ctx context.Context,
	reader *bufio.Reader,
	conn net.Conn,
) error {

	resp := "HTTP/1.1 403 Forbidden\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"

	_, _ = conn.Write([]byte(resp))
	_ = conn.Close()
	return nil
}

// proccess (Second step- handshake)
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Wrap connection در bufio.Reader برای peek
	reader := bufio.NewReader(conn)

	// Peek کردن چند بایت ا
	peeked, err := reader.Peek(64) // حداقل برای magic number یا HTTP header
	if err != nil {
		return err
	}

	// چک کردن magic number (سریع‌تر)
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == ReflexMagic {
			// Magic number پیدا شد - parse کن
			return h.handleReflexMagic(reader, conn, dispatcher, ctx)
		}
	}

	// چک کردن HTTP POST-like
	// باید این تابع رو خودت پیاده‌سازی کنی (در step4 توضیح داده شده)

	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
	}

	// هیچکدوم نبود - به fallback بفرست
	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	// خواندن magic number (4 بایت)
	magic := make([]byte, 4)
	io.ReadFull(reader, magic)

	// خواندن handshake packet
	var packet ClientHandshakePacket
	// ... parse کردن بقیه بسته

	return h.processHandshake(reader, conn, dispatcher, ctx, packet.Handshake)
}

func (h *Handler) handleReflexHTTP(
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	ctx context.Context,
) error {

	// 1️⃣ Parse HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// 2️⃣ فقط POST مجاز است
	if req.Method != http.MethodPost {
		return h.handleFallback(ctx, reader, conn)
	}

	// 3️⃣ خواندن body
	body, err := io.ReadAll(io.LimitReader(req.Body, 8*1024))
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	_ = req.Body.Close()

	if len(body) == 0 {
		return h.handleFallback(ctx, reader, conn)
	}

	// 4️⃣ decode base64
	rawHandshake, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(body)))
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// 5️⃣ parse ClientHandshake از binary
	var clientHS ClientHandshake
	if err := clientHS.UnmarshalBinary(rawHandshake); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// 6️⃣ تحویل به handshake اصلی
	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func generateKeyPair() (privateKey [32]byte, publicKey [32]byte) {
	// 1. Random private key
	if _, err := rand.Read(privateKey[:]); err != nil {
		panic(err)
	}

	// generate public key using x25519
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS ClientHandshake) error {

	// تولید کلید موقت سرور

	serverPrivateKey, serverPublicKey := generateKeyPair()

	// محاسبه کلید مشترک
	sharedKey := deriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))

	// احراز هویت
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		// اگر احراز هویت ناموفق بود، به fallback برو
		return h.handleFallback(ctx, reader, conn)
	}

	// ارسال پاسخ handshake (شبیه HTTP 200)
	serverHS := ServerHandshake{
		PublicKey:   serverPublicKey,
		PolicyGrant: h.encryptPolicyGrant(user, sessionKey),
	}

	_ = serverHS

	//Send response
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
	conn.Write(response)

	// Now, handle session
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionKey []byte,
	user *protocol.MemoryUser,
) error {
	// TODO: پیاده‌سازی session واقعی (AEAD + relay)
	return nil
}

func (h *Handler) encryptPolicyGrant(user *protocol.MemoryUser, sessionKey []byte) []byte {
	// policy
	policy := map[string]any{
		"level":  user.Level,
		"expire": time.Now().Add(10 * time.Minute).Unix(),
	}

	plain, err := json.Marshal(policy)
	if err != nil {
		return nil
	}

	// AEAD
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil
	}

	// random nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}

	// encrypt
	ciphertext := aead.Seal(nil, nonce, plain, nil)

	// nonce || ciphertext
	return append(nonce, ciphertext...)
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
