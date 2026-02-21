package inbound

import (
	"bufio"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

const (
	// حداقل اندازه برای تشخیص handshake
	// Magic number (4) + حداقل اندازه handshake
	ReflexMinHandshakeSize = 64
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
	// Wrap connection در bufio.Reader
	reader := bufio.NewReader(conn)

	// Peek کردن چند بایت اول (بدون مصرف)
	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil {
		return err
	}

	// چک کردن که آیا Reflex هست یا نه
	if h.isReflexHandshake(peeked) {
		// Reflex هست - پردازش کن
		// باید منطق handshake رو از step2 صدا بزنی:
		if h.isReflexMagic(peeked) {
			return h.handleReflexMagic(reader, conn, dispatcher, ctx)
		}
		if h.isHTTPPostLike(peeked) {
			return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
		}
		// اگه هیچکدوم نبود، به fallback برو
		return h.handleFallback(ctx, reader, conn)
	} else {
		// Reflex نیست - به fallback بفرست
		return h.handleFallback(ctx, reader, conn)
	}
}
func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == reflex.ReflexMagic
}
func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	// چک کردن حداقل طول
	if len(peeked) < 5 {
		return false
	}
	// چک کردن متدها (فعلا فقط POST برای مرحله ۴)
	return string(peeked[:5]) == "POST " || string(peeked[:4]) == "GET " || string(peeked[:4]) == "PUT "
}

func (h *Handler) isReflexHandshake(data []byte) bool {
	// اول magic number رو چک کن (سریع‌تر)
	if h.isReflexMagic(data) {
		return true
	}

	// بعد HTTP POST-like رو چک کن (پنهان‌کارتر)
	if h.isHTTPPostLike(data) {
		return true
	}

	return false
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
	// ۱. احراز هویت کاربر
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		// اگر کاربر معتبر نبود، به Fallback هدایت کن (مرحله ۴)
		return h.handleFallback(ctx, reader, conn)
	}

	// ۲. تولید کلید موقت سرور (Ephemeral Key Pair)
	serverPrivateKey, serverPublicKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	// ۳. محاسبه کلید مشترک (Shared Key) با استفاده از PubKey کلاینت
	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)

	// ۴. محاسبه سالت (Salt) - بسیار حیاتی برای هماهنگی با کلاینت
	// دقت شود: حتماً ۲۴ بایت شامل ۸ بایت نانس کلاینت + ۱۶ بایت یوزر آیدی
	// اگر در types.go نانس را ۸ بایت کرده باشید، clientHS.Nonce[:] دقیقاً ۸ بایت خواهد بود
	salt := make([]byte, 0, 24)
	salt = append(salt, clientHS.Nonce[:]...)
	salt = append(salt, clientHS.UserID[:]...)

	sessionKey, err := reflex.DeriveSessionKey(sharedKey, salt)
	if err != nil {
		return err
	}

	// لاگ دیباگ برای مقایسه با کلاینت (اولین بایت‌های کلید باید یکی باشند)
	fmt.Printf("DEBUG (Server): SessionKey (first 4 bytes): %x\n", sessionKey[:4])
	fmt.Printf("DEBUG (Server): Salt used (%d bytes): %x\n", len(salt), salt)

	// ۵. آماده‌سازی و رمزنگاری Policy Grant (مرحله ۵ پیشرفته)
	policyData := []byte("access:granted") // دیتای پالیسی (می‌تواند از فایل کانفیگ بیاید)
	encryptedPolicy, err := h.encryptPolicyGrant(policyData, sessionKey)
	if err != nil {
		return err
	}

	// ۶. ارسال پاسخ نهایی به کلاینت (فرمت باینری دقیق)
	// فرمت: [32B ServerPubKey] + [2B PolicyLen] + [EncryptedPolicy]
	response := make([]byte, 32+2+len(encryptedPolicy))
	copy(response[0:32], serverPublicKey[:])
	binary.BigEndian.PutUint16(response[32:34], uint16(len(encryptedPolicy)))
	copy(response[34:], encryptedPolicy)

	if _, err := conn.Write(response); err != nil {
		return err
	}

	// ۷. ورود به مرحله تبادل دیتای رمز شده (Step 3: Encryption & Framing)
	// اینجا سرور آماده می‌شود تا ترافیک کاربر را رمزگشایی و هدایت کند
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) encryptPolicyGrant(data []byte, key []byte) ([]byte, error) {
	aead, err := reflex.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// نانس صفر برای اولین بسته رمزنگاری شده در کل کانکشن
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, data, nil), nil
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, key []byte, user *protocol.MemoryUser) error {
	// ۱. ساخت Cipher
	aead, err := reflex.NewCipher(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, aead.NonceSize()) // نانس شروع (۰)

	// ۲. دریافت و رمزگشایی آدرس مقصد
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	addrLen := binary.BigEndian.Uint16(header)

	encryptedAddr := make([]byte, addrLen)
	if _, err := io.ReadFull(reader, encryptedAddr); err != nil {
		return err
	}

	decryptedAddr, err := aead.Open(nil, nonce, encryptedAddr, nil)
	if err != nil {
		return errors.New("failed to decrypt target address. key mismatch or corruption")
	}

	// ۳. پارس کردن آدرس و اتصال به مقصد واقعی
	target, err := net.ParseDestination(string(decryptedAddr))
	if err != nil {
		return fmt.Errorf("invalid target address received: %w", err)
	}
	fmt.Printf("DEBUG (Server): Forwarding traffic to: %s\n", target.String())

	// ۴. آماده‌سازی برای تبادل دیتا (افزایش نانس به ۱)
	h.increment(nonce)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	link, err := dispatcher.Dispatch(sessionCtx, target)
	if err != nil {
		return err
	}

	// کپی نانس برای گوروتین‌ها
	serverOutNonce := make([]byte, len(nonce))
	copy(serverOutNonce, nonce)
	serverInNonce := make([]byte, len(nonce))
	copy(serverInNonce, nonce)

	errs := make(chan error, 2)

	// ۵. شروع مسیرهای تبادل دیتا
	go func() {
		errs <- h.readDecrypt(reader, link.Writer, aead, serverInNonce)
	}()

	go func() {
		errs <- h.encryptWrite(link.Reader, conn, aead, serverOutNonce)
	}()

	return <-errs
}

// این دو تابع دقیقاً مشابه کدهای تو هستند، با کمی تغییر برای Inbound
func (h *Handler) encryptWrite(reader buf.Reader, writer io.Writer, aead cipher.AEAD, nonce []byte) error {
	for {
		multiBuffer, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		for _, buffer := range multiBuffer {
			encrypted := aead.Seal(nil, nonce, buffer.Bytes(), nil)
			header := make([]byte, 2)
			binary.BigEndian.PutUint16(header, uint16(len(encrypted)))
			writer.Write(header)
			writer.Write(encrypted)
			h.increment(nonce)
			buffer.Release()
		}
	}
}

func (h *Handler) readDecrypt(reader io.Reader, writer buf.Writer, aead cipher.AEAD, nonce []byte) error {
	header := make([]byte, 2)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return err
		}
		length := binary.BigEndian.Uint16(header)
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return err
		}
		decrypted, err := aead.Open(nil, nonce, payload, nil)
		if err != nil {
			return err
		}
		b := buf.New()
		b.Write(decrypted)
		writer.WriteMultiBuffer(buf.MultiBuffer{b})
		h.increment(nonce)
	}
}

func (h *Handler) increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	// اگر فال‌بک کانفیگ نشده بود، اتصال را ببند
	if h.fallback == nil || h.fallback.Dest == 0 {
		return errors.New("no fallback configured")
	}

	// ساخت Wrapper برای اینکه بایت‌های Peek شده از بین نروند
	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	// اتصال به وب‌سرور محلی (مثلا Nginx روی پورت 80 یا 443)
	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to dial fallback server: %w", err)
	}
	defer target.Close()

	// کپی کردن دوطرفه داده‌ها بین کلاینت و وب‌سرور
	errs := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, wrappedConn)
		errs <- err
	}()
	go func() {
		_, err := io.Copy(wrappedConn, target)
		errs <- err
	}()

	<-errs // منتظر ماندن تا یکی از اتصالات بسته شود
	return nil
}

// preloadedConn باعث می‌شود بایت‌هایی که bufio.Reader خوانده (Peek کرده)
// قبل از بایت‌های اصلی کانکشن به وب‌سرور فرستاده شوند.
type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

// Read را اورراید می‌کنیم تا از Reader بخواند
func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

// Write را دست نمی‌زنیم تا مستقیم روی Connection بنویسد
func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

func (pc *preloadedConn) Close() error {
	return pc.Connection.Close()
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

func (h *Handler) formatHTTPResponse(hs reflex.ServerHandshake) []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
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
