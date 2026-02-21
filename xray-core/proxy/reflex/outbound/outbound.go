package outbound

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	serverAddress string
	serverPort    net.Port
	clientId      string
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// ۱. اتصال به سرور محمد
	destination := net.TCPDestination(net.ParseAddress(h.serverAddress), h.serverPort)
	conn, err := dialer.Dial(ctx, destination)
	if err != nil {
		return fmt.Errorf("failed to dial reflex server %s:%d: %w", h.serverAddress, h.serverPort, err)
	}
	defer conn.Close()

	// ۲. انجام هندشیک و دریافت Session Key
	sessionKey, err := h.clientHandshake(conn)
	if err != nil {
		return fmt.Errorf("reflex handshake failed: %w", err)
	}

	// ۳. ساخت Cipher
	aead, err := reflex.NewCipher(sessionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// ۴. ارسال آدرس مقصد (Target Address) به سرور
	// استخراج مقصد از درخواست (مثلاً www.google.com:80)
	target, ok := proxy.TargetFromContext(ctx)
	if !ok {
		return errors.New("failed to get target destination from context")
	}

	// رمزنگاری آدرس مقصد با نانس صفر
	targetAddrRaw := target.String()
	nonce := make([]byte, aead.NonceSize()) // نانس شروع (۰)

	encryptedAddr := aead.Seal(nil, nonce, []byte(targetAddrRaw), nil)

	// ارسال فریم آدرس: [2B Length][Encrypted Address]
	addrHeader := make([]byte, 2)
	binary.BigEndian.PutUint16(addrHeader, uint16(len(encryptedAddr)))
	if _, err := conn.Write(addrHeader); err != nil {
		return err
	}
	if _, err := conn.Write(encryptedAddr); err != nil {
		return err
	}

	// ۵. افزایش نانس (حالا نانس ۱ است) برای شروع تبادل دیتای اصلی
	h.increment(nonce)

	// ۶. مدیریت مسیرهای آپلود و دانلود
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)

	// کپی نانس برای استفاده در گوروتین‌ها (برای جلوگیری از Race Condition)
	outNonce := make([]byte, len(nonce))
	copy(outNonce, nonce)
	inNonce := make([]byte, len(nonce))
	copy(inNonce, nonce)

	go func() {
		errs <- h.encryptWrite(link.Reader, conn, aead, outNonce)
	}()

	go func() {
		errs <- h.readDecrypt(conn, link.Writer, aead, inNonce)
	}()

	select {
	case err := <-errs:
		if err != nil && err != io.EOF {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (h *Handler) encryptWrite(reader buf.Reader, writer io.Writer, aead cipher.AEAD, nonce []byte) error {
	nonce := make([]byte, aead.NonceSize())
	for {
		b, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}

		for _, buffer := range b {
			if buffer.IsEmpty() {
				continue
			}

			rawPayload := buffer.Bytes()
			encrypted := aead.Seal(nil, nonce, rawPayload, nil)

			frameHeader := make([]byte, 2)
			binary.BigEndian.PutUint16(frameHeader, uint16(len(encrypted)))

			if _, err := writer.Write(frameHeader); err != nil {
				return err
			}
			if _, err := writer.Write(encrypted); err != nil {
				return err
			}

			increment(nonce)
			buffer.Release()
		}
	}
}

func (h *Handler) readDecrypt(reader io.Reader, writer buf.Writer, aead cipher.AEAD, nonce []byte) error {
	nonce := make([]byte, aead.NonceSize())
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
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return err
		}

		increment(nonce)
	}
}

func (h *Handler) clientHandshake(conn net.Conn) ([]byte, error) {
	privKey, pubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	parsedUUID, err := uuid.ParseString(h.clientId)
	if err != nil {
		return nil, err
	}
	uid := [16]byte(parsedUUID)

	// ۱. آماده‌سازی پکت (۴ بایت مجیک + ۶۴ بایت دیتای هندشیک)
	// کل حجم پکت ارسالی: ۶۸ بایت
	fullPayload := make([]byte, 4+64)
	binary.BigEndian.PutUint32(fullPayload[:4], reflex.ReflexMagic)

	// کپی کردن فیلدها با آفست‌های دقیق
	copy(fullPayload[4:36], pubKey[:]) // ۳۲ بایت کلید عمومی
	copy(fullPayload[36:52], uid[:])   // ۱۶ بایت UUID

	timestamp := time.Now().Unix()
	binary.BigEndian.PutUint64(fullPayload[52:60], uint64(timestamp)) // ۸ بایت زمان

	// تولید نانس ۸ بایتی (حتماً ۸ بایت باشد)
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	copy(fullPayload[60:68], nonce) // ۸ بایت نانس

	// ۲. ارسال پکت به سرور
	if _, err := conn.Write(fullPayload); err != nil {
		return nil, err
	}

	// ۳. دریافت پاسخ سرور (۳۲ بایت کلید عمومی سرور)
	respPubKey := make([]byte, 32)
	if _, err := io.ReadFull(conn, respPubKey); err != nil {
		return nil, err
	}
	var sPubKey [32]byte
	copy(sPubKey[:], respPubKey)

	// ۴. استخراج کلید مشترک و کلید نشست (Session Key)
	shared := reflex.DeriveSharedKey(privKey, sPubKey)

	// محاسبه سالت: دقیقاً ۲۴ بایت (۸ بایت نانس + ۱۶ بایت یوزر آیدی)
	salt := make([]byte, 0, 24)
	salt = append(salt, nonce...)
	salt = append(salt, uid[:]...)

	sessionKey, err := reflex.DeriveSessionKey(shared, salt)
	if err != nil {
		return nil, err
	}

	// چاپ دیباگ برای مقایسه با سرور (این بخش را بعد از تست پاک کن)
	fmt.Printf("DEBUG: SessionKey (first 4 bytes): %x\n", sessionKey[:4])
	fmt.Printf("DEBUG: Salt used (%d bytes): %x\n", len(salt), salt)

	// ۵. دریافت Policy Grant (بخش رمزنگاری شده)
	// الف) خواندن ۲ بایت طول
	policyLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, policyLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read policy length: %w", err)
	}
	policyLen := binary.BigEndian.Uint16(policyLenBuf)

	// ب) خواندن دیتای رمز شده
	encryptedPolicy := make([]byte, policyLen)
	if _, err := io.ReadFull(conn, encryptedPolicy); err != nil {
		return nil, fmt.Errorf("failed to read encrypted policy: %w", err)
	}

	// ج) باز کردن رمز پالیسی با نانس صفر
	policyAead, err := reflex.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	pNonce := make([]byte, policyAead.NonceSize()) // نانس تماماً صفر

	decryptedPolicy, err := policyAead.Open(nil, pNonce, encryptedPolicy, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt policy grant (Key Mismatch)")
	}

	fmt.Printf("Policy Grant received and decrypted: %d bytes\n", len(decryptedPolicy))

	return sessionKey, nil
}

func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	if config.Address == "" {
		return nil, errors.New("address is required in reflex outbound config")
	}
	if config.Id == "" {
		return nil, errors.New("id (uuid) is required in reflex outbound config")
	}

	return &Handler{
		serverAddress: config.Address,
		serverPort:    net.Port(config.Port),
		clientId:      config.Id,
	}, nil
}

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func init() {
	common.Must(common.RegisterConfig(
		(*reflex.OutboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.OutboundConfig))
		},
	))
}

func (h *Handler) increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
