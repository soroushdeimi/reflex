package reflex

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// نام تابع حتما باید با Test شروع شود
func TestHandshake(t *testing.T) {
	// ۱. تنظیم کانفیگ (مطابق با تعریف InboundConfig در فایل config.pb.go)
	testConfig := &InboundConfig{
		Clients: []*User{
			{Id: "test-uuid", Policy: "default"},
		},
	}

	// ۲. ساخت هندلر (نام تابع NewHandler را با کد خودتان چک کنید)
	handler := NewHandler(testConfig)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// ۳. کلاینت شبیه‌ساز
	go func() {
		// ارسال Magic Number: REFX
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, ReflexMagic)
		clientConn.Write(magic)

		// ارسال پدینگ برای رسیدن به ۶۴ بایت
		padding := make([]byte, 60)
		clientConn.Write(padding)
	}()

	// ۴. اجرای متد اصلی برای تست
	serverConn.SetDeadline(time.Now().Add(time.Second * 5))
	err := handler.processHandshake(serverConn)

	if err != nil {
		t.Fatalf("Handshake Failed: %v", err)
	}
}
