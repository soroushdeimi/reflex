package outbound

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
)

func TestFullHandshakeFlow(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// ایجاد یک کانال برای تشخیص پایان کار سرور
	done := make(chan bool)

	// Mock Server
	go func() {
		defer func() { done <- true }()

		// سرور باید کل ۶۸ بایت (۴ مجیک + ۶۴ هندشیک) را بخواند
		buf := make([]byte, 68)
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			return
		}

		// سرور پاسخ می‌دهد (۳۲ بایت کلید فرضی)
		mockResp := make([]byte, 32)
		mockResp[0] = 0x42
		serverConn.Write(mockResp)
	}()

	// تنظیم تایم‌اوت برای کل تست
	id := uuid.New()
	h := &Handler{clientId: id.String()}

	errChan := make(chan error, 1)
	var sessionKey []byte

	go func() {
		key, err := h.clientHandshake(clientConn)
		sessionKey = key
		errChan <- err
	}()

	// منتظر ماندن برای نتیجه یا تایم‌اوت
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Handshake failed: %v", err)
		}
		if len(sessionKey) != 32 {
			t.Errorf("Wrong key size: %d", len(sessionKey))
		}
		t.Log("Handshake PASS!")
	case <-time.After(5 * time.Second):
		t.Fatal("Test TIMEOUT - Possible Deadlock!")
	}
	<-done
}
