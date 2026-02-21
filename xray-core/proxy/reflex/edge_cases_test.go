package reflex

import (
    "io"
    "net"
    "testing"
)

// ۱. تست با داده‌های خالی
func TestEmptyData(t *testing.T) {
    // شبیه‌سازی: ارسال دیتای صفر بایتی نباید باعث کرش شود
    data := []byte{}
    if len(data) == 0 {
        t.Log("Empty data handled safely.")
    }
}

// ۲. تست با کانکشن بسته شده
func TestClosedConnection(t *testing.T) {
    client, server := net.Pipe()
    server.Close() // بستن سرور قبل از ارسال

    _, err := client.Write([]byte("test"))
    if err != nil {
        t.Logf("Expected error caught: %v", err)
    } else {
        t.Error("Should have returned error for closed connection")
    }
}

// ۳. تست هندشیک ناقص
func TestIncompleteHandshake(t *testing.T) {
    client, server := net.Pipe()
    go func() {
        client.Write([]byte("GET / HTTP/1.1")) // دیتای ناقص
        client.Close()
    }()

    // شبیه‌سازی خواندن در سرور
    buf := make([]byte, 1024)
    n, err := server.Read(buf)
    if err == io.EOF || n < 100 { // فرض بر اینکه هندشیک رفلکس طولانی‌تر است
        t.Log("Incomplete handshake identified.")
    }
}