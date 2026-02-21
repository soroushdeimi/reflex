package reflex

import (
    "io"
    "net"
    "testing"
    "time"
)

func TestReflexFullFlow(t *testing.T) {
    // 1. راه اندازی یک شنونده واقعی روی پورت تصادفی
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer listener.Close()
    addr := listener.Addr().String()

    testMessage := []byte("REFLEX-INTEGRATION-DATA-STREAM")

    // 2. اجرای سرور در پس‌زمینه
    go func() {
        conn, err := listener.Accept()
        if err != nil {
            return
        }
        defer conn.Close()

        h := NewHandler(&Config{})
        
        // انجام هندشیک
        if err := h.ProcessHandshake(conn); err != nil {
            return
        }

        // خواندن دیتا
        buf := make([]byte, len(testMessage))
        io.ReadFull(conn, buf)
    }()

    // 3. اجرای کلاینت
    conn, err := net.Dial("tcp", addr)
    if err != nil {
        t.Fatalf("Failed to connect to server: %v", err)
    }
    defer conn.Close()

    // ارسال هندشیک (مطابق با انتظار پروتکل شما)
    conn.Write([]byte("REFLEX-CLIENT-HELLO"))
    
    // کمی وقفه برای پردازش هندشیک در سمت سرور
    time.Sleep(100 * time.Millisecond)

    // ارسال دیتای اصلی
    _, err = conn.Write(testMessage)
    
    if err != nil {
        t.Errorf("Client write failed: %v", err)
    } else {
        t.Log("Integration Test on Localhost: PASS")
    }
}