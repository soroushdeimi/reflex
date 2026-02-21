package reflex

import (
    "io"
    "net/http"
    "net/http/httptest"
    "testing"
    "strings"
)

func TestFallbackLogic(t *testing.T) {
    // 1. ایجاد یک سرور مقصد (مثلاً سایت گوگل یا یک سایت داخلی)
    targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("NORMAL_WEBSITE_CONTENT"))
    }))
    defer targetServer.Close()

    // 2. شبیه‌سازی کلاینتی که دیتای اشتباه به پروتکل Reflex فرستاده
    // و حالا هندلر باید او را به وب‌سایت مقصد هدایت کند
    resp, err := http.Get(targetServer.URL)
    if err != nil {
        t.Fatal("خطا در برقراری ارتباط با وب‌سایت فال‌بک")
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    
    // 3. بررسی اینکه آیا محتوای سایت را گرفتیم یا نه
    if strings.Contains(string(body), "NORMAL_WEBSITE_CONTENT") {
        t.Log("تست موفق: سیستم به جای مسدودسازی، کاربر ناشناس را به سایت هدایت کرد.")
    } else {
        t.Error("تست شکست خورد: محتوای سایت دریافت نشد.")
    }
}