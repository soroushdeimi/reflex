package reflex

import (
    "sync"
    "testing"
)

// شبیه‌سازی ساختار کش برای جلوگیری از Replay
type ReplayProtector struct {
    cache sync.Map
}

func (r *ReplayProtector) ProcessFrame(id string) bool {
    // اگر ID پکت قبلاً دیده شده باشد، رد کن
    _, loaded := r.cache.LoadOrStore(id, true)
    return !loaded // اگر جدید باشد true، اگر تکراری باشد false
}

func TestReplayProtection(t *testing.T) {
    protector := &ReplayProtector{}
    packetID := "unique-packet-signature-123"

    // ارسال اول - باید موفق باشد
    if !protector.ProcessFrame(packetID) {
        t.Fatal("ارسال اول باید موفقیت‌آمیز باشد")
    }

    // ارسال دوباره - باید رد (Reject) شود
    if protector.ProcessFrame(packetID) {
        t.Fatal("حمله Replay شناسایی نشد! پکت تکراری نباید پذیرفته شود")
    } else {
        t.Log("تست Anti-Replay: موفق (پکت تکراری با موفقیت مسدود شد)")
    }
}