# 📡 پروژه Reflex - نمای کلی

یک پروتکل پراکسی هوشمند برای **Xray-Core** که ترافیک پراکسی رو غیرقابل تشخیص می‌کنه.

## چی بلد می‌کنه؟

✅ **رمزنگاری قوی**: ChaCha20-Poly1305
✅ **احراز هویت ایمن**: X25519 ECDH
✅ **مخفی‌سازی ترافیک**: Traffic Morphing (مثل YouTube, Zoom, HTTP/2)
✅ **ساختار فریم‌پایه**: پروتکل منظم و انعطاف‌پذیر
✅ **Fallback وب**: به نظر سرور عادی می‌آید

---

## شروع سریع (5 دقیقه)

### ۱. نیازمندی‌ها
```bash
# Go 1.18+
go version

# Git
git --version
```

### ۲. بیلد
```bash
cd xray-core
go build -o xray ./main/
```

### ۳. تست
```bash
# درایو اول (echo server)
go run echo-server.go

# درایو دوم (سرور)
./xray-core/xray -c reflex-server-test.json

# درایو سوم (کلاینت)
./xray-core/xray -c reflex-client-test.json

# درایو چهارم (مرورگر)
# Firefox: SOCKS5 = 127.0.0.1:10002
# Navigate to: http://127.0.0.1:9996
```

### ۴. تأیید
- [ ] Firefox وصل شد ✅
- [ ] Terminal 1: `New connection from 127.0.0.1:XXXXX` دید ✅
- [ ] بسته‌ها رمزنگاری شدند ✅

---

## مراحل پیاده‌سازی

| مرحله | توضیح | کد |
|------|-------|-----|
| **1** | ساختار اولیه | `xray-core/proxy/reflex/` |
| **2** | احراز هویت & Handshake | `encoding/handshake.go` |
| **3** | رمزنگاری & فریم‌ها | `encoding/frame.go` |
| **4** | Fallback | `inbound/inbound.go` |
| **5** | Traffic Morphing | `encoding/morphing.go` |

---

## پروفایل‌های Morphing

```json
{
  "clients": [
    {
      "id": "user-uuid-1",
      "policy": "youtube"      // ← بزرگ = دانلود، استریم
    },
    {
      "id": "user-uuid-2",
      "policy": "zoom"         // ← کوچک = تماس، صدا
    },
    {
      "id": "user-uuid-3",
      "policy": "http2-api"    // ← مختلط = مرور، API (پیش‌فرض)
    }
  ]
}
```

---

## سوالات متداول

**Q: خطای `proto.Message`؟**
A: فایل‌های `.pb.go` را generate کنید: `protoc xray-core/proxy/reflex/*.proto`

**Q: Morphing کار نمی‌کنه؟**
A: Wireshark چک کنید: `tcp.dstport == 8555` - بسته‌ها مختلط باید باشند.

**Q: نمی‌تونم وصل شم؟**
A: UUID کلاینت و سرور یکی هست؟ Log فایل‌ها چک کنید.

---

## مراجع

📘 **جزئیات پیاده‌سازی**: [فایل مراحل](docs/STEPS_FA.md)
🚀 **دستورات اجرا**: [فایل اجرا](docs/RUN_GUIDE_FA.md)
🔐 **پروتکل**: [مشخصات](docs/protocol.md)

---

**موفق باشید!** 🎯
