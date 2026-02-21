# پروژه Reflex - پیاده‌سازی پروتکل Reflex در Xray-Core

## شماره دانشجویی
402170121 - 402100559

## توضیحات

این پروژه پیاده‌سازی پروتکل Reflex در Xray-Core است. Reflex یک پروتکل پراکسی پیشرفته است که برای مقاومت در برابر DPI (Deep Packet Inspection) و شناسایی ترافیک طراحی شده است.

### ویژگی‌های پیاده‌سازی شده

#### Step 1 - ساختار اولیه
- ✅ ساختار پکیج `reflex` در Xray-Core
- ✅ تعریف `config.proto` و تولید `config.pb.go`
- ✅ Handler اولیه برای inbound و outbound
- ✅ ثبت پروتکل در Xray-Core

#### Step 2 - Handshake & Authentication
- ✅ تبادل کلید X25519 برای key exchange
- ✅ استخراج کلید جلسه با HKDF
- ✅ احراز هویت با UUID و HMAC-SHA256
- ✅ محافظت در برابر replay با timestamp validation
- ✅ مدیریت خطا و validation

#### Step 3 - Encryption & Frame Processing
- ✅ ساختار Frame با header (length + type)
- ✅ رمزنگاری AES-256-GCM برای payload
- ✅ خواندن/نوشتن frame با nonce management
- ✅ پشتیبانی از انواع frame (Data, Padding, Timing, Close)

#### Step 4 - Traffic Morphing & Fallback Prep
- ✅ پیاده‌سازی Traffic Morphing (padding/randomization)
- ✅ Validation اندازه بسته‌ها
- ✅ Hooks برای fallback server (آماده برای پیاده‌سازی کامل)
- ✅ تشخیص پروتکل با magic number

### ساختار پروژه

```
reflex/
├── xray-core/
│   ├── proxy/
│   │   └── reflex/
│   │       ├── inbound/
│   │       │   └── inbound.go
│   │       ├── outbound/
│   │       │   └── outbound.go
│   │       ├── handshake.go      # Handshake logic
│   │       ├── auth.go           # Authentication
│   │       ├── session.go        # Encryption session
│   │       ├── frame.go          # Frame structure
│   │       ├── morphing.go       # Traffic morphing
│   │       ├── fallback.go       # Fallback detection
│   │       └── config.proto      # Protobuf config
│   ├── infra/conf/
│   │   └── reflex.go             # JSON config parser
│   └── tests/
│       └── reflex/               # Test files
│           ├── handshake_test.go
│           ├── session_test.go
│           ├── auth_test.go
│           ├── morphing_test.go
│           ├── integration_test.go
│           └── inbound_test.go
├── config.example.json           # مثال پیکربندی
├── README.md                     # این فایل
└── SUBMISSION.md                 # توضیح کارها
```

## نحوه اجرا

### ساخت پروژه

```bash
cd xray-core
go build -o xray ./main
```

### پیکربندی سرور

فایل `config.server.json` را با محتوای زیر بسازید:

```json
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 1080,
      "protocol": "reflex",
      "settings": {
        "clients": [
          {
            "id": "00000000-0000-0000-0000-000000000000"
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
```

### اجرای سرور

```bash
./xray -config config.server.json
```

### پیکربندی کلاینت

فایل `config.client.json` را با محتوای زیر بسازید:

```json
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 10808,
      "protocol": "socks",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "reflex",
      "settings": {
        "address": "your-server-ip",
        "port": 1080,
        "id": "00000000-0000-0000-0000-000000000000"
      }
    }
  ]
}
```

### اجرای کلاینت

```bash
./xray -config config.client.json
```

## تست‌ها

### اجرای همه تست‌ها

```bash
cd xray-core
go test ./tests/reflex/... -v
```

### اجرای با coverage

```bash
go test ./tests/reflex/... -cover
go test ./tests/reflex/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### اجرای با race detection

```bash
go test ./tests/reflex/... -race
```

### تست‌های موجود

- **handshake_test.go**: تست‌های handshake (11 تست)
- **session_test.go**: تست‌های encryption/decryption (12 تست)
- **auth_test.go**: تست‌های authentication (6 تست)
- **morphing_test.go**: تست‌های traffic morphing (7 تست)
- **integration_test.go**: تست‌های end-to-end (3 تست)
- **inbound_test.go**: تست‌های inbound handler (5 تست)

**مجموع: 44 تست**

## مشکلات و راه‌حل‌ها

### مشکل 1: Type Assertion در Tests
**مشکل**: در تست‌های inbound، نیاز به type assertion برای تبدیل `proxy.Inbound` به `*Handler` بود.

**راه‌حل**: استفاده از type assertion در تابع `createTestHandler()`:
```go
return handler.(*Handler), nil
```

### مشکل 2: Validation Packet Size
**مشکل**: ابتدا validation روی encrypted payload size انجام می‌شد که باعث reject شدن بسته‌های بزرگ می‌شد.

**راه‌حل**: انتقال validation به بعد از decryption تا روی decrypted payload size انجام شود.

### مشکل 3: Test Handler Valid Handshake
**مشکل**: تست بعد از handshake hang می‌کرد چون handler منتظر frame می‌ماند.

**راه‌حل**: ارسال `Close` frame بعد از handshake برای terminate کردن connection.

### مشکل 4: Import Conflicts
**مشکل**: در تست‌های inbound، conflict بین `net` standard library و `xray-core/common/net`.

**راه‌حل**: استفاده از alias برای Xray-Core net package:
```go
xnet "github.com/xtls/xray-core/common/net"
```

## نکات فنی

### Handshake Flow
1. Client generates X25519 key pair
2. Client creates handshake with UUID, timestamp, nonce
3. Client computes HMAC-SHA256 over handshake data
4. Server validates timestamp (5-minute window)
5. Server authenticates user by UUID
6. Server verifies client HMAC
7. Server generates key pair and sends response
8. Both sides derive shared key and session key

### Encryption
- استفاده از AES-256-GCM برای encryption
- Nonce management با counter (separate برای read/write)
- Frame format: `[Length:2][Type:1][EncryptedPayload]`

### Traffic Morphing
- Padding بسته‌های کوچک به MinSize (default: 64 bytes)
- Randomization اندازه بسته‌ها بین MinSize و MaxSize
- Validation اندازه بسته‌ها برای drop کردن suspicious packets

## مراجع

- [Xray-Core Documentation](https://xtls.github.io/)
- [Protocol Documentation](docs/protocol.md)
- [Step-by-Step Implementation](docs/)

## مجوز

این پروژه بخشی از پروژه Xray-Core است و تحت مجوز MPL 2.0 منتشر می‌شود.
