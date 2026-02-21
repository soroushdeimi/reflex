# توضیح کارهای انجام شده - پروژه Reflex

## خلاصه

این پروژه پیاده‌سازی کامل پروتکل Reflex در Xray-Core است که شامل مراحل 1 تا 5 از مستندات می‌شود. پروتکل Reflex برای مقاومت در برابر DPI و شناسایی ترافیک طراحی شده است.

## کارهای انجام شده

### Step 1: ساختار اولیه ✅

- ساختار پکیج `reflex` در `xray-core/proxy/reflex/`
- تعریف `config.proto` با messages: `User`, `Account`, `InboundConfig`, `OutboundConfig`, `Fallback`
- تولید `config.pb.go` با `protoc`
- پیاده‌سازی `Handler` اولیه برای inbound و outbound
- ثبت پروتکل در `infra/conf/reflex.go` و `main/distro/all/all.go`
- پیاده‌سازی `MemoryAccount` برای interface `protocol.Account`

### Step 2: Handshake & Authentication ✅

- پیاده‌سازی handshake با X25519 key exchange
- ساختار `ClientHandshake` و `ServerHandshake`
- Encoding/Decoding handshake packets
- استخراج کلید جلسه با HKDF
- احراز هویت با UUID و HMAC-SHA256
- محافظت در برابر replay با timestamp validation (5-minute window)
- مدیریت خطا و validation

**فایل‌های ایجاد شده:**
- `handshake.go`: تمام منطق handshake
- `auth.go`: توابع authentication و UUID handling

### Step 3: Encryption & Frame Processing ✅

- ساختار Frame با header (2 bytes length + 1 byte type)
- پیاده‌سازی `Session` برای مدیریت encryption
- رمزنگاری **ChaCha20-Poly1305** برای payload (مطابق مستندات)
- خواندن/نوشتن frame با nonce management
- پشتیبانی از انواع frame:
  - `FrameTypeData` (0x01): داده‌های کاربر
  - `FrameTypePadding` (0x02): کنترل padding
  - `FrameTypeTiming` (0x03): کنترل timing
  - `FrameTypeClose` (0x04): بستن اتصال
- Integration با inbound و outbound handlers

**فایل‌های ایجاد شده:**
- `frame.go`: ساختار Frame و constants
- `session.go`: مدیریت encryption session

### Step 4: Traffic Morphing & Fallback ✅

- پیاده‌سازی Traffic Morphing پایه:
  - Padding بسته‌های کوچک به MinSize
  - Randomization اندازه بسته‌ها
  - Validation اندازه بسته‌ها
- ساختار `MorphingConfig` با تنظیمات قابل پیکربندی
- **پیاده‌سازی کامل Fallback** به وب‌سرور:
  - Forward کردن connection به fallback destination
  - Bidirectional data forwarding
  - Context cancellation support
- تشخیص پروتکل با magic number (`ReflexMagic`)
- Multiplexing روی یک پورت (Reflex + HTTP)

**فایل‌های ایجاد شده:**
- `morphing.go`: منطق traffic morphing پایه
- `fallback.go`: ساختار fallback detection
- `inbound.go`: پیاده‌سازی کامل `handleFallback()`

### Step 5: Advanced Traffic Morphing ✅

- **پیاده‌سازی Traffic Morphing پیشرفته** با توزیع آماری:
  - ساختار `TrafficProfile` با توزیع اندازه بسته‌ها و timing
  - توزیع احتمال برای اندازه بسته‌ها (`PacketSizeDist`)
  - توزیع احتمال برای تأخیرها (`DelayDist`)
  - پروفایل‌های آماده: YouTube, Zoom, HTTP/2 API
- **پشتیبانی از Frame‌های PADDING_CTRL و TIMING_CTRL**:
  - Handle کردن control frames در session
  - ارسال control frames (`SendPaddingControl`, `SendTimingControl`)
  - Override mechanism برای packet size و delay
- **استخراج پروفایل از ترافیک**:
  - `CreateProfileFromCapture()` برای ساخت پروفایل از ترافیک واقعی
  - توابع helper برای محاسبه توزیع آماری
- یکپارچه‌سازی با Session:
  - `WriteFrameWithMorphing()` برای morphing پیشرفته
  - Split کردن داده‌های بزرگ به چند chunk
  - اعمال padding و delay بر اساس پروفایل

**فایل‌های ایجاد شده:**
- `traffic_profile.go`: ساختار TrafficProfile و پروفایل‌های آماده
- `session.go`: به‌روزرسانی برای پشتیبانی از TrafficProfile

### Testing ✅

- **54 تست** در `xray-core/tests/reflex/`:
  - `handshake_test.go`: 11 تست برای handshake
  - `session_test.go`: 12 تست برای encryption
  - `auth_test.go`: 6 تست برای authentication
  - `morphing_test.go`: 7 تست برای morphing
  - `integration_test.go`: 3 تست end-to-end
  - `inbound_test.go`: 5 تست برای inbound handler
  - `fallback_test.go`: 2 تست برای fallback
  - `traffic_profile_test.go`: 6 تست برای TrafficProfile (Step 5)
  - `session_morphing_test.go`: 8 تست برای advanced morphing (Step 5)

- Coverage: تست‌ها تمام بخش‌های اصلی را پوشش می‌دهند
- Race detection: همه تست‌ها با `-race` pass می‌شوند

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

### مشکل 5: Duplicate Functions
**مشکل**: تابع `equalBytes` در چند فایل تست duplicate بود.

**راه‌حل**: حذف duplicate و استفاده از `bytes.Equal` از standard library.

### مشکل 6: Encryption Algorithm Discrepancy
**مشکل**: مستندات ChaCha20-Poly1305 را می‌خواست اما کد اولیه از AES-256-GCM استفاده می‌کرد.

**راه‌حل**: تغییر encryption algorithm به ChaCha20-Poly1305 برای مطابقت با مستندات.

### مشکل 7: Fallback Implementation ناقص
**مشکل**: Fallback فقط hooks داشت و پیاده‌سازی کامل نبود.

**راه‌حل**: پیاده‌سازی کامل `handleFallback()` با forward کردن connection به وب‌سرور و context cancellation.

### مشکل 8: Fallback Test Hanging
**مشکل**: تست fallback hang می‌کرد چون `io.Copy` منتظر EOF می‌ماند.

**راه‌حل**: اضافه کردن context timeout و استفاده از `DialContext` به جای `Dial`.

### مشکل 9: TestWriteFrameWithMorphingLargeData Data Integrity
**مشکل**: تست `TestWriteFrameWithMorphingLargeData` fail می‌شد چون وقتی داده بزرگ split می‌شد، هر chunk padding می‌گرفت و padding هم خوانده می‌شد.

**راه‌حل**: ایجاد `writeFrameChunkWithoutPadding()` برای chunk‌های split شده تا فقط chunk‌های کوچکتر از targetSize را pad کنیم.

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
- استفاده از **ChaCha20-Poly1305** برای encryption (مطابق مستندات)
- Nonce management با counter (separate برای read/write)
- Frame format: `[Length:2][Type:1][EncryptedPayload]`

### Traffic Morphing پایه
- Padding بسته‌های کوچک به MinSize (default: 64 bytes)
- Randomization اندازه بسته‌ها بین MinSize و MaxSize
- Validation اندازه بسته‌ها برای drop کردن suspicious packets

### Advanced Traffic Morphing (Step 5)
- توزیع آماری اندازه بسته‌ها بر اساس پروفایل (YouTube, Zoom, HTTP/2 API)
- توزیع آماری timing برای تقلید از ترافیک واقعی
- پشتیبانی از PADDING_CTRL و TIMING_CTRL frames برای کنترل dynamic
- استخراج پروفایل از ترافیک واقعی با `CreateProfileFromCapture()`
- Split کردن داده‌های بزرگ به چند chunk با morphing

## ساختار فایل‌ها

```
xray-core/proxy/reflex/
├── inbound/
│   └── inbound.go          # Server-side handler
├── outbound/
│   └── outbound.go          # Client-side handler
├── handshake.go             # Handshake logic
├── auth.go                  # Authentication
├── session.go               # Encryption session (ChaCha20-Poly1305 + TrafficProfile)
├── frame.go                 # Frame structure
├── morphing.go              # Traffic morphing پایه
├── traffic_profile.go        # Advanced traffic morphing (Step 5)
├── fallback.go              # Fallback detection
├── config.proto             # Protobuf config
└── config.pb.go             # Generated code

xray-core/tests/reflex/
├── handshake_test.go
├── session_test.go
├── auth_test.go
├── morphing_test.go
├── integration_test.go
├── inbound_test.go
├── fallback_test.go
├── traffic_profile_test.go  # Step 5
└── session_morphing_test.go # Step 5
```

## نتیجه‌گیری

پروتکل Reflex با موفقیت در Xray-Core پیاده‌سازی شد. تمام مراحل 1 تا 5 کامل شده و تست‌های جامعی نوشته شده است. کد قابل compile است و تمام تست‌ها pass می‌شوند.

**ویژگی‌های کلیدی:**
- ✅ Handshake با X25519 و HMAC authentication
- ✅ Encryption با ChaCha20-Poly1305
- ✅ Traffic morphing پایه برای obfuscation
- ✅ Fallback کامل به وب‌سرور
- ✅ **Advanced Traffic Morphing با توزیع آماری**
- ✅ **پشتیبانی از PADDING_CTRL و TIMING_CTRL frames**
- ✅ **پروفایل‌های آماده (YouTube, Zoom, HTTP/2 API)**
- ✅ 54 تست جامع

**Step 5 کامل شده**: تمام قابلیت‌های اجباری Step 5 پیاده‌سازی شده است.
