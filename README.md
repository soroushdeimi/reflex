# پروژه Reflex 
##اسامی
فرزان محمدیان - نگین امیری - امیررضا نادری

## شماره دانشجویی
402100515 - 402100012 - 401100252

## توضیحات

پیاده‌سازی پروتکل **Reflex** به‌صورت فورک روی **xray-core** با قابلیت‌های زیر:

- **Handshake و احراز هویت:** تشخیص با magic number و/یا HTTP POST-like، مبادله کلید X25519، استخراج کلید جلسه با HKDF، احراز کاربر با UUID و بررسی timestamp (±۵ دقیقه). در صورت موفقیت پاسخ HTTP 200 با JSON و در غیر این صورت 403 و بستن اتصال.
- **Frame و رمزنگاری:** فریم‌های نوع Data، PaddingCtrl و TimingCtrl با ChaCha20-Poly1305؛ محافظت در برابر replay با شمارنده در nonce.
- **Fallback و Multiplexing:** با `Peek` تشخیص ترافیک Reflex از غیر-Reflex؛ ترافیک غیر-Reflex به مقصد fallback (مثلاً وب‌سرور روی پورت ۸۰) فرستاده می‌شود و بایت‌های peek‌شده به سرور fallback می‌رسند.
- **Traffic Morphing:** پروفایل‌های ترافیک (مثل youtube، zoom، http2-api) برای اندازه و تأخیر بسته؛ `WriteFrameWithMorphing` برای پد و تأخیر؛ پردازش فریم‌های PADDING_CTRL و TIMING_CTRL برای به‌روزرسانی پروفایل.

ساختار اصلی در `xray-core/proxy/reflex/` (config، session، morph، inbound، outbound) و تست‌ها در `xray-core/proxy/tests/` (reflex_*_test.go).

## نحوه اجرا

1. **ساخت باینری:** از داخل پوشه `xray-core/main`:
   ```bash
   go build -o xray .
   ```

2. **پیکربندی:** فایل `config.example.json` در ریشه پروژه (پوشه `reflex`) نمونهٔ پیکربندی است. یک UUID معتبر برای هر کلاینت در `settings.clients[].id` قرار دهید (مثلاً با `uuidgen` یا سرویس آنلاین UUID). در صورت نیاز پورت و `fallback.dest` را تنظیم کنید.

3. **اجرای سرور:**
   ```bash
   ./xray -config ../config.example.json
   ```
   (یا مسیر کامل به `config.example.json`)

4. **تست با کلاینت:** با یک کلاینت سازگار با Reflex به آدرس و پورت تعریف‌شده در inbound وصل شوید. برای تست fallback می‌توانید با مرورگر به همان آدرس و پورت بروید تا پاسخ وب‌سرور fallback را ببینید.

## مشکلات و راه‌حل‌ها

- **خطای `protoc-gen-go is not recognized`:** پلاگین `protoc-gen-go` نصب نبود یا مسیر `go/bin` در PATH نبود. با `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest` نصب و اضافه کردن `%USERPROFILE%\go\bin` (در ویندوز) به PATH حل شد.
- **رد شدن اولین frame در تست Replay:** در session با counter از nonce، اولین frame با counter 0 به اشتباه رد می‌شد. با اضافه کردن فلگ `readSeen` و قبول اولین frame و سپس اجبار به counter صعودی برطرف شد.
- **تست fallback بدون پاسخ:** در تست، درخواست HTTP کوتاه‌تر از حد Peek (۶۴ بایت) بود و Peek برنمی‌گشت. با طولانی‌تر کردن درخواست (مثلاً با هدرهای اضافه) تست درست شد.
- **مشکلات احتمالی دیگر:** اگر handshake با 403 مواجه شود، UUID و زمان سیستم کلاینت/سرور را چک کنید. اگر رمزگشایی خطا دهد، مطمئن شوید کلید جلسه و nonce یکسان است. اگر fallback جواب ندهد، مطمئن شوید سرور fallback روی پورت مشخص‌شده در حال اجرا است و فایروال اجازه اتصال می‌دهد.

---

# تست کردن

بعد از پیاده‌سازی، باید تست کنید که همه چیز درست کار می‌کنه.

## تست‌های واحد

تست‌های واحد پروتکل Reflex در پوشه `xray-core/proxy/tests/` قرار دارند:

- **reflex_session_test.go:** رمزنگاری/رمزگشایی فریم و رد replay.
- **reflex_morph_test.go:** پروفایل ترافیک، override اندازه و تأخیر، و تابع AddPadding.
- **reflex_inbound_test.go:** handshake موفق با magic، رد timestamp قدیمی، fallback برای HTTP ساده، و رسیدن بایت‌های peek‌شده به سرور fallback.

اجرای تست‌ها:

```bash
cd xray-core
go test ./proxy/tests/ -v -run Reflex
```

### تست Handshake

```go
func TestHandshake(t *testing.T) {
    // ساخت handler
    handler := NewHandler(testConfig)
    
    // ساخت connection mock
    clientConn, serverConn := net.Pipe()
    
    // تست handshake
    go func() {
        // کلاینت handshake می‌فرسته
        handshake := createClientHandshake()
        clientConn.Write(handshake)
    }()
    
    // سرور handshake رو پردازش می‌کنه
    err := handler.processHandshake(serverConn)
    if err != nil {
        t.Fatalf("handshake failed: %v", err)
    }
}
```

### تست رمزنگاری

```go
func TestEncryption(t *testing.T) {
    session, _ := NewSession(testKey)
    
    // تست رمزنگاری و رمزگشایی
    original := []byte("test data")
    
    encrypted := session.encrypt(original)
    decrypted := session.decrypt(encrypted)
    
    if !bytes.Equal(original, decrypted) {
        t.Fatal("encryption/decryption failed")
    }
}
```

### تست Fallback

```go
func TestFallback(t *testing.T) {
    // ساخت یک وب‌سرور ساده
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    }))
    defer server.Close()
    
    // تست fallback
    handler := NewHandler(fallbackConfig)
    // ... تست اتصال غیر-Reflex به fallback می‌ره
}
```

## تست‌های یکپارچگی

باید کل سیستم رو با هم تست کنید.

### تست اتصال کامل

1. یک سرور Xray با Reflex راه‌اندازی کنید
2. یک کلاینت Reflex بسازید (یا از یک کلاینت موجود استفاده کنید)
3. اتصال برقرار کنید و داده بفرستید
4. چک کنید که داده‌ها درست منتقل می‌شن

### تست Fallback

1. سرور رو با fallback به یک وب‌سرور تنظیم کنید
2. با مرورگر به پورت سرور وصل بشید
3. باید صفحه وب رو ببینید (نه خطای پروتکل)

### تست مقاومت در برابر Replay

```go
func TestReplayProtection(t *testing.T) {
    session := NewSession(testKey)
    
    frame := createTestFrame()
    
    // ارسال اول - باید موفق باشه
    err1 := session.ProcessFrame(frame)
    if err1 != nil {
        t.Fatal("first frame should succeed")
    }
    
    // ارسال دوباره - باید reject بشه
    err2 := session.ProcessFrame(frame)
    if err2 == nil {
        t.Fatal("replay should be rejected")
    }
}
```

## تست عملکرد

می‌تونید سرعت و استفاده از حافظه رو تست کنید:

```go
func BenchmarkEncryption(b *testing.B) {
    session, _ := NewSession(testKey)
    data := make([]byte, 1024)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        session.encrypt(data)
    }
}

// تست با اندازه‌های مختلف
func BenchmarkEncryptionSizes(b *testing.B) {
    sizes := []int{64, 256, 1024, 4096, 16384}
    for _, size := range sizes {
        b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
            session, _ := NewSession(testKey)
            data := make([]byte, size)
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                session.encrypt(data)
            }
        })
    }
}

// تست memory allocation
func BenchmarkMemoryAllocation(b *testing.B) {
    session, _ := NewSession(testKey)
    data := make([]byte, 1024)
    
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        session.encrypt(data)
    }
}
```

## تست Coverage

برای اینکه مطمئن بشی همه کد تست شده، می‌تونی coverage رو چک کنی:

```bash
# اجرای تست‌ها با coverage
go test -cover ./...

# coverage برای یک پکیج خاص
go test -cover ./proxy/reflex/inbound

# coverage با جزئیات بیشتر
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**هدف**: حداقل 60-70% coverage برای کدهای اصلی (handshake, encryption, fallback). Coverage 100% لازم نیست، ولی بخش‌های critical رو حتماً تست کن.

## Linting

قبل از commit، کدت رو با linter چک کن:

```bash
# نصب golangci-lint (اگه ندارید)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# اجرای linter
golangci-lint run ./...

# یا فقط برای پکیج reflex
golangci-lint run ./proxy/reflex/...
```

اگه linter خطا داد، سعی کن fix کنی. بعضی warning‌ها رو می‌تونی ignore کنی (مثلاً complexity بالا برای بعضی توابع).

## Race Detection

برای پیدا کردن race condition‌ها، می‌تونی از race detector استفاده کنی:

```bash
# تست با race detector
go test -race ./...

# برای benchmark هم می‌تونید race detector رو فعال کنید
go test -race -bench=. ./...
```

Race detector کند می‌کنه، ولی خیلی مهمه برای concurrent code. حتماً قبل از تحویل اجرا کن.

## تست Edge Cases

یه سری edge case هست که باید تست کنی:

```go
// تست با داده‌های خالی
func TestEmptyData(t *testing.T) {
    session, _ := NewSession(testKey)
    err := session.WriteFrame(conn, FrameTypeData, []byte{})
    // باید handle بشه بدون crash
}

// تست با داده‌های خیلی بزرگ
func TestLargeData(t *testing.T) {
    session, _ := NewSession(testKey)
    largeData := make([]byte, 10*1024*1024) // 10MB
    err := session.WriteFrame(conn, FrameTypeData, largeData)
    // باید handle بشه
}

// تست با connection بسته شده
func TestClosedConnection(t *testing.T) {
    conn, _ := net.Pipe()
    conn.Close()
    err := session.WriteFrame(conn, FrameTypeData, []byte("test"))
    // باید error برگردونه
}

// تست با handshake نامعتبر
func TestInvalidHandshake(t *testing.T) {
    handler := NewHandler(testConfig)
    conn, _ := net.Pipe()
    // ارسال داده‌های نامعتبر
    conn.Write([]byte("invalid data"))
    err := handler.Process(ctx, net.Network_TCP, conn, dispatcher)
    // باید به fallback بره یا error برگردونه
}

// تست با UUID نامعتبر
func TestInvalidUUID(t *testing.T) {
    handler := NewHandler(testConfig)
    // handshake با UUID که در config نیست
    // باید reject بشه
}

// تست با nonce تکراری (replay)
func TestReplayAttack(t *testing.T) {
    session := NewSession(testKey)
    frame := createTestFrame()
    
    // ارسال اول
    session.ProcessFrame(frame)
    
    // ارسال دوباره با همون nonce
    err := session.ProcessFrame(frame)
    if err == nil {
        t.Fatal("replay should be rejected")
    }
}

// تست با timestamp قدیمی
func TestOldTimestamp(t *testing.T) {
    // handshake با timestamp خیلی قدیمی
    // باید reject بشه
}

// تست با drop وسط انتقال (connection reset)
func TestConnectionReset(t *testing.T) {
    session, _ := NewSession(testKey)
    conn, _ := net.Pipe()
    
    // شروع ارسال
    go func() {
        session.WriteFrame(conn, FrameTypeData, []byte("test"))
    }()
    
    // بستن connection وسط انتقال
    conn.Close()
    
    // باید error handle بشه بدون panic
}

// تست با payload خیلی بزرگ (بیشتر از buffer)
func TestOversizedPayload(t *testing.T) {
    session, _ := NewSession(testKey)
    conn, _ := net.Pipe()
    
    // payload بزرگتر از max frame size
    hugeData := make([]byte, 10*1024*1024) // 10MB
    err := session.WriteFrame(conn, FrameTypeData, hugeData)
    
    // باید یا split بشه یا error برگردونه
    if err == nil {
        // اگه split شده، باید چند frame ارسال شده باشه
    }
}

// تست با handshake ناقص (connection بسته شده وسط handshake)
func TestIncompleteHandshake(t *testing.T) {
    handler := NewHandler(testConfig)
    conn, _ := net.Pipe()
    
    // ارسال فقط بخشی از handshake
    conn.Write([]byte("POST /api"))
    conn.Close()
    
    // باید error handle بشه
    err := handler.Process(ctx, net.Network_TCP, conn, dispatcher)
    if err == nil {
        t.Fatal("should handle incomplete handshake")
    }
}
```

## Documentation Coverage

یه نکته مهم: همه public APIs رو مستند کن. این کار خیلی کمک می‌کنه:

```go
// NewSession creates a new Reflex session with the given session key.
// The session key must be 32 bytes long (for ChaCha20-Poly1305).
// Returns an error if the session key is invalid.
func NewSession(sessionKey []byte) (*Session, error) {
    // ...
}

// WriteFrame encrypts and writes a frame to the connection.
// frameType specifies the type of frame (DATA, PADDING, etc.).
// data is the payload to be encrypted and sent.
// writer can be io.Writer (like stat.Connection or net.Conn)
func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
    // ...
}
```

برای چک کردن، می‌تونی از `godoc` استفاده کنی تا ببینی documentation درست نمایش داده می‌شه:

```bash
godoc -http=:6060
# بعد برید به http://localhost:6060
```

## Examples

برای هر public API، یه example بنویس. این کار خیلی کمک می‌کنه به کسی که می‌خواد از API استفاده کنه:

```go
// example_test.go
package reflex_test

import (
    "github.com/xtls/xray-core/proxy/reflex"
)

func ExampleNewSession() {
    sessionKey := make([]byte, 32)
    // ... initialize key
    
    session, err := reflex.NewSession(sessionKey)
    if err != nil {
        panic(err)
    }
    
    // Use session...
}

func ExampleSession_WriteFrame() {
    session, _ := reflex.NewSession(testKey)
    conn, _ := net.Dial("tcp", "example.com:443")
    
    data := []byte("hello world")
    err := session.WriteFrame(conn, reflex.FrameTypeData, data)
    // توجه: conn باید io.Writer رو implement کنه (که stat.Connection و net.Conn می‌کنن)
    if err != nil {
        panic(err)
    }
}
```

## Security Review

برای پروژه‌های امنیتی، یه سری تست‌های امنیتی هم می‌تونی انجام بدی (اختیاریه، ولی خیلی مفیده):

```go
// تست با input تصادفی (fuzzing)
func FuzzHandshake(f *testing.F) {
    f.Add([]byte("random data"))
    f.Fuzz(func(t *testing.T, data []byte) {
        // تست handshake با داده‌های تصادفی
        // نباید crash کنه یا panic کنه
    })
}

// تست timing attack
func TestTimingAttack(t *testing.T) {
    // تست که UUID comparison timing leak نداره
}

// تست با کلیدهای ضعیف
func TestWeakKeys(t *testing.T) {
    // تست که کلیدهای ضعیف reject می‌شن
}
```

Fuzzing اختیاریه، ولی خیلی مفیده برای پیدا کردن bug‌های امنیتی.

## Compatibility Testing

اگه می‌خوای مطمئن بشی که کدت با نسخه‌های مختلف Go کار می‌کنه:

```bash
# تست با Go 1.21
go1.21 test ./...

# تست با Go 1.22
go1.22 test ./...

# تست با آخرین نسخه
go test ./...
```

اگه از feature‌های جدید Go استفاده کردی (مثلاً Go 1.22+)، باید minimum version رو در `go.mod` مشخص کنی.

## Integration Testing با Xray-Core

یه نکته مهم: باید تست کنی که پروتکلت با Xray-Core درست کار می‌کنه:

```go
// integration_test.go
func TestXrayIntegration(t *testing.T) {
    // ساخت config برای Xray
    config := createXrayConfig()
    
    // راه‌اندازی Xray server
    server := startXrayServer(config)
    defer server.Stop()
    
    // اتصال با کلاینت Reflex
    client := createReflexClient()
    err := client.Connect(server.Address)
    if err != nil {
        t.Fatal(err)
    }
    
    // ارسال داده
    data := []byte("test data")
    err = client.Send(data)
    if err != nil {
        t.Fatal(err)
    }
    
    // دریافت پاسخ
    response, err := client.Receive()
    if err != nil {
        t.Fatal(err)
    }
    
    // چک کردن
    if !bytes.Equal(data, response) {
        t.Fatal("data mismatch")
    }
}
```

## Performance Benchmarking

اگه می‌خوای performance رو با پروتکل‌های دیگه مقایسه کنی (اختیاریه):

```go
func BenchmarkReflexEncryption(b *testing.B) {
    session, _ := NewSession(testKey)
    data := make([]byte, 1024)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        session.encrypt(data)
    }
}

func BenchmarkVMessEncryption(b *testing.B) {
    // benchmark با VMess برای مقایسه
}

func BenchmarkReflexHandshake(b *testing.B) {
    for i := 0; i < b.N; i++ {
        // تست handshake
    }
}

// مقایسه
func BenchmarkComparison(b *testing.B) {
    b.Run("Reflex", BenchmarkReflexEncryption)
    b.Run("VMess", BenchmarkVMessEncryption)
}
```

Performance comparison اختیاریه، ولی اگه انجام بدی، امتیاز اضافی می‌گیری.

## چطوری بفهمید درست کار می‌کنه؟

### چک‌لیست کامل تست

**تست‌های پایه (اینها رو حتماً انجام بده)**:
- [ ] همه تست‌ها pass می‌شن (`go test ./...`)
- [ ] Coverage حداقل 60-70% هست (`go test -cover ./...`)
- [ ] Linting pass می‌شه (`golangci-lint run ./...`)
- [ ] Race detection pass می‌شه (`go test -race ./...`)
- [ ] Handshake درست کار می‌کنه
- [ ] رمزنگاری و رمزگشایی درست کار می‌کنه
- [ ] Fallback به وب‌سرور کار می‌کنه
- [ ] Replay protection کار می‌کنه
- [ ] اتصال کامل از کلاینت به سرور کار می‌کنه
- [ ] داده‌ها بدون خطا منتقل می‌شن

**تست‌های پیشرفته (اینها رو هم انجام بده، بهتره)**:
- [ ] Edge cases تست شده (داده خالی، داده بزرگ، connection بسته، etc.)
- [ ] همه public APIs مستند شدن
- [ ] Examples برای public APIs نوشته شده
- [ ] Integration test با Xray-Core انجام شده
- [ ] Compatibility با نسخه‌های مختلف Go تست شده

**تست‌های اختیاری (اگه وقت داشتی، امتیاز اضافی می‌گیری)**:
- [ ] Security review انجام شده (fuzzing, timing attack, etc.)
- [ ] Performance benchmark با پروتکل‌های دیگه مقایسه شده

### تست دستی

1. سرور رو اجرا کنید: `./xray -config config.json`
2. کلاینت رو اجرا کنید
3. یک وب‌سایت رو باز کنید
4. چک کنید که ترافیک درست منتقل می‌شه

### لاگ‌ها

برای دیباگ، می‌تونید لاگ اضافه کنید:

```go
import "github.com/xtls/xray-core/common/log"

log.Record(&log.GeneralMessage{
    Severity: log.Severity_Info,
    Content: "Handshake completed",
})
```

## مشکلات رایج

### Handshake fail می‌شه
- چک کنید که کلیدها درست مبادله می‌شن
- چک کنید که UUID درست ارسال می‌شه
- لاگ‌ها رو چک کنید

### رمزگشایی fail می‌شه
- چک کنید که nonce درست استفاده می‌شه
- چک کنید که کلید جلسه درست استخراج شده
- چک کنید که payload درست خوانده می‌شه

### Fallback کار نمی‌کنه
- چک کنید که Peek درست کار می‌کنه
- چک کنید که بایت‌های peek شده به وب‌سرور فرستاده می‌شن
- چک کنید که وب‌سرور درست اجرا شده

## بعدی

وقتی تست‌ها رو تموم کردید، برید سراغ [تحویل](submission.md).
