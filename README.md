# پروژه Reflex 

## contributors:
- 401170134-Mohammad Javad Gharegozlou
- 403170055-Rojan Karimghasemi
- 401100047-Amir Mohammad Aghabozorgi

## شماره دانشجویی و نام 
- محمد جواد قره‌گوزلو - 401170134
- روژان کریمقاسمی - 403170055
- 401100047 - امیر محمد اقا بزرگی


## خلاصه پیاده‌سازی
این پروژه شامل پیاده‌سازی کامل پروتکل Reflex در Xray-Core است که در پنج مرحله انجام شده:

### مراحل پیاده‌سازی شده:
1. **Step 1 - ساختار اولیه**: ایجاد ساختار پکیج، تعریف `config.proto`، و handler اولیه
2. **Step 2 - Handshake**: پیاده‌سازی تبادل کلید X25519، استخراج کلید با HKDF، و احراز هویت UUID
3. **Step 3 - Encryption**: رمزنگاری ChaCha20-Poly1305 AEAD، ساختار Frame، و محافظت در برابر replay
4. **Step 4 - Fallback**: تشخیص پروتکل با `Peek()`, fallback به وب‌سرور، و پشتیبانی HTTP POST camouflage
5. **Step 5 - Advanced**: Traffic Morphing با ۳ پروفایل (YouTube, Zoom, HTTP/2 API)، frame‌های PADDING و TIMING

### ویژگی‌های اضافی:
- ✅ پیاده‌سازی کامل HTTP POST handler برای camouflage
- ✅ ۱۴ benchmark test برای تحلیل performance
- ✅ ۳۵+ تست واحد و یکپارچگی
- ✅ Coverage: 67.9% (در محدوده هدف 60-70%)
- ✅ همه تست‌ها با race detector و linter pass می‌شوند

## نحوه اجرا

### بیلد و اجرا:
```bash
cd xray-core
go build -o xray ./main
./xray run -c ../config.example.json
```

### اجرای تست‌ها:
```bash
# تست واحد
go test ./proxy/reflex/... -v

# تست یکپارچگی
go test ./tests/... -v

# بررسی coverage
go test -coverprofile=coverage.out ./proxy/reflex/inbound
go tool cover -html=coverage.out

# اجرای benchmark
go test -bench=. -benchmem ./proxy/reflex/inbound
```

### اسکریپت بررسی پیش از تحویل:
```bash
cd ..
./scripts/check-reflex.sh
```

این اسکریپت همه بررسی‌های لازم (تست‌ها، coverage، race detector، build) را انجام می‌دهد.

## مشکلات و راه‌حل‌ها

### 1. تولید Protocol Buffer Files
**مشکل**: تولید `config.pb.go` از `config.proto` نیاز به ابزارهای `protoc` و `protoc-gen-go` داشت.

**راه‌حل**: از ابزار `vprotogen` موجود در Xray-Core استفاده کردیم:
```bash
cd xray-core
go run ./infra/vprotogen/main.go -pwd .
```

### 2. تشخیص پروتکل بدون مصرف بایت‌ها
**مشکل**: برای پیاده‌سازی fallback، نیاز بود ابتدای ترافیک را بخوانیم بدون اینکه آن را مصرف کنیم.

**راه‌حل**: از `bufio.Reader.Peek()` برای خواندن بدون مصرف استفاده کردیم، سپس یک `preloadedConn` wrapper ساختیم که بایت‌های peek شده را از `Reader` می‌خواند:
```go
type preloadedConn struct {
    *bufio.Reader
    net.Conn
}
```

### 3. تست‌های Fallback با HTTP Server
**مشکل**: استفاده از `httptest.NewServer` در محیط sandbox موجب خطای permission می‌شد.

**راه‌حل**: به جای `httptest`، از `net.Listen("tcp", "127.0.0.1:0")` و `http.Serve()` مستقیم استفاده کردیم و با timeout و channel synchronization از deadlock جلوگیری کردیم.

### 4. Coverage پس از افزودن HTTP POST Handler
**مشکل**: با پیاده‌سازی کامل HTTP POST handler (از stub به 80+ خط کد)، coverage از 72.6% به 67.9% کاهش یافت.

**توضیح**: این کاهش طبیعی است زیرا کد جدید اضافه شده (handler کامل) coverage کمتری دارد. با این حال هنوز در محدوده هدف (60-70%) هستیم و functionality واقعی اضافه شده است.

### 5. Race Condition در تست‌های پیچیده
**مشکل**: برخی تست‌های integration با goroutine و `io.Copy` دچار deadlock می‌شدند.

**راه‌حل**: 
- استفاده از buffered channel برای signal کردن completion
- افزودن timeout با `context.WithTimeout`
- مدیریت دقیق `defer Close()` برای connection‌ها


