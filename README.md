# پروژه Reflex

## اعضای تیم

- 401100296 — ابوالفضل آسوده
- 401100314 — محمدباقر برکند
- 401100393 — علی راسخی

## توضیحات پروژه

پروتکل Reflex یک پروتکل پراکسی جدید هست که برای Xray-Core پیاده‌سازی شده. هدف اصلی این پروتکل اینه که ترافیک پراکسی رو از نظر آماری غیرقابل تشخیص کنه و در برابر تحلیل ترافیک و Active Probing مقاوم باشه. ما این پروتکل رو در پنج مرحله پیاده‌سازی کردیم و بعدش تست‌های واحد و یکپارچگی براش نوشتیم.

### مرحله ۱ — ساختار پایه

ساختار پکیج رو زدیم. فایل `config.proto` رو تعریف کردیم که شامل `InboundConfig`، `OutboundConfig`، `User`، `Account` و `Fallback` هست. با `protoc` فایل `config.pb.go` رو تولید کردیم. هندلرهای اولیه inbound و outbound رو ساختیم و import‌ها رو توی `all.go` اضافه کردیم تا پروتکل توسط Xray-Core شناسایی بشه. ساختار نهایی پکیج به این صورت شد:

```
proxy/reflex/
├── config.proto / config.pb.go
├── config.go
├── handshake.go
├── codec.go
├── morph.go
├── ech.go
├── inbound/inbound.go
└── outbound/outbound.go
```

### مرحله ۲ — Handshake و احراز هویت

برای تبادل کلید از Curve25519 استفاده کردیم. کلاینت یه keypair ephemeral تولید می‌کنه و public key رو همراه با UUID و timestamp و nonce تصادفی توی بسته اول می‌فرسته. سرور هم یه keypair تولید می‌کنه و public key خودشو برمی‌گردونه. بعد هر دو طرف با `DeriveSharedSecret` یه shared secret می‌سازن و با HKDF-SHA256 کلید جلسه ۳۲ بایتی استخراج می‌کنن. احراز هویت با UUID انجام می‌شه — سرور UUID کلاینت رو با لیست کلاینت‌های مجاز مقایسه می‌کنه. برای جلوگیری از timing attack از `subtle.ConstantTimeCompare` استفاده کردیم. اعتبارسنجی timestamp هم هست تا handshake‌های قدیمی reject بشن.

### مرحله ۳ — رمزنگاری و فریم‌بندی

از ChaCha20-Poly1305 به‌عنوان AEAD cipher استفاده کردیم. ساختار هر فریم: ۲ بایت طول + ۱ بایت نوع + payload رمزنگاری‌شده. چهار نوع فریم داریم: `DATA`، `PADDING`، `TIMING` و `CLOSE`. هر فریم با nonce ترتیبی رمزنگاری می‌شه و nonce‌ها برای خواندن و نوشتن جدا مدیریت می‌شن. برای محافظت در برابر replay attack از `NonceTracker` استفاده کردیم که nonce‌های دیده‌شده رو ذخیره می‌کنه و تکراری‌ها رو reject می‌کنه.

### مرحله ۴ — Fallback

با `bufio.Reader` و `Peek` چهار بایت اول ترافیک رو بدون مصرف می‌خونیم و magic number رو چک می‌کنیم (`0x5246584C` = "RFXL"). اگه magic مطابقت نداشته باشه (مثلاً ترافیک HTTP یا TLS عادی باشه)، اتصال به وب‌سرور fallback هدایت می‌شه. برای اینکه بایت‌های peek شده گم نشن، از `preloadedConn` استفاده کردیم که `bufio.Reader` رو wrap می‌کنه. اینطوری multiplexing روی یک پورت انجام می‌شه: هم Reflex و هم ترافیک وب از یک پورت سرویس می‌گیرن.

### مرحله ۵ — قابلیت‌های پیشرفته

#### Traffic Morphing

سیستم Traffic Morphing پیاده‌سازی کردیم که اندازه بسته‌ها و delay بین فریم‌ها رو بر اساس پروفایل‌های ترافیکی تنظیم می‌کنه. پنج پروفایل آماده داریم: YouTube، Zoom، Netflix، HTTP/2 API و Discord. هر پروفایل شامل توزیع وزن‌دار اندازه بسته‌ها و توزیع وزن‌دار delay‌ها هست. `MorphWrite` داده رو به chunk‌های متناسب با پروفایل تقسیم می‌کنه و بینشون delay اعمال می‌کنه. فریم‌های `PADDING_CTRL` و `TIMING_CTRL` هم پشتیبانی می‌شن تا peer بتونه اندازه بسته بعدی یا delay رو override کنه.

#### ECH (Encrypted Client Hello)

پشتیبانی از TLS با ECH رو هم اضافه کردیم. با `GenerateECHKeySet` یه keypair X25519 برای ECH تولید می‌شه و `ECHConfig` سریالایز شده ساخته می‌شه. `ApplyECHServer` و `ApplyECHClient` تنظیمات TLS رو برای سرور و کلاینت اعمال می‌کنن. اینطوری SNI واقعی از دید ناظر مخفی می‌مونه.

### تست‌ها

بیش از ۹۰ تست واحد و یکپارچگی نوشتیم که تمام بخش‌های اصلی پروتکل رو پوشش می‌دن:
- تست‌های handshake (تبادل کلید، سریالایز/دسریالایز، اعتبارسنجی timestamp، احراز هویت)
- تست‌های رمزنگاری (ساخت session، encrypt/decrypt، انواع فریم، nonce tracker)
- تست‌های traffic morphing (پروفایل‌ها، padding، control frame‌ها)
- تست‌های ECH (تولید کلید، config list، تنظیمات TLS)
- تست‌های یکپارچگی (handshake کامل client-server، تشخیص fallback، حفاظت replay، انتقال داده دوطرفه)
- تست‌های edge case (داده خالی، کلید اشتباه، header ناقص، اتصال بسته)

Coverage حدود ۷۲٪ برای پکیج اصلی `proxy/reflex` و حدود ۴۶٪ کلی هست.

## نحوه اجرا

### پیش‌نیازها

- Go نسخه ۱.۲۲ یا بالاتر
- Git

### بیلد

```bash
cd xray-core
go build -o xray ./main
```

### اجرای تست‌ها

```bash
cd xray-core

# اجرای همه تست‌ها
go test ./proxy/reflex/... ./tests/...

# با coverage
go test -coverprofile=coverage.out -covermode=atomic ./proxy/reflex/... ./tests/...
go tool cover -func=coverage.out

# با race detector
CGO_ENABLED=1 go test -race ./proxy/reflex/... ./tests/...
```

### اجرای سرور

فایل `config.example.json` در ریشه ریپو یه نمونه کانفیگ هست. برای اجرا:

```bash
./xray -config config.example.json
```

## نمونه پیکربندی

فایل [`config.example.json`](config.example.json) رو ببینید. توضیح مختصر:

- **inbound**: پروتکل `reflex` روی پورت ۴۴۳ با fallback به پورت ۸۰۸۰ (وب‌سرور). هر کلاینت یه UUID و یه policy (پروفایل morphing) داره.
- **outbound**: از سمت کلاینت، اتصال به سرور Reflex با UUID مشخص.

## مشکلات و راه‌حل‌ها

### مشکل Nonce Synchronization

اوایل کار وقتی فریم‌ها رو رمزنگاری و رمزگشایی می‌کردیم، nonce‌ها از sync خارج می‌شدن و decryption fail می‌شد. مشکل اینجا بود که read nonce و write nonce رو توی یه counter مشترک داشتیم. وقتی nonce‌های خواندن و نوشتن رو جدا کردیم و با mutex محافظت کردیم، مشکل حل شد.

### مشکل Peek و بایت‌های مصرف‌شده

توی پیاده‌سازی fallback، وقتی `Peek` می‌زدیم و بعد اتصال رو به وب‌سرور forward می‌کردیم، بایت‌های peek شده گم می‌شدن و وب‌سرور request ناقص دریافت می‌کرد. `preloadedConn` رو ساختیم که `bufio.Reader` رو wrap می‌کنه و متد `Read` رو override می‌کنه تا بایت‌های peek شده هم خوانده بشن.

### مشکل Traffic Morphing و Overhead

اولین نسخه morphing، overhead رمزنگاری AEAD رو حساب نمی‌کرد و chunk size رو بر اساس target size پروفایل انتخاب می‌کرد. نتیجه این بود که بسته‌های نهایی بزرگ‌تر از حد مورد انتظار بودن. بعداً overhead رو از target size کم کردیم تا اندازه واقعی بسته‌ها با پروفایل مطابقت داشته باشه.

### مشکل Timestamp Validation

وقتی تست‌ها رو روی CI اجرا می‌کردیم، بعضی وقت‌ها handshake fail می‌شد چون ساعت سرور CI با ساعت تست sync نبود. `MaxTimestampDrift` رو ۱۲۰ ثانیه گذاشتیم که یه tolerance معقول باشه.

## ساختار فایل‌ها

```
reflex/
├── README.md                          # همین فایل
├── config.example.json                # نمونه پیکربندی
├── docs/                              # مستندات پروژه
├── xray-core/
│   ├── proxy/reflex/                  # پیاده‌سازی پروتکل
│   │   ├── config.proto               # تعریف protobuf
│   │   ├── config.pb.go               # کد تولیدشده
│   │   ├── config.go                  # Account و MemoryAccount
│   │   ├── handshake.go               # تبادل کلید و احراز هویت
│   │   ├── codec.go                   # رمزنگاری و فریم‌بندی
│   │   ├── morph.go                   # traffic morphing
│   │   ├── ech.go                     # Encrypted Client Hello
│   │   ├── inbound/inbound.go         # هندلر ورودی
│   │   └── outbound/outbound.go       # هندلر خروجی
│   └── tests/
│       └── reflex_test.go             # تست‌های یکپارچگی
└── .github/
    └── workflows/grade-pr.yml         # پایپلاین نمره‌دهی
```
