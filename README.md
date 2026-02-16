# گزارش تغییرات (Reflex Protocol Integration)

- 402100431 — Mahdi Khoshnevis
- 402111045 — AmirAli Shafiei
- 402170154 — AmirHossein Taheri

---
**تست هایی که در پایین آورده شده اند در آخر به دایرکتوری گفته شده در آخر `submission.md` هم منتقل شدند.**

## 📂 گزارش فایل‌های تغییرکرده (فایل‌به‌فایل)

### `xray-core/infra/conf/xray.go`

پروتکل `reflex` به registry مربوط به inbound/outbound اضافه شد.

📌 **نقش فایل:**  
این فایل مسئول نگاشت مقدار `"protocol"` در JSON config به struct صحیح است.
بدون این تغییر، configهایی که شامل:

```json
"protocol": "reflex"
```

باشند شناسایی نمی‌شوند.

---

### `xray-core/main/distro/all/all.go`

صرفا importهای زیر اضافه شد:

- `reflex/inbound`
- `reflex/outbound`

📌 **نقش فایل:**  
این فایل در build کامل (`main/distro/all`) تمام featureها و proxyها و در کل همه موارد را از طریق `init()` رجیستر می‌کند.

---

### `xray-core/infra/conf/reflex.go`

در این فایل json Parser و  builder برای inbound و outbound مربوط به تنظیمات Reflex اضافه شد.

همچنین validation پایه اضافه شد، مثل:
- خالی نبودن `id`
- ست بودن `address/port` (خالی نبودن آدرس و صفر نبودن پورت)

📌 **نقش فایل:**  
تبدیل JSON config به protobuf config قابل استفاده توسط هسته Xray.

---

### `xray-core/proxy/reflex/config_test.go`

تست‌های مربوط به message config اضافه شد:

- درستی getterها و reset
- nil safe بودن ساختارها
- درستی descriptor init

📌 **هدف تست‌ها:**  
جلوگیری از خطاهای ریز و regression در مدل config (کدهای ورژن های قبل در آینده درست و مطابق انتظار کار کنند)

---

## 🔐 Inbound Implementation

### `xray-core/proxy/reflex/inbound/inbound.go`

- تشخیص اینکه اتصال، هندشیک Reflex است یا نه.
- parse و اعتبارسنجی هندشیک کلاینت
- جلوگیری از replay -> یعنی یک nonce نباید بیش از یکبار دیده شود و باید ارور بدهیم 
- ساخت session -> فریم به فریم (ارسال دیتا،  اعمال تنظیمات padding و timing و بستن فریم)
- مدیریت fallback -> در صورت معتبر نبودن اتصال fallback میفرستد (ارورهای غیرمنتظره یا پورت مقصد نامعتبر) 
-  خواندن اطلاعات handshake کاربر: به ترتیب public key و user id و زمان و nonce و طول policy و بررسی معتبر بودن طول آن و گرفتن policy
- ساخت کلید با این الگو -> برای بایت اول 3 بیت اول را پاک کرده (AND گرفتن با صفر) و برای بایت آخر بیت آخر را صفر می کنیم و بیت 7 را یک می کنیم (OR گرفتن با یک)
- چک کردن معتبر بودن زمان (اختلاف کمتر از 300 ثانیه ای با سرور)
- رمزنگاری با استفاده از XOR گرفتن email و بایت متناظر آن در کلید session



**باقی توابع بر اساس مراحل و step یک تا پنج و تقریبا کپی شده آنها هستند**

📌 **نقش فایل:**  
اصلی‌ترین مسیر runtime سمت server.

---

### `xray-core/proxy/reflex/inbound/session.go`

منطق session و frame اضافه شده:
- استفاده از AEAD برای encrypt/decrypt فریم‌ها
- استفاده از  nonce (number used once) برای امنیت بیشتر

**باقی توابع بر اساس مراحل و step یک تا پنج و تقریبا کپی شده آنها هستند**

📌 **نقش فایل:**  
امنیت بیشتر و شکل‌دهی ترافیک در سطح فریم

---

## 🧪 Tests (Inbound)

### `xray-core/proxy/reflex/inbound/helpers_test.go`

تست helperها و مسیرهای مهم inbound:

- ساخت handler
- auth (regular user and user not found) + replay -> مثلا  در اینجا توقع داریم اعداد یکبار مصرف پس از استفاده از بین بروند
- parse مقصد و payload 
- parse handshake
- بررسی key derivation -> چک کردن قطعی بودن shared key نسبت و ورودی ها و قابل قبول بودن اختلاف زمانی نسبت زمان حال (حداکثر 300 ثانیه یا 5 دقیقه تفاوت قابل قبول است)
- بررسی Policy و HTTP response -> اعتبارسنجی می‌کند که انتخاب policy کاربر درست است (کاربر موجود، ناموجود، و nil)، سپس برگشت‌پذیری encryptPolicyGrant را چک می‌کند و در نهایت ساختار پاسخ HTTP/JSON را بررسی میکند.

- بررسی fallback و non TCP -> بررسی که آیا این دو به درستی کد 403 (با فرمت درست و بدنه غیر خالی) برمی گردانند و در غیر این صورت FAIL می شوند. 
- بررسی SessionClose و UnknownFrame -> بررسی بستن درست یک session و  فریم ناشناخته (مثل 0x99) باید دقیقا خطای unknown frame type بدهد.
- بررسی data parse -> ورودی کوتاه/خراب به handleData می‌دهد تا مطمئن شود خطای parse برمی‌گردد

📌 **هدف:**  
افزایش پوشش تست برای رفتار توابع کمکی.

---

### `xray-core/proxy/reflex/inbound/session_test.go`

تست‌های session:

- write/read فریم درست
- خطای کلید نامعتبر -> مثلا در اینجا کلید بیش از حد کوتاه
- خطای frame بزرگ
- اعمال morphing
- اثر control frame روی profile -> در واقع عوض کردن دیفالت و پیش فرض یک بخش پروفایل و چک کردن اینکه آیا تغییر به درستی ایجاد میشود یا نه

📌 **هدف:**  
تضمین پایداری encode/decode فریم‌ها

---

### `xray-core/proxy/reflex/inbound/fallback_test.go`

تست fallback و handshake detection:

- تشخیص magic handshake
- تشخیص HTTP POST handshake
- حفظ بایت‌های peek شده (باید بعد از peek همان حالت قبلی بمانند و تغییر نکنند)
- ارسال پاسخ 403 در حالت deny -> ما کد 403 ارسال می کنیم از طرف سرور و چک میکنیم که کلاینت آن را باید به درستی بررسی کند 

📌 **هدف:**  
جلوگیری از regression در مسیر fallback (یعنی تا جایی که امکان پذیر است، از خرابی و به مشکل خوردن قابلیت هایی که قبلا درست کار می کردند جلوگیری کنیم)

---

### `xray-core/proxy/reflex/inbound/security_test.go`

تست امنیتی auth:

- بررسی استفاده از `subtle.ConstantTimeCompare`
- تست تقریبی timing برای mismatch position و اگر تفاوت نسبت زیاد بود (بیشتر از 1.8) احتمالا به مکان ربط دارد و تست FAIL می شود.

📌 **هدف:**  
کاهش ریسک نشت زمانی (Timing Leak)

---

### `xray-core/proxy/reflex/inbound/security_fuzz_test.go`

اضافه شدن fuzz test برای parserها:

- `parseClientHandshakeBytes`
همونطور که کامنت هم شده 74 از جمع طول بخش های مختلف میاد.
- `parseDestinationAndPayload`

📌 **هدف:**  
اطمینان از اینکه ورودی‌های خراب یا تصادفی باعث crash/panic نشوند.

---

## 🌍 Outbound Implementation

### `xray-core/proxy/reflex/outbound/outbound.go`

اسکلت اولیه outbound Reflex اضافه و register شد.

⚠️ در این مرحله `Process` عمداً خالی نگه داشته شده تا:
- ساختار کلی پروتکل کامل باشد

---

### `xray-core/proxy/reflex/outbound/outbound_test.go`

تست پایه outbound برای موارد زیر اضافه شد:

- `New`
- `Process`

📌 **هدف:**  
اطمینان از ساخته شدن handler و جلوگیری از خطاهای غیرمنتظره در مسیر اولیه.

---

## ⚡ Benchmarks

### `xray-core/testing/benchmarks/protocol_compare_test.go`

یک benchmark مقایسه‌ای واقعی اضافه شد که Reflex را با پروتکل‌های زیر مقایسه می‌کند:
دقت که آیدی های قرار شده یک سری UUID قابل قبول هستند و برای ... VLESS و VMESS متفاوتند.

- Reflex
- VLESS
- VMess
- Trojan

سناریو benchmark:

- `Request + 1KB payload`

---

## ▶️ دستور اجرای Benchmark

دستورها از `docs/testing.md` استخراج شده‌اند:

```bash
cd xray-core

go test -run '^$' -bench BenchmarkProtocolRequestWithPayload1KB -benchmem ./testing/benchmarks

go test -run '^$' -bench BenchmarkProtocolRequestWithPayload1KB -benchmem -count=5 ./testing/benchmarks
```

output:
```=> reflex/xray-core$ go test -run '^$' -bench BenchmarkProtocolRequestWithPayload1KB -benchmem ./testing/benchmarks
goos: linux
goarch: amd64
pkg: github.com/xtls/xray-core/testing/benchmarks
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkProtocolRequestWithPayload1KB/Reflex-20         	 1737727	       683.5 ns/op	1498.09 MB/s	    1168 B/op	       3 allocs/op
BenchmarkProtocolRequestWithPayload1KB/VLESS-20          	 9811322	       119.6 ns/op	8564.55 MB/s	      92 B/op	       5 allocs/op
BenchmarkProtocolRequestWithPayload1KB/VMess-20          	   53119	     21599 ns/op	  47.41 MB/s	   17688 B/op	     160 allocs/op
BenchmarkProtocolRequestWithPayload1KB/Trojan-20         	 9088728	       125.9 ns/op	8136.46 MB/s	      92 B/op	       5 allocs/op
PASS
ok  	github.com/xtls/xray-core/testing/benchmarks	5.855s
```
---

## 📊 توضیح خروجی Benchmark

- **`ns/op`** → زمان متوسط اجرای هر عملیات  
- **`B/op`** → میزان حافظه مصرف‌شده در هر عملیات  
- **`allocs/op`** → تعداد allocation انجام‌شده در هر عملیات

---

## 🔧 نمونه‌های  config

`reflex/server-config.json`

```json
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "reflex",
      "settings": {
        "clients": [
          {
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "policy": "youtube"
          },
          {
            "id": "e5c89a12-3f45-4b6c-9d78-1a2b3c4d5e6f",
            "policy": "zoom"
          }
        ],
        "fallback": {
          "dest": 8080
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
```

`reflex/client-config.json`

```json
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 1080,
      "protocol": "socks",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "reflex",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 8443,
            "users": [
              {
                "id": "b831381d-6324-4d53-ad4f-8cda48b30811"
              }
            ]
          }
        ]
      },
      "tag": "reflex"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "outboundTag": "reflex",
        "ip": ["geoip:private"],
        "invert": true
      }
    ]
  }
}
```

---

## ▶️ اجرای سرور و کلاینت

```bash
# شروع سرور
./xray-core/xray -c server-config.json

# در یک ترمینال دیگر، شروع مشتری
./xray-core/xray -c client-config.json

curl -x socks5://127.0.0.1:1080 https://example.com
```

⚠️ **توجه:**  
```
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to example.com:443
```

این پیش‌بینی می‌شود زیرا certificate برای OpenSSL به مشکل می‌خورد.  

---

## ✅ اجرای تست‌ها

برای اطمینان از درست کار کردن کد، تست‌های زیر را اجرا کنید. تمام دستورات از داخل دایرکتوری `xray-core` اجرا شوند:

```bash
cd xray-core
go test ./tests/reflex_*
go test -cover ./proxy/reflex/...
go test -race ./tests/...
```

### نتایج تست‌های پوشش (Coverage)

```
ok      github.com/xtls/xray-core/proxy/reflex  0.002s  coverage: 96.1% of statements
ok      github.com/xtls/xray-core/proxy/reflex/inbound  2.017s  coverage: 57.7% of statements
ok      github.com/xtls/xray-core/proxy/reflex/outbound 0.003s  coverage: 75.0% of statements
```

---

## 📈 اجرای بنچمارک (Benchmark)
```bash
go test -run '^$' -bench BenchmarkProtocolRequestWithPayload1KB -benchmem ./testing/benchmarks
```
### نتایج بنچمارک (Benchmark)

```
go test -run '^$' -bench BenchmarkProtocolRequestWithPayload1KB -benchmem ./testing/benchmarks
goos: linux
goarch: amd64
pkg: github.com/xtls/xray-core/testing/benchmarks
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkProtocolRequestWithPayload1KB/Reflex-20                 1835884               643.9 ns/op      1590.42 MB/s        1168 B/op       3 allocs/op
BenchmarkProtocolRequestWithPayload1KB/VLESS-20                  9818664               116.9 ns/op      8761.65 MB/s          92 B/op       5 allocs/op
BenchmarkProtocolRequestWithPayload1KB/VMess-20                    55654             22424 ns/op          45.67 MB/s       17691 B/op     160 allocs/op
BenchmarkProtocolRequestWithPayload1KB/Trojan-20                 9310561               128.6 ns/op      7963.45 MB/s          92 B/op       5 allocs/op
PASS
ok      github.com/xtls/xray-core/testing/benchmarks    5.925s
```

---

## ⚠️ چالش‌ها

- آشنایی ناکافی با زبان Go؛ نیاز به یادگیری بیشتر و درک دقیق‌تر از نحوه کار goroutineها که یکی از ویژگی‌های اصلی Go هستند.
- آشنایی محدود با سازوکار پروتکل‌ها به‌صورت کلی؛ تا حدی برای درک پروژه کافی بود اما نیاز به مطالعه عمیق‌تر داشت.
- عدم قطعیت در اینکه چه تست‌هایی باید نوشته شوند و پیاده‌سازی تست‌های لازم (به‌ویژه برای بخش‌هایی که تست نداشتند).
- زمان‌بر بودن تهیه گزارش؛ مشخص نبود دقیقاً چه مقدار و با چه جزئیاتی باید نوشته شود و در نهایت گزارش طولانی‌تر از حد انتظار شد.
- اجرای تست‌ها در مسیر اشتباه: تست‌ها به‌اشتباه در دایرکتوری xray اجرا می‌شدند به‌خاطر این دستور:

```bash
go test ./...
```

مسیر صحیح اجرای تست‌ها: `xray-core/`؛ این اشتباه باعث می‌شد خطاها و FAILهای دایرکتوری‌های دیگر هم لحاظ شوند و زمان زیادی از ما گرفت.