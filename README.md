<div dir="rtl">

# پروژه Reflex - علی زینبی/زینب توانا

## شماره دانشجویی
400108803-400105711
---

## توضیحات
در این پروژه پروتکل <span dir="ltr"><b>Reflex</b></span> را داخل ساختار اصلی <span dir="ltr"><b>Xray-Core</b></span> پیاده‌سازی کردیم (طبق مراحل <span dir="ltr">Step1</span> تا <span dir="ltr">Step5</span>). خلاصه‌ی کارهایی که انجام دادیم:

- ساختار پروژه را دقیقاً مطابق ریپوی اصلی داخل مسیرهای زیر قرار دادیم تا روی ریپوی اصلی <span dir="ltr">compile</span> شود و تست‌ها در پایپلاین اجرا شوند:
  - <span dir="ltr"><code>xray-core/proxy/reflex/...</code></span>
  - <span dir="ltr"><code>xray-core/tests/...</code></span>
- فایل تنظیمات <span dir="ltr"><code>config.proto</code></span> را نوشتیم و با <span dir="ltr"><code>protoc</code></span> کامپایل کردیم تا <span dir="ltr"><code>config.pb.go</code></span> استاندارد تولید شود.
- <span dir="ltr"><b>Handshake</b></span> را پیاده‌سازی کردیم:
  - تشخیص handshake به دو روش: <span dir="ltr">Magic</span> و <span dir="ltr">HTTP POST-like</span>
  - تبادل کلید با <span dir="ltr">X25519</span> و تولید <span dir="ltr">session key</span>
  - پشتیبانی از policy request/grant با <span dir="ltr">PSK</span> مشتق‌شده از <span dir="ltr">UUID</span>
  - محافظت با <span dir="ltr">timestamp</span>/<span dir="ltr">nonce</span> برای کاهش <span dir="ltr">replay</span>
- انتقال دیتا بعد از handshake:
  - فریم‌بندی و <span dir="ltr">read/write</span> فریم‌ها
  - رمزنگاری با <span dir="ltr">ChaCha20-Poly1305</span>
- <span dir="ltr"><b>Fallback</b></span>:
  - با <span dir="ltr"><code>bufio.Peek</code></span> تشخیص می‌دهیم اتصال Reflex هست یا نه
  - اگر نبود، بدون از دست رفتن بایت‌های اولیه، درخواست را به fallback forward می‌کنیم
- قابلیت‌های گام پنجم (امتیازی):
  - <span dir="ltr">Traffic Morphing</span> با پروفایل ترافیک (توزیع اندازه بسته و delay)
  - split کردن دیتا به chunkها
  - پشتیبانی از کنترل‌فریم‌های <span dir="ltr">padding/timing</span> و اعمال <span dir="ltr">delay/padding</span> طبق پروفایل
- تست‌های لازم (handshake/encryption/fallback/integration) را داخل
  <span dir="ltr"><code>xray-core/tests/reflex_test.go</code></span>
  نوشتیم و پاس شدند.

---

## نحوه اجرا

### 1) آماده‌سازی (Protobuf)
اگر لازم بود (مثلاً بعد از تغییر <span dir="ltr"><code>config.proto</code></span>) فایل‌های protobuf را دوباره تولید کنید:

```bash
cd xray-core
protoc --go_out=. --go_opt=paths=source_relative proxy/reflex/config.proto
```

---

### 2) بیلد پروژه
داخل پوشه <span dir="ltr"><code>xray-core</code></span>:

```bash
cd xray-core
go build -o xray ./main
```

---

### 3) اجرای تست‌ها (هدفمند)
داخل پوشه <span dir="ltr"><code>xray-core</code></span>:

```bash
# 1) تست/کامپایل پکیج Reflex
go test ./proxy/reflex/...

# 2) اجرای تست‌های نوشته‌شده برای پروژه
go test ./tests -run "Test" -v
```

<b>نکته:</b> اجرای <span dir="ltr"><code>go test ./...</code></span> ممکن است تست‌های خود xray-core را هم اجرا کند که به assetهای خارجی/شبکه وابسته‌اند و ممکن است لوکال fail شوند. برای پروژه‌ی Reflex همین دو دستور بالا مناسب‌تر است.

---

### 4) اجرای باینری با کانفیگ نمونه (اختیاری)
اگر کانفیگ نمونه در ریشه ریپو باشد:

```bash
cd xray-core
./xray -c ../config.example.json
```

---

## مشکلات و راه‌حل‌ها


### 1) `config.pb.go` دستی بود، نه خروجی protobuf
- <b>مشکل:</b> فایل دستی باعث شد structها protobuf واقعی نباشند و خطای <span dir="ltr"><code>ProtoReflect</code></span> بگیریم.
-  <b>راه‌حل:</b> با <span dir="ltr"><code>protoc</code></span> خروجی استاندارد تولید کردیم و فایل دستی را حذف/جایگزین کردیم.

### 2) ناسازگاری با اینترفیس‌های xray-core (ToProto و Policy)
- <b>مشکل:</b> متد <span dir="ltr"><code>ToProto()</code></span> باید <span dir="ltr"><code>proto.Message</code></span> برگرداند، و <span dir="ltr"><code>MemoryUser</code></span> فیلد <span dir="ltr">Policy</span> ندارد.
-  <b>راه‌حل:</b> امضای <span dir="ltr"><code>ToProto()</code></span> اصلاح شد و policy را در یک ساختار جدا (مثل <span dir="ltr"><code>clientEntry</code></span>) نگه داشتیم.

### 3) Dispatcher: `DialContext` وجود نداشت
- <b>مشکل:</b> از <span dir="ltr"><code>dispatcher.DialContext</code></span> استفاده کرده بودیم ولی در این ریپو وجود نداشت.
- <b>راه‌حل:</b> برای اینکه پروژه build شود، اتصال upstream را فعلاً با <span dir="ltr"><code>net.DialTimeout</code></span> برقرار کردیم.


### 4) تفاوت نام فیلد proto
- <b>مشکل:</b> بعد از generate شدن protobuf، نام فیلد <span dir="ltr"><code>UseHTTPHandshake</code></span> به <span dir="ltr"><code>UseHttpHandshake</code></span> تغییر کرد و build fail شد.
-  <b>راه‌حل:</b> همه‌ی استفاده‌ها در outbound و تست‌ها هماهنگ شد.

### 5) fail شدن `TestFallback` با timeout
- <b>مشکل:</b> خطای <span dir="ltr"><code>read pipe: i/o timeout</code></span> چون سرور fallback منتظر EOF می‌ماند.
- <b>راه‌حل:</b> منطق fallback را با حفظ بایت‌های peek شده و forward سریع + مدیریت جریان اصلاح کردیم تا پاسخ به موقع برسد.


---

</div>