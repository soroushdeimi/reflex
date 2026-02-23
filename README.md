# پروژه Reflex — پیاده‌سازی مرحله‌ای پروتکل Reflex در Xray-Core

## معرفی

این پروژه پیاده‌سازی مرحله‌ای پروتکل **Reflex** در ساختار **Xray-Core** است و مطابق فایل‌های مراحل توسعه داده شده است:

**Basic → Handshake → Encryption(Session/Frame) → Fallback → Advanced (Data + Morphing + QUIC)**

مسیر اصلی کدهای Reflex:

- `xray-core/proxy/reflex/`
  - `config.proto`
  - `config.pb.go` (Generated)
  - `outbound/outbound.go`
  - `inbound/` (کدها و تست‌ها)

---

## 1) اعضای تیم و تقسیم کار

این پروژه به‌صورت **سه‌نفره** انجام شده است:

- **نوید خوش‌کام** — 400108825  
  Step1 (Basic) و Step2 (Handshake)
- **تبسم فتحی** — 400108893  
  Step3 (Encryption / Session)
- **محمدرضا ضیاء** — 400108871  
  Step4 (Fallback) و **پیاده‌سازی Step5 (Advanced)**
- **کار تیمی (هر سه نفر)**  
  **تست‌های Step5** + یکپارچه‌سازی و تست‌های سراسری

---

## شماره دانشجویی

[400108825]

## 2) لیست کامل فایل‌های `xray-core/proxy/reflex/inbound/`

**Implementation**

- `inbound.go`
- `handshake.go`
- `session.go`
- `fallback.go`
- `data.go`
- `morphing.go`
- `quic.go`

**Tests**

- `handshake_test.go`
- `session_test.go`
- `fallback_test.go`
- `morphing_test.go`
- `integration_test.go`
- `edge_cases_test.go`
- `replay_test.go`
- `example_test.go`
- `benchmark_test.go`
- `coverage_test.go`
- `fuzz_test.go`

---

## 3) نگاشت Step → فایل‌ها و تست‌ها

### Step 1 — Basic

**پیاده‌سازی**

- `config.proto`, `config.pb.go`
- `inbound/inbound.go`
- `outbound/outbound.go`

**تست‌ها (سراسری / پوشش مسیرهای پایه)**

- `integration_test.go`: `TestProcessMethod`, `TestProcessPeekError`, `TestNetworkMethod`, `TestMemoryAccountEquals`, `TestMemoryAccountToProto`
- `coverage_test.go`: `TestCoverageProcessPaths`
- `example_test.go` (نمونه‌های اجرا)

**مسئول**: نوید خوش‌کام

---

### Step 2 — Handshake

**پیاده‌سازی**

- `inbound/handshake.go`

**تست‌ها**

- `handshake_test.go`
- `replay_test.go`: `TestTimestampValidationInProcessHandshake`
- `edge_cases_test.go`: `TestInvalidHandshake`, `TestInvalidUUID`, `TestIncompleteHandshake`
- `coverage_test.go`: `TestCoverageHandshakeErrorBranches`
- `integration_test.go`: `TestFormatHTTPResponse`, `TestHandleReflexHTTP`, `TestReadClientHandshakeMagicWithPolicy`, `TestReadClientHandshakeMagicInvalid`
  - (برخی تست‌های handshake در `integration_test.go` با _(Skip)_ علامت‌گذاری شده‌اند: `TestProcessHandshake`, `TestProcessHandshakeInvalidTimestamp`, `TestProcessHandshakeInvalidUser`, `TestHandleReflexMagic`)

**مسئول**: نوید خوش‌کام

---

## شماره دانشجویی

[400108893]

### Step 3 — Encryption (Session/Frame)

**پیاده‌سازی**

- `inbound/session.go`

**تست‌ها**

- `session_test.go`
- `edge_cases_test.go`: `TestEmptyData`, `TestLargeData`, `TestClosedConnection`, `TestConnectionReset`, `TestOversizedPayload`, `TestSessionKeyInvalidLength`, `TestFrameTypeValidation`
- `replay_test.go`: `TestReplayProtectionRejectsReplayedFrame`, `TestNonceUniquenessMonotonicCounters`
- `benchmark_test.go`: `BenchmarkSessionWriteFrame`, `BenchmarkSessionReadFrame`
- `example_test.go`: `ExampleNewSession`, `ExampleSession_WriteFrame`
- `fuzz_test.go`: `FuzzSessionReadFrame`
- `integration_test.go`: `TestSessionWriteReadNonce`, `TestIntegrationHandleSessionEOFStable`, `TestIntegrationHandleSessionInvalidFrameStable`
  - (برخی تست‌های session در `integration_test.go` با _(Skip)_ علامت‌گذاری شده‌اند: `TestHandleSessionWithProfile`, `TestHandleSessionControlFrames`, `TestHandleSessionEOF`, `TestHandleSessionUnknownFrameType`)

**مسئول**: تبسم فتحی

---

## شماره دانشجویی

[400108871]

### Step 4 — Fallback

**پیاده‌سازی**

- `inbound/fallback.go`

**تست‌ها**

- `fallback_test.go`
- `coverage_test.go`: `TestCoverageHandleFallbackRoundTrip`
- `integration_test.go`: `TestProcessWithFallback`, `TestPreloadedConnReadWrite`, `TestIntegrationHandleFallbackCompleteStable`
  - (برخی تست‌های fallback در `integration_test.go` با _(Skip)_ علامت‌گذاری شده‌اند: `TestHandleFallbackComplete`)

**مسئول**: محمدرضا ضیاء

---

### Step 5 — Advanced (Data + Morphing + QUIC)

**پیاده‌سازی**

- `inbound/data.go`
- `inbound/morphing.go`
- `inbound/quic.go`

**مسئول پیاده‌سازی**: محمدرضا ضیاء

**تست‌ها (کار تیمی)**

- `morphing_test.go`
- `integration_test.go`:
  - Parse/Helpers: `TestParseDestinationIPv4`, `TestParseDestinationIPv6`, `TestParseDestinationDomain`, `TestParseDestinationInvalid`, `TestGetDestinationLength`
  - Morphing Controls: `TestWriteFrameChunk`, `TestWriteFrameWithMorphingSplit`, `TestSendPaddingControl`, `TestSendTimingControl`, `TestHandleControlFramePadding`, `TestHandleControlFrameTiming`, `TestGetProfileByName`, `TestCreateProfileFromCapture`
  - Stable-path: `TestAddPaddingTruncate`, `TestWriteFrameWithMorphingNilProfile`, `TestGetPacketSizeDistribution`, `TestGetDelayDistribution`, `TestIntegrationHandleDataWithDestinationStable`, `TestIntegrationHandleDataFrameTypesStable`
  - (برخی تست‌های data در `integration_test.go` با _(Skip)_ علامت‌گذاری شده‌اند: `TestHandleDataWithDestination`, `TestHandleDataFrameTypes`)
- `coverage_test.go`: `TestCoverageHandleDataHappyPath`, `TestCoverageTrafficProfileFallbackBranches`, `TestCoverageHandleDataErrorBranches`
- `benchmark_test.go`: `BenchmarkSessionWriteFrameWithMorphing`
- `fuzz_test.go`: `FuzzParseDestination`

---

---

## 5) شرح انجام مسئولیت‌ها (این‌که هر نفر دقیقاً «چطور» انجام داده)

### 5.1) نوید خوش‌کام — 400108825 (Step1 و Step2)

نوید کار را از **زیرساخت و ورودی پروتکل** شروع کرده و بعد آن را به Handshake رسانده است. روند انجام مسئولیت‌ها:

- **ساخت و اتصال پروتکل به Xray-Core (Step1)**
  - با تعریف کانفیگ Reflex در `config.proto` و تولید کد در `config.pb.go`، ساختار تنظیمات پروتکل را آماده کرده است تا Xray بتواند Reflex را مثل سایر پروتکل‌ها load کند.
  - در `inbound/inbound.go` Handler اصلی را ساخته که نقطه‌ی ورود اتصال است: ساخت Handler از روی config، نگهداری کاربران/Policyها، و تصمیم‌گیری اولیه روی اینکه کانکشن Reflex است یا باید مسیر دیگری طی شود.
  - در `outbound/outbound.go` اسکلت اولیه Outbound را قرار داده تا رجیستر/ساختار outbound هم در پروژه حاضر باشد (حتی اگر منطق اصلی outbound محدود/مینیمال باشد).

- **پیاده‌سازی Handshake (Step2)**
  - در `inbound/handshake.go` مسیر Handshake را به شکل مرحله‌ای پیاده کرده است: خواندن و اعتبارسنجی handshake، احراز هویت UUID، کنترل شرایط نامعتبر/ناقص، و جلوگیری از ورود به Session قبل از موفقیت handshake.
  - کنترل‌های امنیتی این مرحله (مثل رد کردن timestamp‌های خارج از بازه) نیز در همین مسیر لحاظ شده‌اند.

- **تست‌نویسی برای Step2 و پوشش شاخه‌ها**
  - `handshake_test.go` برای سناریوهای اصلی handshake (موفق/ناموفق و ورودی‌های نامعتبر).
  - `edge_cases_test.go` برای حالت‌های خاص handshake:
    - `TestInvalidHandshake`, `TestInvalidUUID`, `TestIncompleteHandshake`
  - `replay_test.go` برای بررسی منطق زمان در handshake:
    - `TestTimestampValidationInProcessHandshake`
  - `coverage_test.go` برای پوشش شاخه‌های خطای handshake:
    - `TestCoverageHandshakeErrorBranches`
  - همچنین در `integration_test.go` برخی تست‌های handshake/parse/format حضور دارند (بخشی skip شده‌اند تا نیاز به اجرای کامل core/timeout نداشته باشند):
    - `TestFormatHTTPResponse`, `TestHandleReflexHTTP`, `TestReadClientHandshakeMagicWithPolicy`, `TestReadClientHandshakeMagicInvalid`

---

### 5.2) تبسم فتحی — 400108893 (Step3)

تبسم مسئول طراحی و پیاده‌سازی **Session رمزنگاری‌شده و فریم‌ها** بوده است. روند انجام مسئولیت‌ها:

- **ساخت Session و Frame برای رمزنگاری (Step3)**
  - در `inbound/session.go` ساختار Session را پیاده کرده است تا ارتباط بعد از handshake وارد فاز امن شود:
    - تعریف FrameTypeها (Data/Padding/Timing/Close)
    - خواندن/نوشتن فریم‌ها (Read/Write) با مدیریت nonce
    - اعتبارسنجی کلید و شرایط نامعتبر برای جلوگیری از خطاهای امنیتی

- **تست‌نویسی برای Session و سناریوهای رمزنگاری**
  - `session_test.go` تست‌های مستقیم read/write و صحت رمزنگاری/رمزگشایی.
  - `edge_cases_test.go` برای سناریوهای خاص session/frame:
    - `TestEmptyData`, `TestLargeData`, `TestClosedConnection`, `TestConnectionReset`,
      `TestOversizedPayload`, `TestSessionKeyInvalidLength`, `TestFrameTypeValidation`
  - `replay_test.go` برای بررسی رفتارهای replay/nonce:
    - `TestReplayProtectionRejectsReplayedFrame`, `TestNonceUniquenessMonotonicCounters`
  - `benchmark_test.go` برای اندازه‌گیری عملکرد مسیرهای اصلی:
    - `BenchmarkSessionWriteFrame`, `BenchmarkSessionReadFrame`
  - `example_test.go` برای نمونه‌های قابل اجرا:
    - `ExampleNewSession`, `ExampleSession_WriteFrame`
  - `fuzz_test.go` برای سخت‌گیری در ورودی‌های خراب:
    - `FuzzSessionReadFrame`
  - بخش‌هایی از `integration_test.go` هم صحت nonce و رفتارهای پایدار را پوشش می‌دهد:
    - `TestSessionWriteReadNonce`, `TestIntegrationHandleSessionEOFStable`, `TestIntegrationHandleSessionInvalidFrameStable`
    - (برخی تست‌های session در integration به‌صورت `Skip` نگه داشته شده‌اند)

---

### 5.3) محمدرضا ضیاء — 400108871 (Step4 و پیاده‌سازی Step5)

محمدرضا هم مسیر **Fallback** را پیاده کرده و هم پیاده‌سازی قابلیت‌های **Advanced** (Step5) را انجام داده است.

- **پیاده‌سازی Fallback (Step4)**
  - در `inbound/fallback.go` مسیر جایگزین را پیاده کرده تا اگر Reflex نبود یا مسیر اصلی شکست خورد، اتصال به مقصد fallback هدایت شود.
  - هدف این بخش جلوگیری از رفتارهای نامشخص/کرش در شرایط خراب و داشتن رفتار قابل پیش‌بینی بوده است.

- **تست‌نویسی مستقیم برای Fallback**
  - `fallback_test.go` برای مسیرهای اصلی fallback.
  - `coverage_test.go` برای پوشش مسیر رفت/برگشت fallback:
    - `TestCoverageHandleFallbackRoundTrip`
  - `integration_test.go` برای پوشش end-to-end و مسیرهای پایدار:
    - `TestProcessWithFallback`, `TestPreloadedConnReadWrite`, `TestIntegrationHandleFallbackCompleteStable`
    - (یک مورد هم در integration با `Skip` مشخص شده: `TestHandleFallbackComplete`)

- **پیاده‌سازی Step5 (Advanced)**
  - در `inbound/data.go` مسیر عبور داده واقعی و پردازش مقصد پیاده‌سازی شده است (parse مقصد و آماده‌سازی مسیر ارسال).
  - در `inbound/morphing.go` رفتارهای Morphing (padding/delay/profile و کنترل‌فریم‌ها) پیاده شده تا الگوی ترافیک قابل کنترل باشد.
  - در `inbound/quic.go` بخش‌های تکمیلی مرتبط با QUIC اضافه شده است.

> نکته: مطابق تقسیم کار، **تست‌های Step5** به‌صورت تیمی نوشته شده‌اند (سه‌نفره)، اما پیاده‌سازی کدهای Step5 با مسئولیت محمدرضا انجام شده است.

---

### 5.4) کار تیمی (هر سه نفر) — تست‌های Step5 و تست‌های سراسری

در بخش Advanced و در کل پروژه، تست‌های سراسری و Step5 به صورت تیمی انجام شده‌اند تا هم پوشش شاخه‌ها بالا برود و هم مسیرهای end-to-end پایدار شوند:

- **تست‌های Step5 (کار تیمی)**
  - `morphing_test.go`
  - `integration_test.go` (تست‌های parseDestination و کنترل‌فریم‌ها و مسیرهای پایدار Step5)
  - `coverage_test.go` برای شاخه‌های data/morphing:
    - `TestCoverageHandleDataHappyPath`, `TestCoverageTrafficProfileFallbackBranches`, `TestCoverageHandleDataErrorBranches`
  - `benchmark_test.go` برای عملکرد morphing:
    - `BenchmarkSessionWriteFrameWithMorphing`
  - `fuzz_test.go` برای سخت‌گیری روی ورودی مقصد:
    - `FuzzParseDestination`

- **تست‌های سراسری**
  - `integration_test.go` و `coverage_test.go` برای افزایش coverage مسیرهای چندمرحله‌ای و جلوگیری از regression

---

## 6) چالش‌ها و مشکلاتی که در پیاده‌سازی با آن‌ها برخورد کردیم و نحوه حل آن‌ها

### 6.1) مشکل در Handshake: رد شدن به‌خاطر Timestamp و Replay

**کجا/چه چیزی؟**  
در پیاده‌سازی Handshake داخل `inbound/handshake.go` و هنگام اجرای تست‌های مربوط به زمان، مثل `TestTimestampValidationInProcessHandshake` (در `replay_test.go`) و برخی سناریوهای `handshake_test.go`.

**مشکل چه بود؟**  
در چند سناریو، Handshake به‌صورت غیرمنتظره reject می‌شد؛ چون اختلاف ساعت سیستم یا ترتیب اجرای تست‌ها باعث می‌شد timestamp خارج از بازه‌ی مجاز تشخیص داده شود و به‌اشتباه به عنوان replay یا درخواست قدیمی رد شود.

**چطور حل شد؟**

- بازه‌ی اعتبارسنجی timestamp در Handshake به‌صورت دقیق‌تر اعمال شد و تست‌ها طوری نوشته شدند که مقدار timestamp را کنترل‌شده تولید کنند (به‌جای تکیه روی زمان واقعی سیستم).
- شاخه‌های خطای handshake نیز با `TestCoverageHandshakeErrorBranches` در `coverage_test.go` پوشش داده شد تا regression در این بخش سریع‌تر مشخص شود.

---

### 6.2) مشکل در Session/Encryption: ناسازگاری Nonce و خطای Decrypt

**کجا/چه چیزی؟**  
در `inbound/session.go` و تست‌هایی مثل `TestSessionWriteReadNonce` (در `integration_test.go`) و `FuzzSessionReadFrame` (در `fuzz_test.go`).

**مشکل چه بود؟**  
در برخی حالت‌ها، nonce طرف خواننده/نویسنده همگام نبود یا به‌خاطر ورودی‌های ناقص/خراب (خصوصاً در fuzz) ReadFrame به خطای decrypt می‌خورد یا در شرایط خاص به مسیرهای غیرمنتظره می‌رفت.

**چطور حل شد؟**

- مدیریت nonce به‌صورت monotonic و با قفل/هماهنگی مناسب انجام شد تا همگام‌سازی read/write پایدار بماند.
- برای ورودی‌های خراب، بررسی‌های طول/نوع فریم و خطاهای قابل پیش‌بینی اضافه شد (و در `edge_cases_test.go` با مواردی مثل `TestSessionKeyInvalidLength` و `TestFrameTypeValidation` تثبیت شد).
- در بنچ‌ها (`BenchmarkSessionWriteFrame`, `BenchmarkSessionReadFrame`) هم فشار اجرا بررسی شد تا تغییرات باعث افت شدید عملکرد نشود.

---

### 6.3) مشکل در Morphing: دو تکه شدن فریم‌ها و رفتار نامطلوب با پروفایل خالی

**کجا/چه چیزی؟**  
در `inbound/morphing.go` و تست‌هایی مثل `TestWriteFrameWithMorphingSplit`, `TestWriteFrameWithMorphingNilProfile` (در `integration_test.go`) و بنچ `BenchmarkSessionWriteFrameWithMorphing` (در `benchmark_test.go`).

**مشکل چه بود؟**  
وقتی پروفایل تعیین نشده بود یا distributionها مقدار خاصی برمی‌گرداندند، ممکن بود اندازه‌ی packet به‌صورت غیرواقعی انتخاب شود و فریم‌ها بی‌دلیل split شوند یا padding نامناسب تولید شود.

**چطور حل شد؟**

- رفتار پیش‌فرض برای حالت nil/ناموجود بودن پروفایل مشخص شد (تست `TestWriteFrameWithMorphingNilProfile`).
- منطق split شدن فریم‌ها برای payloadهای بزرگ‌تر کنترل شد و در تست `TestWriteFrameWithMorphingSplit` صحت آن بررسی شد.
- شاخه‌های خطا/پروفایل در `coverage_test.go` با `TestCoverageTrafficProfileFallbackBranches` پوشش داده شد.

---

### 6.4) مشکل در Data/Parsing مقصد: Panic روی ورودی‌های کوتاه یا خراب

**کجا/چه چیزی؟**  
در `inbound/data.go` (تابع parse مقصد) و تست‌های `TestParseDestinationInvalid` (در `integration_test.go`) و `FuzzParseDestination` (در `fuzz_test.go`).

**مشکل چه بود؟**  
در بعضی ورودی‌های خیلی کوتاه یا malformed، parsing می‌توانست به دسترسی خارج از محدوده یا خطاهای کنترل‌نشده برسد (خصوصاً fuzz این حالت‌ها را سریع پیدا می‌کند).

**چطور حل شد؟**

- قبل از خواندن فیلدها، بررسی طول ورودی و validation اضافه شد تا به جای panic، خطای قابل مدیریت برگشت داده شود.
- تست‌های `TestParseDestinationInvalid` و `TestGetDestinationLength` به‌عنوان guardrail نگه داشته شدند و fuzz به‌عنوان تست سخت‌گیرانه روی همین بخش فعال شد.

---

### 6.5) مشکل در Fallback: بن‌بست (Deadlock) یا نیمه‌باز ماندن اتصال در Round-trip

**کجا/چه چیزی؟**  
در `inbound/fallback.go` و تست‌های `TestProcessWithFallback` و `TestIntegrationHandleFallbackCompleteStable` (در `integration_test.go`) و `TestCoverageHandleFallbackRoundTrip` (در `coverage_test.go`).

**مشکل چه بود؟**  
در سناریوهای copy دوطرفه، اگر یک سمت اتصال زودتر بسته می‌شد یا یک طرف داده نمی‌فرستاد، احتمال گیر کردن goroutineها یا نیمه‌باز ماندن اتصال وجود داشت.

**چطور حل شد؟**

- مسیرهای copy با مدیریت بهتر پایان ارتباط (close) و کنترل خطا/EOF اصلاح شد.
- تست‌های پایدار (stable) برای fallback نگه داشته شدند تا این نوع regressionها سریع مشخص شود.

---

### 6.6) مشکل در تست‌های Integration: نیاز به محیط کامل Xray یا زمان اجرای طولانی

**کجا/چه چیزی؟**  
در `integration_test.go` برخی تست‌ها با _(Skip)_ علامت‌گذاری شده‌اند (مثل `TestProcessHandshake`, `TestHandleSessionWithProfile`, `TestHandleDataWithDestination` و …).

**مشکل چه بود؟**  
برخی تست‌ها برای اجرا نیاز به شرایط کامل‌تر (dispatcher واقعی، محیط شبکه، یا زمان اجرای بیشتر) داشتند و ممکن بود در CI/محیط محدود زمان‌بر یا flaky شوند.

**چطور حل شد؟**

- تست‌های حساس به محیط به‌صورت `Skip` نگه داشته شدند تا اجرای روزمره و CI پایدار بماند.
- در عوض، نسخه‌های stable (مثل `TestIntegrationHandleDataWithDestinationStable` و `TestIntegrationHandleSessionInvalidFrameStable`) اضافه/نگه‌داری شد تا منطق اصلی بدون نیاز به محیط کامل هم تست شود.

## 4) نحوه اجرا (کامل و عملی)

### 4.1) پیش‌نیازها

- **Go** (پیشنهادی: `Go 1.21+`)
  ```bash
  go version
  ```
- **Git**
  ```bash
  git --version
  ```

### 4.3) Build گرفتن

```bash
cd xray-core
go build -o xray ./main
./xray -h
```

### 4.4) اجرای تست‌ها

```bash
cd xray-core
go test ./...
```

برای پوشش و خروجی HTML:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```
