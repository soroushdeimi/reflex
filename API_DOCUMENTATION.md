# مستندات فنی و API پروتکل Reflex

این مستند شامل جزئیات پیکربندی JSON، ساختار فریم‌ها و توابع کلیدی پیاده‌سازی شده در زبان Go است.

## ۱. تنظیمات JSON (Configuration)

### Inbound (ورودی سرور)
تنظیمات در بخش `inbounds` در آرایه `settings` قرار می‌گیرد.

| فیلد | نوع | توضیح |
| :--- | :--- | :--- |
| `clients` | Array | لیستی از کاربران مجاز. |
| `fallback` | Object | تنظیمات هدایت ترافیک غیرمجاز. |
| `tls` | Object | تنظیمات امنیتی TLS و ECH. |

#### ساختار User
- `id`: (رشته) UUID منحصر به فرد کاربر.
- `policy`: (رشته) نام پروفایل مورفینگ (`youtube`, `streaming`, `web` یا خالی).

#### ساختار Fallback
- `dest`: (عدد) پورت مقصد روی localhost (مثلاً 80).

### Outbound (خروجی کلاینت)
تنظیمات در بخش `outbounds` قرار می‌گیرد.

| فیلد | نوع | توضیح |
| :--- | :--- | :--- |
| `address` | String | آدرس IP یا دامنه سرور. |
| `port` | Number | پورت سرور (معمولاً 443). |
| `id` | String | UUID کاربر (باید با سرور یکی باشد). |
| `tls` | Object | تنظیمات TLS و ECH کلاینت. |

### تنظیمات TLS (مشترک)
- `enabled`: (بولین) فعال یا غیرفعال کردن TLS.
- `server_name`: (رشته) SNI مورد استفاده در هندشیک.
- `ech_key`: (رشته) کلید ECH به صورت Base64 (در سرور KeySet و در کلاینت ConfigList).
- `cert_file`: (رشته) مسیر فایل گواهی (فقط سرور).
- `key_file`: (رشته) مسیر فایل کلید خصوصی (فقط سرور).

---

## ۲. ساختار فریم‌های پروتکل (Frame Structure)

هر فریم در پروتکل Reflex از بخش‌های زیر تشکیل شده است:

1.  **Header (3 bytes):**
    - `Length` (2 bytes): طول کل بخش رمزنگاری شده (Big Endian).
    - `Type` (1 byte): نوع فریم.
        - `0x01`: DATA (داده‌های کاربر)
        - `0x02`: PADDING_CTRL (کنترل پدینگ)
        - `0x03`: TIMING_CTRL (کنترل تاخیر)
        - `0x04`: CLOSE (بستن اتصال)
2.  **Encrypted Payload:**
    - محتوای رمزنگاری شده با الگوریتم ChaCha20-Poly1305.
    - در فریم‌های DATA، محتوای رمزگشایی شده شامل ۲ بایت اول برای تعیین طول واقعی داده و سپس خود داده و پدینگ است.

---

## ۳. توابع کلیدی در کد Go

### پکیج `proxy/reflex`

#### `GenerateKeyPair() ([]byte, []byte, error)`
تولید یک جفت کلید عمومی و خصوصی X25519 برای تبادل کلید (Diffie-Hellman).

#### `DeriveSharedKey(priv, pub []byte) []byte`
محاسبه کلید مشترک (Shared Secret) با استفاده از کلید خصوصی خودی و کلید عمومی طرف مقابل.

#### `DeriveSessionKeys(shared, info []byte) ([]byte, []byte)`
استخراج کلیدهای نشست (C2S و S2C) با استفاده از تابع HKDF برای اطمینان از امنیت و منحصر به فرد بودن کلیدهای هر جهت.

#### `NewSession(readKey, writeKey []byte) (*Session, error)`
ایجاد یک نشست جدید که مدیریت رمزنگاری (AEAD) و شمارنده نانس (Nonce Counter) را برای جلوگیری از Replay Attack بر عهده دارد.

#### `(s *Session) ReadFrame(reader io.Reader) (*Frame, error)`
خواندن یک فریم کامل از استریم، رمزگشایی آن و جدا کردن داده‌های اصلی از پدینگ.

#### `(s *Session) WriteFrameWithMorphing(writer io.Writer, type, data, profile)`
ارسال داده‌ها با اعمال پروفایل مورفینگ. این تابع داده‌ها را به تکه‌های کوچک‌تر تقسیم کرده، پدینگ تصادفی اضافه می‌کند و بین ارسال هر تکه تاخیر زمانی ایجاد می‌کند.

#### `HandleControlFrame(frame, profile)`
پردازش فریم‌های کنترلی برای تغییر داینامیک رفتار مورفینگ در طول یک نشست برقرار شده.
