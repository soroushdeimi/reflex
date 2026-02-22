# پروژه Reflex - دیانا بابایی

## اعضای تیم

 دیانا بابایی 400171324 
 
 رضوان حسین‌نژاد  400108814 
 
 امین هاشمی  400109208 


## توضیحات

در این پروژه پروتکل جدید **Reflex** را روی **Xray-Core** پیاده‌سازی کردیم. هدف، ساخت یک پروتکل پراکسی است که ترافیک آن غیرقابل تشخیص باشد و با رمزنگاری قوی و مخفی‌سازی ترافیک، محدودیت‌های پروتکل‌های قبلی مثل VMess و VLESS را کاهش دهد.

### کارهای انجام‌شده:
- ساختار پایه پکیج Reflex در Xray-Core
- Handshake و احراز هویت با X25519 ECDH
- رمزنگاری فریم‌ها با ChaCha20-Poly1305
- مکانیزم Fallback به وب‌سرور
- Traffic Morphing با ۳ پروفایل (YouTube, Zoom, HTTP/2 API)
- 7 تست در xray-core/tests/ و تست‌های واحد در proxy/reflex/

### Bonus:
- ۳ پروفایل Morphing با توزیع اندازه بسته و تاخیر متفاوت
- Random Nonce برای جلوگیری از replay attack
- Poly1305 Authentication Tag برای tamper detection
- Fallback که سرور را شبیه HTTP سرور عادی نشان می‌دهد

## نحوه اجرا

### بیلد
```bash
cd xray-core
go build -o xray ./main/
```

### اجرای سرور و کلاینت
```bash
# ترمینال 1 - سرور
cd xray-core
./xray -c ../reflex-server-test.json

# ترمینال 2 - کلاینت
cd xray-core
./xray -c ../reflex-client-test.json

# ترمینال 3 - تست
curl -x socks5://127.0.0.1:10003 http://example.com
```

### اجرای تست‌ها
```bash
cd xray-core
go test ./tests/... -v
go test ./proxy/reflex/... -v
```

## مشکلات و راه‌حل‌ها

**مشکل: تونل برقرار می‌شد ولی ترافیک به سایت واقعی نمی‌رسید**
تونل بین کلاینت و سرور برقرار می‌شد (اتصال TCP موفق)، اما درخواست‌ها به مقصد واقعی ارسال نمی‌شدند. مشکل در routing سرور بود — outbound روی `freedom` تنظیم نشده بود و ترافیک پس از decrypt شدن جایی برای رفتن نداشت. راه‌حل: اضافه کردن outbound با protocol `freedom` و routing rule در config سرور.

**مشکل: Firefox با SOCKS5 کار نمی‌کند (400 Bad Request)**
راه‌حل:فکر میکنم این محدودیت Firefox است، نه Reflex. curl بدون مشکل کار می‌کنند.


---

## مراحل پیاده‌سازی

| مرحله | توضیح | فایل |
|------|-------|------|
| **1** | ساختار اولیه | `xray-core/proxy/reflex/` |
| **2** | احراز هویت & Handshake | `encoding/handshake.go` |
| **3** | رمزنگاری & فریم‌ها | `encoding/frame.go` |
| **4** | Fallback | `inbound/inbound.go` |
| **5** | Traffic Morphing | `encoding/morphing.go` |

---

## مستندات

- [گزارش پیاده‌سازی](REPORT.md)
- [راهنمای اجرا](RUN_GUIDE_FA.md)
- [نمونه کانفیگ](config.example.json)
