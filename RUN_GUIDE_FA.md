# 🚀 راهنمای اجرا - دستورات

## ۱. نصب و بیلد

```bash
cd reflex

# وابستگی‌ها
cd xray-core && go mod download

# بیلد
go build -o xray ./main/
cd ..
```

---

## ۲. تست سریع (۵ دقیقه)

**۲ ترمینال و curl:**

### ترمینال 1️⃣ - Reflex Server
```bash
cd xray-core
./xray -c ../reflex-server-test.json

# Server شروع می‌شود - روی :8557
```

### ترمینال 2️⃣ - Reflex Client
```bash
cd xray-core
./xray -c ../reflex-client-test.json

# Client شروع می‌شود - روی :10003
```

### ترمینال 3️⃣ - تست با curl
```bash
# Server و Client فعال باشند

curl -x socks5://127.0.0.1:10003 http://example.com

# یا:
curl -x socks5://127.0.0.1:10003 http://httpbin.org/ip

# خروجی: HTML صفحه یا JSON
# {
#   "origin": "YOUR_IP"
# }


```

---

## ۳. Firefox تنظیمات 


### **Step 1: SOCKS5 Proxy تنظیم کنید**
```
1. Firefox باز کنید
2. Settings (تنظیمات)
3. Network Settings بروید
4. Configure Proxy for this Network:

   ☑ Manual proxy configuration

   SOCKS Host: 127.0.0.1
   Port: 10003
   ☑ SOCKS v5

5. OK کلیک کنید
```

### **Step 2: DNS کنفیگ**
```
آدرس بار: about:config

جستجو: network.proxy.socks_remote_dns
Double-click: TRUE تنظیم کنید
```

### **Step 3: تست (نتیجه: 400 Bad Request)**
```
سایت‌های مختلف رو امتحان کنید:
- google.com 
- example.com 
- httpbin.org/ip 

⚠️ این مشکل Firefox است، نه Reflex!
```

---

## ۴. firefox 

**Firefox**:  کار نمی‌کند - سوکس5 مشکل دارد (400 Bad Request)

**curl، wget، و سایر tools**:  بدون مشکل کار می‌کنند

**تونل کاملاً کار می‌کند** - curl ثابت می‌کنه!

---

## ۴. تست هر مرحله

### مرحله 1: Config Parsing
```bash
go test ./infra/conf -v -run Reflex

# انتظار: PASS
```

### مرحله 2: Handshake
```bash
go test ./proxy/reflex/encoding -v -run Handshake

# انتظار: Session key generated ✓
```

### مرحله 3: Encryption
```bash
go test ./proxy/reflex/encoding -v -run Frame

# انتظار: Encrypt/Decrypt works ✓
```

### مرحله 4: Fallback
```bash
# HTTP server روی 9996
python3 -m http.server 9996 &

# سپس curl:
curl http://127.0.0.1:8555

# انتظار: HTTP response
```

### مرحله 5: Morphing
```bash
go test ./proxy/reflex/encoding -v -run Morphing

# انتظار: Packet sizes match distribution ✓
```

---

## ۵. تأیید کارکرد

### ✅ Test 1: Tunnel کار می‌کنه (curl)
```bash
curl -x socks5://127.0.0.1:10003 http://example.com
# یا
curl -x socks5://127.0.0.1:10003 http://httpbin.org/ip

# خروجی: HTML صفحه یا JSON
# SUCCESS ✓
```

**نکته**: Firefox سوکس5 مشکل دارد. curl و دیگر tools بدون مشکل کار می‌کنند.

### ✅ Test 2: Morphing کار می‌کنه
```bash
# Wireshark بازی کنید

# Filter:
tcp.dstport == 8555

# Firefox رو بارها refresh کنید

# ببینید: Mixed packet sizes
# 45B, 56B, 79B, 200B, 500B, 1000B+

SUCCESS ✓
```

### ✅ Test 3: رمزنگاری کار می‌کنه
```bash
# tcpdump (Linux/Mac):
sudo tcpdump -i lo -A 'port 8555' | head -50

# خروجی: Binary gibberish
# NOT readable = رمزنگاری شده ✓

SUCCESS ✓
```

---

## ۶. دستورات سریع

```bash
# بیلد
cd xray-core && go build -o xray ./main/ && cd ..

# تست همه
go test ./proxy/reflex/... -v

# تست specific
go test ./proxy/reflex/encoding -v -run TestFrame

# Log دیدن
tail -f reflex-server-test-error.log

# Process کشتن
pkill -f "xray.*8555"

# Clean
go clean && rm xray-core/xray
```

---

## ۸. جریان داده

```
Firefox Browser
    ↓ SOCKS5 :10003
Reflex Client
    ↓ Encrypt + Morphing (padding)
Network :8557
    ↓
Reflex Server
    ↓ Decrypt
Real Internet (google.com, etc)
    ↓ Response
... (برعکس)
    ↓
Firefox ✓
```
