# Step 5: قابلیت‌های پیشرفته

این مرحله اجباریه و 25 نمره داره (15 نمره برای قابلیت‌های اجباری + 5 نمره امتیازی برای قابلیت‌های اضافی). باید Traffic Morphing رو پیاده‌سازی کنی و می‌تونی یکی از قابلیت‌های پیشرفته دیگه رو هم اضافه کنی.

## Traffic Morphing: هنر فریب

ایده اصلی اینه که ترافیک رو طوری شکل بدی که شبیه یه پروتکل بی‌خطر (مثلاً YouTube، Zoom، یا یه REST API) به نظر برسه. این فقط padding ساده نیست - باید توزیع آماری اندازه بسته‌ها و timing رو هم تقلید کنی.

### چرا Traffic Morphing مهمه؟

یه ناظر می‌تونه با تحلیل آماری ترافیک (Website Fingerprinting)، بفهمه که این ترافیک پراکسی هست. این تحلیل بر اساس:
- **توزیع اندازه بسته‌ها**: پراکسی‌ها معمولاً بسته‌های با اندازه‌های خاصی دارن
- **الگوهای timing**: فاصله زمانی بین بسته‌ها
- **جهت ترافیک**: نسبت آپلود به دانلود

برای فریب دادن، باید این ویژگی‌های آماری رو طوری تغییر بدی که شبیه پروتکل هدف باشه.

### چرا padding ساده کافی نیست؟

Padding تصادفی یه توزیع یکنواخت ایجاد می‌کنه که خیلی متفاوت از توزیع واقعی پروتکل‌هاست. یه ناظر می‌تونه با تحلیل آماری بفهمه که padding تصادفی هست. برای فریب دادن، باید توزیع آماری واقعی پروتکل هدف رو تقلید کنی.

### پیاده‌سازی پیشرفته

```go
import (
    "encoding/binary"
    "io"
    "math/rand"
    "sort"
    "sync"
    "time"
)

type TrafficProfile struct {
    Name        string
    // توزیع اندازه بسته‌ها (با احتمال)
    PacketSizes []PacketSizeDist
    // توزیع تأخیرها (با احتمال)
    Delays      []DelayDist
    nextPacketSize int  // برای override موقت
    nextDelay       time.Duration  // برای override موقت
    mu              sync.Mutex
}

type PacketSizeDist struct {
    Size     int     // اندازه بسته
    Weight   float64 // وزن (احتمال)
}

type DelayDist struct {
    Delay    time.Duration
    Weight   float64
}

var Profiles = map[string]TrafficProfile{
    "youtube": {
        Name: "YouTube",
        PacketSizes: []PacketSizeDist{
            {Size: 1400, Weight: 0.4},  // 40% احتمال
            {Size: 1200, Weight: 0.3},
            {Size: 1000, Weight: 0.2},
            {Size: 800, Weight: 0.1},
        },
        Delays: []DelayDist{
            {Delay: 10 * time.Millisecond, Weight: 0.5},
            {Delay: 20 * time.Millisecond, Weight: 0.3},
            {Delay: 30 * time.Millisecond, Weight: 0.2},
        },
    },
    "zoom": {
        Name: "Zoom",
        PacketSizes: []PacketSizeDist{
            {Size: 500, Weight: 0.3},
            {Size: 600, Weight: 0.4},
            {Size: 700, Weight: 0.3},
        },
        Delays: []DelayDist{
            {Delay: 30 * time.Millisecond, Weight: 0.4},
            {Delay: 40 * time.Millisecond, Weight: 0.4},
            {Delay: 50 * time.Millisecond, Weight: 0.2},
        },
    },
    "http2-api": {
        Name: "HTTP/2 API",
        PacketSizes: []PacketSizeDist{
            {Size: 200, Weight: 0.2},
            {Size: 500, Weight: 0.3},
            {Size: 1000, Weight: 0.3},
            {Size: 1500, Weight: 0.2},
        },
        Delays: []DelayDist{
            {Delay: 5 * time.Millisecond, Weight: 0.3},
            {Delay: 10 * time.Millisecond, Weight: 0.4},
            {Delay: 15 * time.Millisecond, Weight: 0.3},
        },
    },
}

// انتخاب اندازه بسته بر اساس توزیع (یا override)
func (p *TrafficProfile) GetPacketSize() int {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // اگه override شده، از اون استفاده کن
    if p.nextPacketSize > 0 {
        size := p.nextPacketSize
        p.nextPacketSize = 0  // reset بعد از استفاده
        return size
    }
    
    // در غیر این صورت از توزیع استفاده کن
    r := rand.Float64()
    cumsum := 0.0
    
    for _, dist := range p.PacketSizes {
        cumsum += dist.Weight
        if r <= cumsum {
            return dist.Size
        }
    }
    
    return p.PacketSizes[len(p.PacketSizes)-1].Size
}

// انتخاب تأخیر بر اساس توزیع (یا override)
func (p *TrafficProfile) GetDelay() time.Duration {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // اگه override شده، از اون استفاده کن
    if p.nextDelay > 0 {
        delay := p.nextDelay
        p.nextDelay = 0  // reset بعد از استفاده
        return delay
    }
    
    // در غیر این صورت از توزیع استفاده کن
    r := rand.Float64()
    cumsum := 0.0
    
    for _, dist := range p.Delays {
        cumsum += dist.Weight
        if r <= cumsum {
            return dist.Delay
        }
    }
    
    return p.Delays[len(p.Delays)-1].Delay
}

// اضافه کردن padding برای رسیدن به اندازه هدف
func (s *Session) AddPadding(data []byte, targetSize int) []byte {
    if len(data) >= targetSize {
        // اگه بزرگتر بود، split کن (یا truncate کن)
        return data[:targetSize]
    }
    
    padding := make([]byte, targetSize-len(data))
    rand.Read(padding) // padding تصادفی
    
    return append(data, padding...)
}
```

### استفاده در Session

```go
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
    // انتخاب اندازه هدف بر اساس پروفایل
    targetSize := profile.GetPacketSize()
    
    // اگه داده بزرگتر از targetSize بود، split کن
    if len(data) > targetSize {
        // ارسال اولین بخش
        firstChunk := data[:targetSize]
        if err := s.writeFrameChunk(writer, frameType, firstChunk, profile); err != nil {
            return err
        }
        
        // ارسال بقیه داده‌ها
        remaining := data[targetSize:]
        return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
    }
    
    // اضافه کردن padding
    morphedData := s.AddPadding(data, targetSize)
    
    // رمزنگاری
    nonce := make([]byte, 12)
    binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
    s.writeNonce++
    
    encrypted := s.aead.Seal(nil, nonce, morphedData, nil)
    
    // نوشتن frame
    header := make([]byte, 3)
    binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
    header[2] = frameType
    
    writer.Write(header)
    writer.Write(encrypted)
    
    // اعمال تأخیر بر اساس پروفایل
    delay := profile.GetDelay()
    time.Sleep(delay)
    
    return nil
}

func (s *Session) writeFrameChunk(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
    return s.WriteFrameWithMorphing(writer, frameType, data, profile)
}
```

### یکپارچه‌سازی با Frame‌های PADDING_CTRL و TIMING_CTRL

در پروتکل Reflex، Frame‌های `PADDING_CTRL` و `TIMING_CTRL` برای کنترل شکل‌دهی ترافیک استفاده می‌شن. می‌تونی از این Frame‌ها برای هماهنگ کردن شکل‌دهی بین کلاینت و سرور استفاده کنی:

```go
// ارسال دستور padding به طرف مقابل
func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
    // باید FrameTypePadding و FrameTypeTiming تعریف شده باشن
    ctrlData := make([]byte, 2)
    binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))
    
    return s.WriteFrame(writer, FrameTypePadding, ctrlData)
}

// ارسال دستور timing به طرف مقابل
func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
    ctrlData := make([]byte, 8)
    binary.BigEndian.PutUint64(ctrlData, uint64(delay.Milliseconds()))
    
    return s.WriteFrame(writer, FrameTypeTiming, ctrlData)
}

// متدهای کنترلی برای TrafficProfile
func (p *TrafficProfile) SetNextPacketSize(size int) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.nextPacketSize = size
}

func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.nextDelay = delay
}

// پردازش Frame‌های کنترلی
func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
    switch frame.Type {
    case FrameTypePadding:
        // طرف مقابل می‌خواد padding اضافه کنی
        targetSize := int(binary.BigEndian.Uint16(frame.Payload))
        profile.SetNextPacketSize(targetSize)
        
    case FrameTypeTiming:
        // طرف مقابل می‌خواد تأخیر اضافه کنی
        delayMs := binary.BigEndian.Uint64(frame.Payload)
        profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
    }
}
```

### استخراج پروفایل از ترافیک واقعی

برای ساخت پروفایل‌های دقیق، باید از ترافیک واقعی استفاده کنی. این کار خیلی مهمه - اگه پروفایل‌ها دقیق نباشن، morphing کار نمی‌کنه:

**روش استخراج**:
1. با Wireshark یا tcpdump ترافیک واقعی رو capture کن (مثلاً YouTube یا Zoom)
2. اندازه بسته‌ها و فاصله زمانی بینشون رو استخراج کن
3. هیستوگرام بساز و توزیع آماری رو محاسبه کن
4. از Kolmogorov-Smirnov test استفاده کن تا مطمئن بشی توزیع درسته

**مثال با pcap**:
```bash
# Capture ترافیک
tcpdump -i eth0 -w youtube.pcap host youtube.com

# استخراج اندازه بسته‌ها
tshark -r youtube.pcap -T fields -e frame.len > packet_sizes.txt

# تحلیل با Python یا Go
# محاسبه توزیع و ساخت پروفایل
```

**شواهد آماری**: برای اثبات اینکه morphing کار می‌کنه، باید:
- هیستوگرام ترافیک morph شده رو با ترافیک واقعی مقایسه کنی
- از KS-test استفاده کنی تا ببینی آیا توزیع‌ها مشابه هستن یا نه
- نتایج رو در PR ضمیمه کنی

```go
// تست آماری با KS-test
func TestMorphingStatistical(t *testing.T) {
    // تولید ترافیک morph شده
    morphedSizes := generateMorphedTraffic(YouTubeProfile, 1000)
    
    // مقایسه با توزیع واقعی
    ksStat := kolmogorovSmirnovTest(morphedSizes, realYouTubeSizes)
    
    // KS-test: p-value باید > 0.05 باشه (یعنی توزیع‌ها مشابه هستن)
    if ksStat.PValue < 0.05 {
        t.Fatal("morphing failed: distributions are different")
    }
}
```

برای ساخت پروفایل‌های دقیق:

```go
// تحلیل ترافیک با Wireshark یا tcpdump
// بعد از تحلیل، می‌تونی پروفایل بسازی:

func CreateProfileFromCapture(packetSizes []int, delays []time.Duration) *TrafficProfile {
    // محاسبه توزیع اندازه بسته‌ها
    sizeDist := calculateSizeDistribution(packetSizes)
    
    // محاسبه توزیع تأخیرها
    delayDist := calculateDelayDistribution(delays)
    
    return &TrafficProfile{
        PacketSizes: sizeDist,
        Delays: delayDist,
    }
}

func calculateSizeDistribution(values []int) []PacketSizeDist {
    // شمارش فراوانی هر مقدار
    freq := make(map[int]int)
    for _, v := range values {
        freq[v]++
    }
    
    // تبدیل به توزیع احتمال
    total := len(values)
    dist := make([]PacketSizeDist, 0, len(freq))
    
    for size, count := range freq {
        dist = append(dist, PacketSizeDist{
            Size: size,
            Weight: float64(count) / float64(total),
        })
    }
    
    // مرتب‌سازی بر اساس اندازه
    sort.Slice(dist, func(i, j int) bool {
        return dist[i].Size < dist[j].Size
    })
    
    return dist
}

func calculateDelayDistribution(values []time.Duration) []DelayDist {
    // شمارش فراوانی هر مقدار
    freq := make(map[time.Duration]int)
    for _, v := range values {
        freq[v]++
    }
    
    // تبدیل به توزیع احتمال
    total := len(values)
    dist := make([]DelayDist, 0, len(freq))
    
    for delay, count := range freq {
        dist = append(dist, DelayDist{
            Delay: delay,
            Weight: float64(count) / float64(total),
        })
    }
    
    // مرتب‌سازی بر اساس تأخیر
    sort.Slice(dist, func(i, j int) bool {
        return dist[i].Delay < dist[j].Delay
    })
    
    return dist
}
```

### مثال عملی: تقلید از YouTube

```go
// پروفایل YouTube بر اساس تحلیل ترافیک واقعی
var YouTubeProfile = TrafficProfile{
    Name: "YouTube",
    PacketSizes: []PacketSizeDist{
        {Size: 1400, Weight: 0.35},  // بیشتر بسته‌ها MTU size هستن
        {Size: 1200, Weight: 0.25},
        {Size: 1000, Weight: 0.20},
        {Size: 800, Weight: 0.10},
        {Size: 600, Weight: 0.05},
        {Size: 400, Weight: 0.05},
    },
    Delays: []DelayDist{
        {Delay: 8 * time.Millisecond, Weight: 0.30},   // تأخیر کم برای streaming
        {Delay: 12 * time.Millisecond, Weight: 0.25},
        {Delay: 16 * time.Millisecond, Weight: 0.20},
        {Delay: 20 * time.Millisecond, Weight: 0.15},
        {Delay: 30 * time.Millisecond, Weight: 0.10},
    },
}

// استفاده در Session
func (s *Session) StartYouTubeMorphing() {
    s.profile = &YouTubeProfile
    s.morphingEnabled = true
}
```

## TLS با ECH: پنهان‌سازی SNI

Encrypted Client Hello (ECH) یه افزونه TLS 1.3 هست که SNI (Server Name Indication) رو رمزنگاری می‌کنه. این یعنی سانسورچی نمی‌تونه ببینه به کدوم دامنه وصل می‌شی.

### چرا ECH مهمه؟

بدون ECH، وقتی به یه سرور TLS وصل می‌شی، SNI در plaintext ارسال می‌شه. سانسورچی می‌تونه ببینه که به `example.com` وصل می‌شی و اگه این دامنه block شده باشه، اتصال رو قطع کنه.

با ECH، SNI رمزنگاری می‌شه و سانسورچی فقط یه SNI عمومی (public SNI) می‌بینه که معمولاً یه دامنه بی‌خطر هست.

### استفاده در Go

اگه Go 1.25+ داری، می‌تونی از ECH استفاده کنی:

```go
import (
    "crypto/tls"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
)

func setupTLSWithECH() (*tls.Config, error) {
    // ساخت کلید ECH (X25519)
    echPrivateKey, err := generateECHKey()
    if err != nil {
        return nil, err
    }
    
    // ساخت ECHConfig
    echConfig, err := createECHConfig(echPrivateKey)
    if err != nil {
        return nil, err
    }
    
    config := &tls.Config{
        EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
            {
                Config: echConfig,
                PrivateKey: echPrivateKey,
            },
        },
        // SNI عمومی (fake SNI)
        ServerName: "cloudflare.com", // یا هر دامنه بی‌خطر دیگه
    }
    
    return config, nil
}

func generateECHKey() (interface{}, error) {
    // برای ECH معمولاً از X25519 استفاده می‌شه
    // اینجا یه مثال ساده با ECDSA (در واقع باید X25519 باشه)
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    return key, err
}
```

**نکته**: پیاده‌سازی کامل ECH در Go 1.25+ نیاز به کتابخانه‌های اضافی داره. می‌تونی از `github.com/cloudflare/circl` استفاده کنی.

### یکپارچه‌سازی با Reflex

می‌تونی TLS رو به عنوان لایه انتقال استفاده کنی. این یعنی:

1. اول TLS handshake (با ECH) انجام می‌شه
2. بعد Reflex handshake (ضمنی) روی TLS connection انجام می‌شه
3. بعد Frame‌های رمزنگاری شده ارسال می‌شن

```go
import (
    "bufio"
    "encoding/binary"
    "crypto/tls"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/transport/internet/stat"
    "github.com/xtls/xray-core/features/routing"
)

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
    // اگه TLS فعال بود، اول TLS handshake رو انجام بده
    if h.config.TLS != nil && h.tlsConfig != nil {
        tlsConn := tls.Server(conn, h.tlsConfig)
        if err := tlsConn.Handshake(); err != nil {
            return err
        }
        // تبدیل tls.Conn به stat.Connection
        // توجه: در واقعیت باید از stat.WrapConnection استفاده کنی:
        // conn = stat.WrapConnection(tlsConn)
        // یا می‌تونی مستقیماً از tlsConn استفاده کنی اگه stat.Connection interface رو implement کنه
        conn = stat.Connection(tlsConn) // این cast ممکنه کار نکنه - باید wrapper استفاده کنی
    }
    
    // حالا بقیه منطق مثل قبل (peek و تشخیص پروتکل)
    // اینجا باید منطق اصلی Process رو صدا بزنی که در Step 4 تعریف شده
    reader := bufio.NewReader(conn)
    peeked, err := reader.Peek(ReflexMinHandshakeSize)
    if err != nil {
        return err
    }
    
    // منطق تشخیص پروتکل (مثل step4)
    if len(peeked) >= 4 {
        magic := binary.BigEndian.Uint32(peeked[0:4])
        if magic == ReflexMagic {
            return h.handleReflexMagic(reader, conn, dispatcher, ctx)
        }
    }
    if h.isHTTPPostLike(peeked) {
        return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
    }
    return h.handleFallback(ctx, reader, conn)
}
```

این یعنی Reflex می‌تونه روی vanilla TCP یا TLS (با ECH) کار کنه. انتخاب با توئه.

## QUIC Transport: عملکرد و پنهان‌کاری

QUIC یه پروتکل انتقال مدرن روی UDP هست که مزایای زیادی داره:
- **بدون head-of-line blocking**: اگه یه بسته گم بشه، بقیه بسته‌ها منتظر نمی‌مونن
- **Handshake سریعتر**: 0-RTT و 1-RTT handshake
- **Connection Migration**: می‌تونی اتصال رو migrate کنی بدون قطع شدن

### استفاده از quic-go

می‌تونی از کتابخانه `github.com/quic-go/quic-go` استفاده کنی:

```go
import (
    "github.com/quic-go/quic-go"
    "crypto/tls"
)

func setupQUICListener(addr string, tlsConfig *tls.Config) (net.Listener, error) {
    // QUIC نیاز به TLS داره (حتی برای UDP)
    listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{
        MaxIdleTimeout: 30 * time.Second,
        KeepAlivePeriod: 10 * time.Second,
    })
    if err != nil {
        return nil, err
    }
    
    return listener, nil
}

// Accept کردن اتصالات QUIC
func acceptQUICConnections(listener net.Listener) {
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        
        // conn از نوع quic.Connection هست
        go handleQUICConnection(conn)
    }
}
```

### Connection Migration: تکنیک QUICstep

یه تکنیک جالب برای دور زدن سانسور اینه که:

1. **اتصال اولیه** از یه کانال بی‌خطر (مثلاً domain fronting یا پراکسی دیگه) برقرار می‌شه
2. **Handshake Reflex** روی این اتصال انجام می‌شه
3. **بعد از برقراری سِشِن**، سرور به کلاینت دستور می‌ده که اتصال QUIC رو به مسیر مستقیم (IP واقعی سرور) migrate کنه
4. **سانسورچی** فقط اتصال اولیه بی‌خطر رو می‌بینه و بعد از اون، جریان ترافیک QUIC رو می‌بینه که فاقد هرگونه handshake با متن آشکار هست

```go
type QUICSession struct {
    conn quic.Connection
    stream quic.Stream
    migrated bool
}

func (s *QUICSession) MigrateToDirect(serverAddr string) error {
    // قطع اتصال قدیمی
    s.conn.CloseWithError(0, "migrating")
    
    // برقراری اتصال جدید به IP مستقیم
    tlsConfig := &tls.Config{
        // استفاده از کلیدهای سِشِن قبلی
    }
    
    newConn, err := quic.DialAddr(serverAddr, tlsConfig, &quic.Config{
        // استفاده از connection ID قبلی برای migration
    })
    if err != nil {
        return err
    }
    
    // انتقال state (کلیدهای سِشِن، nonce‌ها، و غیره)
    s.conn = newConn
    s.migrated = true
    
    return nil
}
```

**نکته**: Connection Migration در QUIC نیاز به حفظ Connection ID داره. باید مطمئن بشی که Connection ID در migration حفظ می‌شه.

### یکپارچه‌سازی با Reflex

برای استفاده از QUIC با Reflex:

1. QUIC listener رو setup کن
2. برای هر اتصال QUIC، یه stream باز کن
3. Reflex handshake رو روی stream انجام بده
4. Frame‌های Reflex رو روی stream ارسال کن

```go
import (
    "bufio"
    "context"
    "net"
    "time"
    "github.com/quic-go/quic-go"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/features/routing"
)

func handleQUICConnection(conn quic.Connection, h *Handler, dispatcher routing.Dispatcher) error {
    // باز کردن stream برای Reflex
    stream, err := conn.AcceptStream(context.Background())
    if err != nil {
        return err
    }
    
    // تبدیل stream به net.Conn-like interface
    streamConn := &quicStreamConn{stream: stream}
    
    // حالا می‌تونی Reflex handler رو صدا بزنی
    // باید Process رو صدا بزنی یا منطق handshake رو مستقیماً اجرا کنی
    reader := bufio.NewReader(streamConn)
    return h.Process(context.Background(), net.Network_TCP, streamConn, dispatcher)
}

type quicStreamConn struct {
    stream quic.Stream
}

func (c *quicStreamConn) Read(b []byte) (int, error) {
    return c.stream.Read(b)
}

func (c *quicStreamConn) Write(b []byte) (int, error) {
    return c.stream.Write(b)
}

func (c *quicStreamConn) Close() error {
    return c.stream.Close()
}

// برای سازگاری با stat.Connection، باید متدهای دیگه رو هم implement کنی:
func (c *quicStreamConn) RemoteAddr() net.Addr {
    return c.stream.ConnectionState().TLS.ConnectionState().PeerCertificates[0].Subject
}

func (c *quicStreamConn) LocalAddr() net.Addr {
    return nil // یا آدرس محلی
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
    return c.stream.SetDeadline(t)
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
    return c.stream.SetReadDeadline(t)
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
    return c.stream.SetWriteDeadline(t)
}
```

## کدوم رو پیاده‌سازی کنیم؟

هر کدوم که پیاده‌سازی کنی، 5 نمره اضافی می‌گیری. بذار ببینیم کدوم بهتره:

### Traffic Morphing

**مزایا:**
- ساده‌تره برای پیاده‌سازی
- نیاز به کتابخانه اضافی نداره
- می‌تونی پروفایل‌های مختلف بسازی

**معایب:**
- باید تحقیق کنی که چه پروفایل‌هایی خوبن
- باید توزیع‌های آماری رو درست پیاده‌سازی کنی
- ممکنه overhead داشته باشه

**پیشنهاد**: اگه می‌خوای سریع شروع کنی، این رو انتخاب کن.

### TLS با ECH

**مزایا:**
- خیلی مفیده برای پنهان‌سازی SNI
- استاندارد صنعتی هست
- مقاوم در برابر مسدودسازی مبتنی بر دامنه

**معایب:**
- نیاز به Go 1.25+ داره
- پیاده‌سازی کاملش پیچیده‌تره
- ممکنه نیاز به کتابخانه‌های اضافی داشته باشه

**پیشنهاد**: اگه می‌خوای مقاومت بیشتری داشته باشی، این رو انتخاب کن.

### QUIC

**مزایا:**
- عملکرد خیلی خوبی داره
- Connection Migration خیلی مفیده
- بدون head-of-line blocking

**معایب:**
- پیچیده‌تره
- نیاز به کتابخانه `quic-go` داره
- ممکنه در بعضی محیط‌ها UDP block شده باشه

**پیشنهاد**: اگه می‌خوای عملکرد و پنهان‌کاری بالایی داشته باشی، این رو انتخاب کن.

### ترکیب چندتا

می‌تونی چندتا رو با هم ترکیب کنی:
- **QUIC + ECH**: حداکثر پنهان‌کاری و عملکرد
- **TCP + ECH + Traffic Morphing**: تعادل خوب بین سادگی و مقاومت
- **QUIC + Traffic Morphing**: عملکرد بالا با شکل‌دهی ترافیک

## Pro Tips

### برای Traffic Morphing

1. **استخراج پروفایل‌ها**: پروفایل‌ها رو از ترافیک واقعی استخراج کن. می‌تونی از Wireshark استفاده کنی:
   - یه capture از ترافیک واقعی بگیر (مثلاً YouTube یا Zoom)
   - توزیع اندازه بسته‌ها رو تحلیل کن
   - فاصله زمانی بین بسته‌ها رو محاسبه کن
   - از این داده‌ها برای ساخت پروفایل استفاده کن

2. **تست کردن پروفایل‌ها**: همیشه تست کن که پروفایل‌ها درست کار می‌کنن:
   - از ابزارهای تحلیل ترافیک استفاده کن (مثلاً `tshark` یا `tcpdump`)
   - توزیع آماری ترافیک morph شده رو با ترافیک واقعی مقایسه کن
   - از تست‌های آماری استفاده کن (مثلاً Kolmogorov-Smirnov test)

3. **بهینه‌سازی**: اگه overhead خیلی زیاده، می‌تونی:
   - فقط برای بسته‌های بزرگ morphing اعمال کنی
   - از پروفایل‌های ساده‌تر استفاده کنی
   - morphing رو فقط برای direction خاصی فعال کنی (مثلاً فقط upload)

4. **تغییر پروفایل**: برای مقاومت بیشتر، می‌تونی به صورت دوره‌ای پروفایل رو تغییر بدی. این باعث می‌شه الگوهای رفتاری ثابت ایجاد نشه.

### برای ECH

از دامنه‌های بزرگ و معتبر (مثلاً Cloudflare) به عنوان public SNI استفاده کن. این احتمال block شدن رو کم می‌کنه.

### برای QUIC

اگه UDP block شده، می‌تونی از TCP fallback استفاده کنی. یا می‌تونی QUIC رو روی TCP tunnel کنی (مثلاً با HTTP/3).

### تست کردن

همیشه تست کن که همه قابلیت‌های پیشرفته درست کار می‌کنن. می‌تونی از ابزارهای تحلیل ترافیک استفاده کنی تا ببینی آیا ترافیک شبیه پروتکل هدف هست یا نه.

## چک‌لیست

- [ ] یکی از قابلیت‌های پیشرفته پیاده‌سازی شده
- [ ] تست شده و کار می‌کنه
- [ ] مستند شده

## تمام!

تبریک! پروژه شما تموم شد. حالا برید سراغ [تست](testing.md) و بعد [تحویل](submission.md).

