package inbound

import (
    "bufio"
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "io"
    "net"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/xtls/xray-core/common"
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/features/routing"
    "github.com/xtls/xray-core/proxy"
    "github.com/xtls/xray-core/proxy/reflex"
    "github.com/xtls/xray-core/transport/internet/stat"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/hkdf"
)

const (
    ReflexMagic      = 0x5246584C
    FrameTypeData    = 0x01
    FrameTypePadding = 0x02
    FrameTypeTiming  = 0x03
    FrameTypeClose   = 0x04
)

// Traffic Morphing (Step 5)
type PacketSizeDist struct {
    Size   int
    Weight float64
}
type DelayDist struct {
    Delay  time.Duration
    Weight float64
}
type TrafficProfile struct {
    Name        string
    PacketSizes []PacketSizeDist
    Delays      []DelayDist
    mu          sync.Mutex
}

type Handler struct {
    clients  map[string]*protocol.MemoryUser
    fallback *reflex.Fallback
    profiles map[string]*TrafficProfile
}

func (h *Handler) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.InboundHandler, error) {
    h := &Handler{
        clients:  make(map[string]*protocol.MemoryUser),
        profiles: make(map[string]*TrafficProfile),
    }
    for _, user := range config.Clients {
        account := &reflex.MemoryAccount{ID: user.Id}
        mUser := &protocol.MemoryUser{Email: user.Id, Level: 0, Account: account}
        h.clients[user.Id] = mUser
    }
    if config.Fallback != nil { h.fallback = config.Fallback }
    h.loadProfiles()
    return h, nil
}

func (h *Handler) loadProfiles() {
    h.profiles["youtube"] = &TrafficProfile{
        Name: "YouTube",
        PacketSizes: []PacketSizeDist{{1400, 0.4}, {1200, 0.3}, {1000, 0.2}, {800, 0.1}},
        Delays:      []DelayDist{{10 * time.Millisecond, 0.5}, {20 * time.Millisecond, 0.3}},
    }
}

func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
    reader := bufio.NewReader(conn)
    // Step 4: Fallback & Peek
    peeked, err := reader.Peek(64)
    if err != nil { return h.handleFallback(conn, reader) }

    isReflex := false
    if len(peeked) >= 4 {
        magic := binary.BigEndian.Uint32(peeked[:4])
        if magic == ReflexMagic { isReflex = true }
    }
    if !isReflex && string(peeked[:4]) == "POST" { isReflex = true }

    if !isReflex { return h.handleFallback(conn, reader) }
    return h.handleHandshake(ctx, conn, reader, dispatcher)
}

func (h *Handler) handleFallback(conn stat.Connection, reader *bufio.Reader) error {
    if h.fallback == nil { conn.Close(); return nil }
    target, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
    if err != nil { return err }
    defer target.Close()
    go io.Copy(target, reader)
    io.Copy(conn, target)
    return nil
}

func (h *Handler) handleHandshake(ctx context.Context, conn stat.Connection, reader *bufio.Reader, dispatcher routing.Dispatcher) error {
    // Step 2: Handshake
    peeked, _ := reader.Peek(4)
    if binary.BigEndian.Uint32(peeked) == ReflexMagic { reader.Discard(4) }
    
    clientKeys := make([]byte, 48)
    if _, err := io.ReadFull(reader, clientKeys); err != nil { return err }
    
    u, err := uuid.FromBytes(clientKeys[32:])
    if err != nil { return h.handleFallback(conn, reader) }
    
    _, exists := h.clients[u.String()]
    if !exists { return h.handleFallback(conn, reader) }

    var privKey, pubKey, sharedKey [32]byte
    rand.Read(privKey[:])
    curve25519.ScalarBaseMult(&pubKey, &privKey)
    copy(sharedKey[:], clientKeys[:32]) // Simplified curve mult for mock
    
    hkdfReader := hkdf.New(sha256.New, sharedKey[:], nil, []byte("reflex-session"))
    sessionKey := make([]byte, 32)
    hkdfReader.Read(sessionKey)

    conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
    conn.Write(pubKey[:])
    
    return h.handleSession(ctx, conn, reader, dispatcher, sessionKey)
}

func (h *Handler) handleSession(ctx context.Context, conn stat.Connection, reader *bufio.Reader, dispatcher routing.Dispatcher, key []byte) error {
    // Step 3: Encryption
    aead, err := chacha20poly1305.New(key)
    if err != nil { return err }
    var readNonce uint64 = 0
    nonceCache := make(map[uint64]bool)

    for {
        header := make([]byte, 3)
        if _, err := io.ReadFull(reader, header); err != nil { return err }
        length := binary.BigEndian.Uint16(header[:2])
        frameType := header[2]
        
        encryptedPayload := make([]byte, length)
        if _, err := io.ReadFull(reader, encryptedPayload); err != nil { return err }
        
        if nonceCache[readNonce] { return fmt.Errorf("replay detected") }
        nonceCache[readNonce] = true
        
        nonce := make([]byte, 12)
        binary.BigEndian.PutUint64(nonce[4:], readNonce)
        readNonce++
        
        _, err = aead.Open(nil, nonce, encryptedPayload, nil)
        if err != nil { return err }
        
        if frameType == FrameTypeClose { return nil }
    }
}

func init() {
    common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
        return New(ctx, config.(*reflex.InboundConfig))
    }))
}
