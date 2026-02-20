# Reflex Protocol Implementation Notes

## Authors
- **401170156** — **Pouria Golestani**
- **401100303** — **Aria Ale-Yasin**

## Architecture Overview

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
│  (Outbound) │                    │  (Inbound)  │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │   ┌──────────────────────┐      │
       ├───┤  1. Magic Number     │──────┤
       │   │     0x5246584C      │      │
       │   └──────────────────────┘      │
       │                                  │
       │   ┌──────────────────────┐      │
       ├───┤  2. Client Handshake │──────┤
       │   │   - Public Key       │      │
       │   │   - User UUID        │      │
       │   │   - Timestamp        │      │
       │   │   - Nonce            │      │
       │   └──────────────────────┘      │
       │                                  │
       │   ┌──────────────────────┐      │
       ├───┤  3. Server Handshake │──────┤
       │   │   - Public Key       │      │
       │   │   - Policy Grant     │      │
       │   └──────────────────────┘      │
       │                                  │
       │   ┌──────────────────────┐      │
       ├───┤  4. Encrypted Frames │──────┤
       │   │   [Len|Type|Payload] │      │
       │   └──────────────────────┘      │
       │                                  │
```

## Key Components

### 1. Handshake Module (`handshake.go`)

Implements the X25519 key exchange:
- Client generates ephemeral key pair
- Server generates ephemeral key pair
- Both derive shared secret via Diffie-Hellman
- Session key extracted using HKDF-SHA256

**Security Properties:**
- Forward secrecy (ephemeral keys)
- Authentication via UUID
- Replay protection via timestamp + nonce

### 2. Crypto Module (`crypto.go`)

Implements frame encryption:
- AEAD cipher: ChaCha20-Poly1305
- Nonce: 12 bytes (4 zero + 8 byte counter)
- Separate counters for read/write
- Mutex protection for thread safety

**Why ChaCha20-Poly1305?**
- Faster than AES on systems without AES-NI
- Constant-time (resistant to timing attacks)
- Authenticated encryption (AEAD)

### 3. Traffic Morphing (`morph.go`)

Implements statistical traffic shaping:
- Weighted random selection for packet sizes
- Weighted random selection for delays
- Profiles based on real protocol analysis

**Profiles:**
- `youtube`: Large packets (800-1400 bytes), moderate delays
- `zoom`: Medium packets (500-700 bytes), longer delays
- `http2-api`: Variable packets (200-1500 bytes), short delays

### 4. Inbound Handler (`inbound/inbound.go`)

Server-side implementation:
1. Peek connection to detect protocol
2. Parse handshake if Reflex magic found
3. Authenticate user UUID
4. Establish encrypted session
5. Proxy data with traffic morphing
6. Fallback to web server if not Reflex

**Key Optimizations:**
- Uses `bufio.Reader.Peek()` to avoid consuming bytes
- Buffered I/O for efficiency
- Goroutines for bidirectional relay

### 5. Outbound Handler (`outbound/outbound.go`)

Client-side implementation:
1. Connect to server
2. Send handshake with user credentials
3. Receive server response
4. Establish encrypted session
5. Relay data with traffic morphing

## Protocol Flow

### Handshake Phase

```
Client                                 Server
  │                                      │
  │  REFX + PubKey + UUID + Time + Nonce │
  ├─────────────────────────────────────>│
  │                                      │
  │                  PubKey + PolicyGrant │
  │<─────────────────────────────────────┤
  │                                      │
  ├──── Both derive session key ─────────┤
  │                                      │
```

### Data Transfer Phase

```
Client                                 Server
  │                                      │
  │  Frame: [Len|Type|Encrypted Data]    │
  ├─────────────────────────────────────>│
  │                                      │
  │            [Len|Type|Encrypted Data] │
  │<─────────────────────────────────────┤
  │                                      │
  │  (Traffic morphing applied)          │
  │  - Packet size from profile          │
  │  - Delay from profile                │
  │                                      │
```

## Security Considerations

### 1. Key Derivation

```
Shared Secret = X25519(clientPriv, serverPub)
              = X25519(serverPriv, clientPub)

Session Key = HKDF-SHA256(
    secret:  Shared Secret,
    salt:    Client Nonce,
    info:    "reflex-session-v1",
    length:  32 bytes
)
```

### 2. Replay Protection

- Timestamp must be within acceptable window
- Nonce prevents same handshake replay
- Server should track recent nonces (not implemented due to time/memory constraints)

### 3. Traffic Analysis Resistance

- Magic number can be disabled (use HTTP-like format)
- Traffic morphing mimics legitimate protocols
- Fallback provides plausible deniability
- Encrypted payloads hide traffic content

## Performance Characteristics

### Latency
- Handshake: 1 RTT
- Additional morphing delay: 5-50ms per packet (configurable)

### Throughput
- ChaCha20: ~1-2 GB/s on modern CPU
- Limited by network, not crypto

### Memory
- Per-connection overhead: ~8KB (buffers)
- Session state: <1KB

## Future Improvements

1. **Implement nonce replay cache**
   - Track recent nonces to prevent replay
   - Use LRU cache with expiration

2. **ECH Support**
   - Integrate Encrypted Client Hello
   - Requires Go 1.23+ or Cloudflare circl

3. **QUIC Transport**
   - Add QUIC as transport option
   - Better on lossy networks

4. **Machine Learning Morphing**
   - Train on real traffic captures
   - More realistic distributions

5. **Obfuscation Layers**
   - Additional obfuscation for magic number
   - Mimic TLS ClientHello perfectly

## References

- X25519: RFC 7748
- ChaCha20-Poly1305: RFC 8439
- HKDF: RFC 5869
- Xray-Core: https://github.com/XTLS/Xray-core

---

**Implementation Team:**
- Pouria Golestani (401170156) - Architecture, Handshake, Crypto
- Aria Ale-Yasin (401100303) - Traffic Morphing, Handlers, Tests
