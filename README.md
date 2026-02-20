# Reflex Protocol Implementation - Team Project

**Course:** Networks & Security  
**University:** Sharif University of Technology

## Team Members
*   **Sina Daneshgar** (Student ID: 401100369)
*   **Sayna Sadabadi** (Student ID: 401171609)

## Project Overview
Reflex is a stealthy proxy protocol extension for Xray-Core designed to bypass active probing and deep packet inspection (DPI). It employs traffic morphing, secure handshakes, and fallback mechanisms to masquerade as legitimate traffic.

This repository contains the complete implementation of the Reflex protocol, covering Steps 1 through 5 of the assignment requirements.

## Features Implemented

### Step 1 — Basic Structure & Configuration
- Defined all protocol buffer messages in `config.proto` and generated `config.pb.go`.
- Implemented `Inbound` and `Outbound` handlers registered with Xray-Core's DI system via `init()`.

### Step 2 — Secure Handshake
- **Key Exchange**: Ephemeral **X25519** ECDH per connection.
- **Session Keys**: Derived with **HKDF-SHA256** from the shared secret — unique keys per session.
- **Authentication**: UUID-based user lookup with constant-time comparison.
- **Replay Protection**: `antireplay.ReplayFilter` combined with a ±90s timestamp window blocks replayed handshakes.

### Step 3 — Encryption & Framing
- **Cipher**: **ChaCha20-Poly1305** (AEAD) for confidentiality + integrity on every frame.
- **Frame types**: `DATA (0x01)`, `PADDING (0x02)`, `TIMING (0x03)`, `CLOSE (0x04)`.
- **Nonce management**: Per-session monotonic counter prevents nonce reuse.

### Step 4 — Fallback System
- **Non-destructive detection**: `bufio.Reader.Peek(64)` inspects the Magic Number without consuming bytes.
- **Transparent forwarding**: Unrecognized traffic is pipelined verbatim to the configured fallback port (e.g. Nginx on 80).
- **Single-port multiplexing**: Reflex and fallback traffic co-exist on one listener.

### Step 5 — Traffic Morphing & Advanced Features
- **Statistical profiles**: `youtube`, `zoom`, `mimic-http2-api` built-in; custom profiles via `CreateProfileFromCapture`.
- **Packet-size morphing**: `WriteFrameWithMorphing` chunks and pads frames to match the target size distribution.
- **Timing morphing**: Inter-frame delays drawn from a weighted distribution.
- **PADDING_CTRL / TIMING_CTRL frames**: Remote control of the active profile at runtime.
- **KS-test evidence**: `KolmogorovSmirnovTest` + auto-generated `morphing_evidence.md` histogram report.
- **QUIC transport**: QUIC listener scaffolded on top of TLS (`StartQUIC`).
- **TLS + ECH**: Inbound handler supports optional TLS with Encrypted Client Hello config bytes.
- **Performance**: Single `transport.Link` reused for the entire session lifetime (no per-frame dispatch).

## Project Structure

```
reflex/
├── xray-core/
│   ├── proxy/reflex/
│   │   ├── inbound/           # Server-side: Handshake, Fallback, Session, QUIC
│   │   │   ├── inbound.go
│   │   │   ├── handshake.go
│   │   │   ├── inbound_core_test.go
│   │   │   ├── inbound_session_test.go
│   │   │   ├── transport_test.go
│   │   │   ├── benchmark_comparison_test.go
│   │   │   ├── examples_test.go
│   │   │   └── handshake_fuzz_test.go
│   │   ├── outbound/          # Client-side: Handshake, Frame encoding
│   │   │   ├── outbound.go
│   │   │   └── outbound_test.go
│   │   ├── config.proto
│   │   ├── config.pb.go
│   │   ├── protocol.go        # Core crypto, framing, key derivation
│   │   ├── protocol_test.go
│   │   ├── morphing.go        # Traffic shaping, KS-test
│   │   ├── morphing_test.go
│   │   ├── morphing_extra_test.go
│   │   ├── config_test.go
│   │   └── encoding.go
│   └── tests/
│       └── reflex_test.go     # End-to-end integration tests
├── config.example.json
├── README.md
└── SUBMISSION.md
```

## Test Coverage

| Package | Coverage |
|---|---|
| `proxy/reflex` | **92.9%** |
| `proxy/reflex/inbound` | **77.7%** |
| `proxy/reflex/outbound` | **73.8%** |

**87 tests** total — unit, integration, fuzz, benchmark, and example tests.

```bash
# Run all tests
go test ./proxy/reflex/... ./tests/... -timeout 120s

# With coverage
go test ./proxy/reflex/... -covermode=atomic

# Specific packages
go test -v ./proxy/reflex/inbound/
go test -v ./tests/
```

## How to Run

### Prerequisites
- Go 1.21+
- Git

### Steps

1. **Clone:**
    ```bash
    git clone https://github.com/soroushdeimi/reflex.git
    cd reflex/xray-core
    ```

2. **Run tests:**
    ```bash
    go test ./proxy/reflex/... ./tests/... -timeout 120s
    ```

3. **Build:**
    ```bash
    go build -o xray.exe ./main
    ```

4. **Run with config:**
    ```bash
    ./xray.exe -config ../config.example.json
    ```

## Challenges & Solutions

### 1. Race Conditions in Integration Tests
**Issue:** `io: read/write on closed pipe` errors in `TestReflexFullIntegration` caused by `task.Run` closing connections prematurely when one direction reached EOF.

**Solution:** Revamped `MockDispatcher` to use separate pipes per direction and ensured rigorous `defer common.Close(...)` resource management throughout.

### 2. Connection Reuse (Performance)
**Issue:** The initial implementation dispatched a new backend connection for *every* data frame — inefficient and detectable by traffic analysis.

**Solution:** Refactored `inbound.go` to establish a single `transport.Link` per session, maintained for the full lifetime of the user session.

### 3. Non-Destructive Fallback
**Issue:** Identifying non-Reflex traffic consumed the first bytes, corrupting the stream forwarded to the web server.

**Solution:** `bufio.Reader.Peek()` inspects the Magic Number without advancing the read pointer, so the full unmodified stream is forwarded to the fallback destination.

## License
Reflex Implementation for Academic Purposes.


## Features Implemented

### 1. Basic Structure & Configuration
*   Defined protocol buffer messages in `config.proto`.
*   Implemented `Inbound` and `Outbound` handlers integrated into Xray-Core's architecture.

### 2. Secure Handshake
*   **Mechanism**: Uses **X25519** ECDH for ephemeral key exchange.
*   **Authentication**: Verifies users based on UUID.
*   **Replay Protection**: Implements a time-window filter (±90s) and nonces to prevent replay attacks.
*   **Session Keys**: Derives distinct session keys for every connection using HKDF.

### 3. Encryption & Framing
*   **Cipher**: **ChaCha20-Poly1305** (AEAD) ensures confidentiality and integrity.
*   **Framing**: Custom frame format handling Data, Padding, Timing, and Close signals.

### 4. Advanced Fallback System
*   **Protocol Detection**: Uses `bufio.Reader.Peek` to inspect the first few bytes (Magic Number) without consuming them.
*   **Fallback Strategy**: If the handshake fails or the protocol is not detected (e.g., active probing), traffic is seamlessly pipelined to a fallback destination (e.g., a local Nginx server on port 80).
*   **Multiplexing**: Supports multiple concurrent users on a single listening port.

### 5. Traffic Morphing (Stealth)
*   Implemented in `morphing.go` and integrated into the write loop.
*   **Padding**: Adds random padding frames to obfuscate packet sizes, mimicking distribution profiles of common services (e.g., YouTube).
*   **Connection Reuse**: Optimized inbound handler to sustain a persistent backend link for the duration of a session, improving performance and behavior consistency.

### 6. Bonus Features
*   **QUIC Transport Support**: Initial scaffolding for QUIC listeners alongside TCP.
*   **Performance Optimization**: Refactored the inbound data loop to reuse `transport.Link` and connections, significantly reducing overhead compared to per-packet dispatching.

## Project Structure

```
reflex/
├── xray-core/
│   ├── proxy/reflex/
│   │   ├── inbound/       # Server-side logic (Handshake, Fallback, Session mgmt)
│   │   ├── outbound/      # Client-side logic (Handshake, Encoding)
│   │   ├── config.proto   # Protobuf definitions
│   │   ├── protocol.go    # Core crypto and framing utilities
│   │   └── morphing.go    # Traffic shaping logic
│   └── tests/
│       └── reflex_test.go # Comprehensive Integration Tests
├── config.example.json    # Sample configuration for testing
└── README.md              # This file
```

## How to Run

### Prerequisites
*   Go 1.21+
*   Git

### Steps
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/soroushdeimi/reflex.git
    cd reflex/xray-core
    ```

2.  **Run Tests:**
    Execute the integration suites to verify Handshake, Data Transfer, and Fallback.
    ```bash
    go test -v ./tests/...
    ```

3.  **Build Xray:**
    ```bash
    go build -o xray.exe ./main
    ```

4.  **Run with Config:**
    ```bash
    ./xray.exe -config ../config.example.json
    ```

## Challenges & Solutions

### 1. Integration Test Loop & Race Conditions
**Issue:** During `TestReflexFullIntegration`, we encountered `io: read/write on closed pipe` errors. This was caused by the `task.Run` function in the outbound handler closing the connection prematurely when one direction reached EOF.

**Solution:** We revamped the testing mock dispatcher (`MockDispatcher`) to use separate pipes for Read/Write and ensured rigorous `defer common.Close(...)` resource management. We also fixed the `outbound.go` loop to handle half-closed states gracefully.

### 2. Connection Reuse (Performance)
**Issue:** The initial implementation dispatched a new connection to the destination for *every* data frame, which is highly inefficient and creates easy traffic patterns for analysis.

**Solution:** We refactored `inbound.go` to establish a single `transport.Link` per session. This link is maintained in a goroutine for the lifetime of the user session, significantly improving throughput and matching standard TCP behavior.

### 3. Non-Destructive Fallback
**Issue:** Identifying non-Reflex traffic usually consumed the first few bytes, making it impossible to forward that traffic effectively to a web server (which would receive corrupted headers).

**Solution:** Utilized `bufio.Reader`'s `Peek()` method to inspect the `Magic Number` without advancing the read pointer. This allows the full, unaltered stream to be copied to the fallback destination if the handshake check fails.

## License
Reflex Implementation for Academic Purposes.

