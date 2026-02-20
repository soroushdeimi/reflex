# Reflex Protocol Submission

**Project:** Reflex Protocol Implementation for Xray-Core  
**Team Members:**
- **Sina Daneshgar** (401100369)
- **Sayna Sadabadi** (401171609)

## Summary of Work

Complete implementation of the Reflex protocol across all 5 steps, plus bonus features (QUIC, TLS/ECH, KS-test statistical evidence, and performance optimization).

## Test Coverage

| Package | Statements | Tests |
|---|---|---|
| `proxy/reflex` | **92.9%** | 30+ unit tests |
| `proxy/reflex/inbound` | **77.7%** | 30+ unit/integration tests |
| `proxy/reflex/outbound` | **73.8%** | 5 unit tests |
| `tests` | integration | 2 end-to-end tests |
| **Total** | **85.5% overall** | **87 tests** |

```bash
# Run everything
go test ./proxy/reflex/... ./tests/... -timeout 120s

# With coverage
go test ./proxy/reflex/... -covermode=atomic

# go vet (clean)
go vet ./proxy/reflex/... ./tests/...
```

## Test Types Included

- **Unit**: encryption, key derivation, handshake parsing, morphing profiles, protobuf getters
- **Integration**: full handshake + data transfer (`TestHandleSession_*`), outbound process flow
- **End-to-end**: `TestReflexFullIntegration`, `TestReflexFallback`
- **Edge cases**: replay attack, old timestamp, incomplete handshake, wrong key decryption, dispatcher errors
- **Fuzz**: `FuzzInboundProcess` with 3 seed corpus entries
- **Benchmarks**: encryption throughput at multiple sizes, handshake, morphing, memory allocation
- **Example**: `ExampleNewSession` (runnable godoc example)


### Key Achievements
- **Robustness**: The integration tests (`reflex_test.go`) confirm that our implementation handles full connection lifecycles, including handshake, data exchange, and graceful closure.
- **Security**: We implemented replay protection using a 120-second time window and nonce cache. The handshake is secured with X25519 and verified with HMAC-based session derivation (HKDF).
- **Functionality**: The fallback mechanism is fully operational. Any non-Reflex traffic (e.g., standard HTTP or simple TCP probes) is transparently forwarded to a destination port, making the server indistinguishable from a normal web server to casual observation.

## Grading Criteria

### Step 1: Basic Structure
- **Package Structure**: Organized into standard `inbound` and `outbound` packages within `proxy/reflex`.
- **Config**: `config.proto` is defined and `pb.go` is generated.
- **Handlers**: Initial handlers are functional and integrated.

### Step 2: Handshake
- **Key Exchange**: X25519 ECDH is fully implemented.
- **Session Keys**: Derived using HKDF from the shared secret.
- **Authentication**: UUID-based authentication is enforced; invalid users are rejected or sent to fallback.
- **Error Handling**: Comprehensive error checks during the handshake phase.

### Step 3: Encryption
- **Cipher**: ChaCha20-Poly1305 is used for all data frames.
- **Framing**: Protocol follows a strict Frame format (Type + Length + Payload).
- **Replay Protection**: Integration of `antireplay.ReplayFilter` prevents reuse of nonces/timestamps.

### Step 4: Fallback
- **Detection**: Protocol detection uses `bufio.Peek(64)` to identify the Reflex "Magic Number" cheaply.
- **Forwarding**: Active probing traffic falls back to a configured destination (e.g., port 80).
- **Multiplexing**: The server listens on a single port for both Reflex and Fallback traffic.

### Step 5: Advanced (Morphing)
- **Traffic Morphing**: The `WriteFrameWithMorphing` function adds padding frames to data streams, altering packet sizes according to statistical profiles (e.g., YouTube-like distribution).
- **Profile Support**: The system supports loading traffic profiles (padding intervals and size distributions).
- **Optimization**: Connection reuse logic in `inbound.go` prevents opening a new backend connection for every single packet, drastically improving performance and stealth.

## Test Coverage
We have included a comprehensive test suite in `reflex_test.go` covering:
- **Full Integration**: End-to-end Client <-> Server communication.
- **Handshake Verification**: Correct key exchange and auth.
- **Fallback Verification**: Ensuring junk data is routed to the fallback server.

To run the tests:
```bash
go test -v ./tests/...
```
