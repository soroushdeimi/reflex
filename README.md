# Reflex Protocol Implementation - Danial Darroudy & Mohammad Mohsen Abbas Zade & Seyyed Hossein Ahmadi Mosavi

## Student Information
- Name: Danial Darroudy
- Student ID: 401100371
- Name: Mohammad Mohsen Abbas Zade
- Student ID: 401100433
- Name: Seyyed Hossein Ahmadi Mosavi
- Student ID: 402100334
---

## Project Overview

This project implements the **Reflex protocol** inside Xray-Core.

Reflex is a custom proxy protocol with:

- Implicit handshake (X25519 key exchange)
- UUID-based authentication
- AEAD encryption (ChaCha20-Poly1305)
- Frame-based transport
- Replay protection
- Fallback mechanism (Trojan-like behavior)
- Traffic Morphing (statistical disguise)

The protocol is designed to resist traffic fingerprinting and DPI detection.

---

# Implemented Features

## ✅ Step 1 - Basic Structure

- Created `proxy/reflex` package
- Implemented `config.proto`
- Generated `config.pb.go`
- Implemented inbound and outbound handlers
- Registered protocol inside Xray

---

## ✅ Step 2 - Handshake

- X25519 key exchange
- Shared key derivation
- Session key generation via HKDF
- UUID authentication
- Timestamp validation (anti-replay)
- Proper error handling

---

## ✅ Step 3 - Encryption

- Frame structure:
    - Length (2 bytes)
    - Type (1 byte)
    - Encrypted payload
- AEAD: ChaCha20-Poly1305
- Read/Write frame implementation
- Nonce-based replay protection
- Directional session keys

---

## ✅ Step 4 - Fallback & Multiplexing

- Protocol detection using `bufio.Peek`
- Reflex magic detection
- HTTP detection
- TLS detection
- Fallback to local web server
- Single port multiplexing (Reflex + HTTP)

---

## ✅ Step 5 - Advanced (Traffic Morphing)

### Mandatory features implemented:

- TrafficProfile structure
- Statistical packet size distribution
- Statistical delay distribution
- Dynamic padding
- Timing morphing
- PADDING_CTRL frame support
- TIMING_CTRL frame support
- Profile creation from samples
- KS statistical test

### Profiles implemented:

- YouTube-like
- Zoom-like
- HTTP/2 API-like
- Generic

### Extra (Bonus)

- KS-test statistical comparison
- Traffic statistics collector
- Replay protection testing
- Full unit test coverage
- Race-safe implementation

---

# How To Build

```bash
cd xray-core
go mod tidy
go build -o xray.exe ./main
```

# How To Run

Example config:
```bash
./xray.exe -config config.example.json
```
# Testing
Run tests:
```bash
go test ./proxy/reflex/... -v
go test -race ./proxy/reflex/...
```
Lint:
```bash
golangci-lint run ./proxy/reflex/...
```
# Problems Faced & Solutions
## 1️⃣ Handshake Synchronization
### Problem:
Nonce mismatch between client and server.

### Solution:
Unified nonce generation logic and synchronized timestamp-based nonce derivation.

## 2️⃣ Replay Protection Issues
### Problem:
Duplicate frame detection triggered incorrectly during testing.

### Solution:
Implemented proper NonceCache with sliding window cleanup.

## 3️⃣ Traffic Morphing Overhead
### Problem:
Large delays caused performance degradation.

### Solution:
Optimized cumulative weight calculation and controlled delay application only between chunks.

## 4️⃣ Frame Parsing Edge Cases
### Problem:
Malformed frames caused panic.

### Solution:
Added strict validation and error returns for:

- Invalid frame type
- Short header
- Oversized handshake
## 5️⃣ Fallback Byte Consumption
### Problem:
Peeked bytes were lost during fallback.

### Solution:
Implemented `FallbackConn` wrapper to preserve buffered bytes.

# Security Considerations
- AEAD encryption
- HKDF key derivation
- Replay protection
- Timestamp validation
- No plaintext handshake markers (optional HTTP disguise supported)
- Strict frame validation

# Final Status
- ✅ All steps implemented
- ✅ Unit tests written
- ✅ Replay protection tested
- ✅ Morphing implemented
- ✅ Fallback working
- ✅ Clean build
- ✅ Race detection safe

