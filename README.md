# Reflex Protocol Implementation

## Team Members
- Barbod Zohourfazeli – 402111464  
- MohammadParsa Sadeghi – 401109947 

## Project Overview

This project implements the Reflex protocol on top of Xray-Core as part of the course assignment.

The implementation follows all required steps:

- Step 1: Basic protocol structure
- Step 2: Secure handshake using X25519 key exchange
- Step 3: Frame encryption using ChaCha20-Poly1305 (AEAD)
- Step 4: Protocol detection and fallback using bufio.Peek
- Step 5: Basic traffic morphing (packet size & timing distribution)

## Implemented Features

### Handshake
- Ephemeral X25519 key exchange
- Session key derivation using HKDF-SHA256
- UUID-based authentication
- Timestamp validation
- Replay protection using nonce tracking

### Encryption
- Frame structure:
  - 2 bytes length
  - 1 byte type
  - Encrypted payload
- AEAD encryption (ChaCha20-Poly1305)
- Independent read/write nonces
- Replay protection at session level

### Fallback
- Protocol detection using `bufio.Peek`
- Magic-based and HTTP-like detection
- Fallback forwarding to a local web server
- Single-port multiplexing support

### Traffic Morphing (Basic)
- FrameTypePadding support
- FrameTypeTiming support
- Packet size randomization
- Basic delay distribution

## How to Build

```bash
cd xray-core
go build -o xray ./main