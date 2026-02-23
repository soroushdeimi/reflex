# Submission Notes

## What we implemented
- Step 1: Package structure, config.proto, handler
- Step 2: X25519 key exchange, HKDF session key, UUID auth, replay protection
- Step 3: ChaCha20-Poly1305 frames, read/write counters, frame types
- Step 4: bufio.Peek detection (REFX magic + POST), fallback forwarding
- Step 5: Traffic morphing (TrafficProfile, PADDING_CTRL, TIMING_CTRL frames)

## Challenges and solutions
- TCP RST on error responses: fixed by draining reader in background goroutine
- net.Pipe deadlock in tests: same fix — async drain prevents both ends blocking
- Timestamp validation: server sends HTTP error + drains, client reads response

## Known limitations
- Outbound not fully implemented (inbound-only)