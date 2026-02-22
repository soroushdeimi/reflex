# SUBMISSION

## Summary

Implemented the Reflex protocol inside `xray-core/proxy/reflex` following Steps 1–5:

- **Step 1**: Package structure + `config.proto` + config structs.
- **Step 2**: Handshake (magic + HTTP POST-like), X25519 key exchange, UUID auth, HKDF session key, policy request/grant (PSK-encrypted).
- **Step 3**: Encrypted frame transport using **ChaCha20-Poly1305** (pure-Go RFC 8439 implementation), nonce counters.
- **Step 4**: Fallback for non-Reflex traffic via `Peek()` and forwarding to `127.0.0.1:<dest>`.
- **Step 5**: Traffic morphing (`TrafficProfile`) with distributions + support for PADDING/TIMING control frames.

## Tests

Tests are located at `xray-core/tests/reflex_test.go` and cover:

- Handshake
- Encryption
- Fallback
- End-to-end integration (client -> inbound -> destination echo server)
