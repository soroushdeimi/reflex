# Reflex Project Submission

**Student ID:** 400108582, 400108955 400108966

## Implementation Summary

We have completed all stages of the Reflex protocol implementation:

1.  **Structure**: Created the `proxy/reflex` package with inbound and outbound handlers. Registered the protocol in `main/distro/all/all.go` and added JSON config support in `infra/conf`.
2.  **Handshake**: Implemented X25519 key exchange and HKDF-based session key derivation. Users are authenticated using UUIDs.
3.  **Encryption**: Implemented ChaCha20-Poly1305 AEAD encryption for all data frames.
4.  **Fallback**: Implemented a robust fallback mechanism using `bufio.Peek` to detect Reflex connections without consuming bytes, allowing redirection to a local web server for non-Reflex traffic.
5.  **Advanced Morphing**: Implemented statistical traffic morphing with multiple profiles (YouTube, Zoom, HTTP/2 API). Added support for PADDING_CTRL and TIMING_CTRL frames to dynamically adjust traffic shapes.

## Testing

- **Unit Tests**: 22 unit tests covering handshake, KDF, session management, and morphing logic.
- **Integration Tests**: Comprehensive integration tests for handshake and fallback/replay protection.
- **Result**: All tests pass successfully.

## Configuration

An example configuration is provided in `config.example.json` in the root directory.
