# پروژه Reflex -
# Meqdad Mahmoudi 400106054 & Mohammad Rahmanitalab 400105636

## Student Information
- Name: Meqdad Mahmoudi
- Student ID: 400106054
- Name: Mohammad Rahmanitalab
- Student ID: 400105636

## Step 1 - Basic Structure

In the first step, the foundational structure of the Reflex protocol was implemented inside Xray-Core. A dedicated `proxy/reflex` package was created to properly isolate the protocol logic. The `config.proto` file was defined to describe inbound and outbound configurations, and the corresponding `config.pb.go` file was generated to enable Go integration.

Inbound and outbound handlers were implemented to comply with Xray’s proxy interfaces. Finally, the protocol was properly registered inside Xray so that it can be recognized and instantiated from configuration files. This step ensures that the project builds successfully and integrates cleanly into the Xray architecture.

---

## Step 2 - Handshake

In the second step, the secure handshake mechanism was implemented. The protocol uses X25519 for key exchange, allowing both client and server to derive a shared secret securely. From this shared key, a session key is generated using HKDF to ensure proper key separation and forward secrecy.

User authentication is performed using UUID verification against configured clients. Additionally, timestamp validation is included as a basic anti-replay protection mechanism. Proper error handling was added to ensure that invalid handshakes are rejected gracefully without crashing the server.

---

## Step 3 - Encryption

The third step focused on implementing encrypted communication after the handshake phase. A custom frame structure was defined, consisting of a two-byte length field, a one-byte type field, and an encrypted payload section. This frame format standardizes how data is transmitted between client and server.

Encryption is handled using ChaCha20-Poly1305 (AEAD), providing authenticated encryption for both confidentiality and integrity. Read and write frame functions were implemented to correctly encrypt outgoing frames and decrypt incoming ones. Nonce-based replay protection ensures that frames cannot be reused maliciously, and session handling is designed to support directional encryption logic.

---

## Step 4 - Fallback & Multiplexing

In the final step, protocol detection and fallback behavior were implemented. The handler uses `bufio.Peek` to inspect initial connection bytes without consuming them, allowing safe protocol identification. Reflex traffic is detected using a magic value check as well as HTTP-like pattern detection.

If incoming traffic does not match the Reflex protocol, it is forwarded to a local web server using a fallback mechanism. This enables single-port multiplexing, allowing both Reflex traffic and regular HTTP traffic to coexist on the same port. This design improves resistance to active probing and increases deployment flexibility.

