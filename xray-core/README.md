# Reflex: A Stealthy Proxy Protocol for Xray-core
**Author:** Zeinab GhodsPour 403100546 - Mahdi Yazdanbakhsh 403100621
**Course:** Network Engineering Project - Sharif University of Technology

## 1. Project Vision
Reflex is designed to solve the "identifiability" problem of modern proxy protocols. Instead of using a clear handshake that DPI (Deep Packet Inspection) can easily flag, Reflex blends into the network as standard web traffic.

## 2. Technical Architecture (Steps 1-4)

### A. Implicit Handshake & Mimicry (Step 2 & 4)
To evade detection, Reflex does not send a binary blob as its first packet.
- **Client Side:** Wraps X25519 ephemeral public keys and UserID inside a legitimate-looking `HTTP POST` request.
- **Server Side:** Uses `bufio.Peek` to inspect the first 64 bytes. If it detects an HTTP pattern or the Reflex Magic Number, it proceeds to the handshake; otherwise, it triggers a **Fallback**.
- **Mimicry Target:** The protocol mimics **Aparat** (Iran's local video platform) API calls, ensuring high deniability within domestic networks.

### B. Security & Key Derivation
- **Key Exchange:** Elliptic-curve Diffie-Hellman (X25519).
- **Session Keys:** Derived using **HKDF-SHA256**. The salt includes the client's unique nonce to prevent Replay Attacks.
- **Encryption:** Uses **ChaCha20-Poly1305** (AEAD) for high performance and integrity.

### C. Framing System (Step 3)
Reflex uses a compact 3-byte header for every frame:
| Field | Size | Description |
| :--- | :--- | :--- |
| **Length** | 2 Bytes | Size of the encrypted payload (Big Endian) |
| **Type** | 1 Byte | `0x01`: Data, `0x04`: Close Connection |

## 3. Fallback Mechanism
If an unauthorized probe or a standard browser connects to the Reflex port, the server transparently proxies the traffic to a local web server (e.g., Nginx on port 80). This makes the proxy server appear as a regular website to any external scanner.

## 4. How to Build & Test
1. Navigate to the `xray-core` directory.
2. Build the binary: `go build -o xray ./main`.
3. Run integration tests: `go test ./tests/...`.

## 5. Challenges Overcome
- **HTTP Buffer Management:** Solving the issue of "consumed bytes" during protocol detection using `bufio.Reader`.
- **Directional Encryption:** Implementing independent keys for C2S (Client-to-Server) and S2C (Server-to-Client) to enhance security.