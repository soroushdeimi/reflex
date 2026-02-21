# Submission Notes

## Name
Kasra Arabi  
Kajal Baghestani  
Sogol Zamanian

## Student ID
401110953  
401100071  
401109014

## Implemented Work Summary
- Step 1: Reflex protocol package, proto config, inbound/outbound registration.
- Step 2: Handshake with X25519 key exchange, HKDF session key derivation, UUID auth.
- Step 3: Encrypted frame transport with ChaCha20-Poly1305 and replay protection.
- Step 4: Protocol detection by peek + fallback routing on shared port.
- Step 5: Traffic morphing profile + control frames + KS statistic helper.

## Testing Summary
- `go test ./...` passed.
- `go test -cover ./...` passed.
- `go test -race ./...` passed.
- `golangci-lint run ./...` passed (project lint config included).
- Reflex grading coverage is above 70%.
