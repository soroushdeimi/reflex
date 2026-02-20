# Testing Guide for Reflex Protocol

## Authors
- **401170156** — **Pouria Golestani**
- **401100303** — **Aria Ale-Yasin**

## Running Tests

### Unit Tests

To run all unit tests for the Reflex protocol:

```bash
cd xray-core/proxy/reflex
go test -v
```

### Specific Test Cases

Run specific tests:

```bash
# Test handshake only
go test -v -run TestHandshake

# Test session encryption
go test -v -run TestSession

# Test traffic morphing
go test -v -run TestTrafficMorphing
```

### Coverage Report

Generate test coverage report:

```bash
go test -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Integration Tests

### Server-Client Integration Test

1. Start the server:
```bash
./xray -config config.server.json
```

2. In another terminal, start the client:
```bash
./xray -config config.client.json
```

3. Test with curl through SOCKS proxy:
```bash
curl -x socks5://127.0.0.1:1080 http://example.com
```

### Fallback Test

Test that non-Reflex traffic is properly forwarded to fallback server:

1. Ensure you have a web server running on port 80
2. Connect directly to the Reflex server port with HTTP:
```bash
curl http://your.server.com:8443
```

Expected: Should receive response from fallback web server, not connection error.

### Traffic Morphing Test

To verify traffic morphing is working:

1. Use Wireshark or tcpdump to capture packets
2. Connect through Reflex with different policies
3. Analyze packet size distributions

Expected: Packet sizes should match the configured profile (youtube, zoom, http2-api).

## Test Scenarios

### Scenario 1: Basic Connectivity
- ✅ Client connects to server
- ✅ Handshake completes successfully
- ✅ Data is transmitted and received

### Scenario 2: Authentication
- ✅ Valid user ID is accepted
- ✅ Invalid user ID is rejected
- ✅ Replay protection works

### Scenario 3: Encryption
- ✅ Data is encrypted with ChaCha20-Poly1305
- ✅ Nonce is incremented for each frame
- ✅ Decryption fails with wrong key

### Scenario 4: Fallback
- ✅ Non-Reflex traffic triggers fallback
- ✅ HTTP requests reach fallback server
- ✅ TLS handshake works with fallback

### Scenario 5: Traffic Morphing
- ✅ Packet sizes follow profile distribution
- ✅ Delays are applied correctly
- ✅ Different profiles produce different patterns

## Troubleshooting

### Connection Refused
- Check server is running
- Verify firewall allows connections on port
- Check config file addresses and ports

### Handshake Failure
- Verify user UUID matches server config
- Check system time synchronization
- Ensure network allows TCP connections

### Fallback Not Working
- Verify fallback destination is reachable
- Check fallback service is running
- Test fallback independently

## Performance Tests

### Latency Test

Measure connection latency:

```bash
time curl -x socks5://127.0.0.1:1080 http://example.com
```

### Throughput Test

Measure throughput:

```bash
curl -x socks5://127.0.0.1:1080 http://speedtest.com/large-file.bin -o /dev/null
```

### Concurrent Connections

Test multiple simultaneous connections:

```bash
for i in {1..10}; do
  curl -x socks5://127.0.0.1:1080 http://example.com &
done
wait
```

## Expected Results

All tests should pass with:
- ✅ 100% handshake success rate
- ✅ Zero decryption failures
- ✅ Fallback working for non-Reflex traffic
- ✅ Traffic patterns matching configured profile

## Reporting Issues

If tests fail, provide:
1. Xray version and Go version
2. Config files (with sensitive data redacted)
3. Test output and error messages
4. Network environment details

---

**Last Updated**: February 20, 2026  
**Tested Versions**: Xray-core v1.8.x, Go 1.21+
