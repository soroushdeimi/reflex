# Build and Deployment Guide

## Authors
- **401170156** — **Pouria Golestani**
- **401100303** — **Aria Ale-Yasin**

## Prerequisites

### Required Software
- **Go 1.21 or later**: Download from [golang.org](https://go.dev/dl/)
- **Git**: Download from [git-scm.com](https://git-scm.com/)
- **Protocol Buffers Compiler (protoc)**: Download from [github.com/protocolbuffers/protobuf](https://github.com/protocolbuffers/protobuf/releases)

### System Requirements
- Operating System: Linux, macOS, or Windows
- RAM: 512MB minimum (1GB recommended)
- Disk Space: 500MB for source and build

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/soroushdeimi/reflex.git
cd reflex
```

### 2. Initialize Submodules (if applicable)

```bash
git submodule update --init --recursive
```

### 3. Install Go Dependencies

```bash
cd xray-core
go mod download
```

### 4. Compile Protocol Buffers

```bash
# Install protoc-gen-go plugin
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

# Compile the proto file
protoc --go_out=. proxy/reflex/config.proto
```

This will generate `proxy/reflex/config.pb.go`.

### 5. Build Xray with Reflex

```bash
# Build for your platform
go build -o xray ./main

# Or build with optimizations
go build -trimpath -ldflags "-s -w" -o xray ./main
```

**Windows users:**
```powershell
go build -o xray.exe ./main
```

### 6. Verify Build

```bash
./xray version
```

You should see Xray version information.

## Cross-Compilation

### Build for Linux (from any OS)
```bash
GOOS=linux GOARCH=amd64 go build -o xray-linux ./main
```

### Build for Windows (from any OS)
```bash
GOOS=windows GOARCH=amd64 go build -o xray-windows.exe ./main
```

### Build for macOS (from any OS)
```bash
GOOS=darwin GOARCH=amd64 go build -o xray-macos ./main
```

### Build for ARM devices
```bash
# Raspberry Pi, Android
GOOS=linux GOARCH=arm64 go build -o xray-arm64 ./main
```

## Configuration

### Server Configuration

1. Copy example config:
```bash
cp config.server.json /etc/xray/config.json
```

2. Edit configuration:
```bash
nano /etc/xray/config.json
```

3. Generate UUIDs for users:
```bash
# Using xray
./xray uuid

# Or using uuidgen (Linux/macOS)
uuidgen

# Or using PowerShell (Windows)
[guid]::NewGuid()
```

4. Update the `clients` array with generated UUIDs.

### Client Configuration

1. Copy example config:
```bash
cp config.client.json ~/.config/xray/config.json
```

2. Edit configuration:
```bash
nano ~/.config/xray/config.json
```

3. Update:
   - `address`: Your server's domain or IP
   - `port`: Your server's port (default 8443)
   - `id`: Your user UUID (must match server)
   - `policy`: Traffic profile (`http2-api`, `youtube`, or `zoom`)

## Deployment

### Linux Server (systemd)

1. Copy binary:
```bash
sudo cp xray /usr/local/bin/
sudo chmod +x /usr/local/bin/xray
```

2. Create systemd service:
```bash
sudo nano /etc/systemd/system/xray.service
```

Add:
```ini
[Unit]
Description=Xray with Reflex Protocol
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

3. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable xray
sudo systemctl start xray
```

4. Check status:
```bash
sudo systemctl status xray
```

### Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /build
COPY reflex/ .

RUN cd xray-core && \
    go mod download && \
    go build -trimpath -ldflags "-s -w" -o /xray ./main

FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=builder /xray /usr/local/bin/xray
COPY config.server.json /etc/xray/config.json

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/xray"]
CMD ["run", "-config", "/etc/xray/config.json"]
```

Build and run:
```bash
docker build -t xray-reflex .
docker run -d -p 8443:8443 --name xray xray-reflex
```

### Using Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  xray:
    build: .
    ports:
      - "8443:8443"
    volumes:
      - ./config.server.json:/etc/xray/config.json:ro
    restart: unless-stopped
```

Run:
```bash
docker-compose up -d
```

## Firewall Configuration

### Allow Reflex Port
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 8443/tcp

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

## Monitoring and Logs

### View Logs
```bash
# Systemd service
sudo journalctl -u xray -f

# Docker
docker logs -f xray

# Direct execution (logs to stdout)
./xray run -config config.json
```

### Check Connections
```bash
# Show established connections
netstat -antp | grep xray

# Or using ss
ss -antp | grep xray
```

## Performance Tuning

### Increase File Descriptor Limits
```bash
# Edit /etc/security/limits.conf
* soft nofile 51200
* hard nofile 51200
```

### Optimize Network Stack
```bash
# Edit /etc/sysctl.conf
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Apply
sudo sysctl -p
```

## Troubleshooting

### Build Errors

**Problem**: `protoc-gen-go: program not found or is not executable`
**Solution**: 
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

**Problem**: `package golang.org/x/crypto/curve25519: cannot find package`
**Solution**:
```bash
go mod download
go mod tidy
```

### Runtime Errors

**Problem**: `bind: address already in use`
**Solution**: Change port in config or kill existing process:
```bash
# Find process using port
lsof -i :8443

# Kill process
kill -9 <PID>
```

**Problem**: `authentication failed`
**Solution**: Verify UUID matches between client and server config.

## Security Best Practices

1. **Use strong UUIDs**: Generate with proper UUID tools
2. **Enable firewall**: Only allow necessary ports
3. **Regular updates**: Keep Xray and Go updated
4. **Monitor logs**: Watch for suspicious activity
5. **Limit users**: Don't share UUIDs publicly
6. **Use HTTPS fallback**: Configure a real web server for fallback

## Production Checklist

- [ ] Built with optimizations (`-trimpath -ldflags "-s -w"`)
- [ ] Unique UUIDs generated for each user
- [ ] Firewall configured correctly
- [ ] Systemd service enabled
- [ ] Logs monitoring configured
- [ ] Fallback web server running
- [ ] Backup configuration stored securely
- [ ] Auto-restart on failure configured

## Support

For issues or questions:
1. Check [FAQ](docs/FAQ.md)
2. Review [Testing Guide](TESTING.md)
3. Check [Implementation Notes](IMPLEMENTATION.md)

---

**Last Updated**: February 20, 2026  
**Build Tested On**: Ubuntu 22.04, macOS 14, Windows 11  
**Go Versions**: 1.21, 1.22
