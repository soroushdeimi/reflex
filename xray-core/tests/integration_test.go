package reflex_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func TestXrayIntegration(t *testing.T) {
	uID := uuid.New().String()
	serverLn, _ := net.Listen("tcp", "127.0.0.1:0")
	serverPort := uint32(serverLn.Addr().(*net.TCPAddr).Port)
	serverLn.Close()

	targetLn, _ := net.Listen("tcp", "127.0.0.1:0")
	targetPort := uint32(targetLn.Addr().(*net.TCPAddr).Port)

	// Start a mock target server
	defer targetLn.Close()
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil { return }
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // Echo
			}()
		}
	}()

	serverConfigJSON := fmt.Sprintf(`{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"port": %d,
			"protocol": "reflex",
			"settings": {
				"clients": [{"id": "%s"}]
			}
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`, serverPort, uID)

	clientConfigJSON := fmt.Sprintf(`{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"port": 0,
			"protocol": "dokodemo-door",
			"settings": {
				"address": "127.0.0.1",
				"port": %d,
				"network": "tcp"
			}
		}],
		"outbounds": [{
			"protocol": "reflex",
			"settings": {
				"address": "127.0.0.1",
				"port": %d,
				"id": "%s"
			}
		}]
	}`, targetPort, serverPort, uID)

	// Start Server
	serverConfig, err := core.LoadConfig("json", strings.NewReader(serverConfigJSON))
	if err != nil { t.Fatalf("failed to load server config: %v", err) }
	server, err := core.New(serverConfig)
	if err != nil { t.Fatal(err) }
	common.Must(server.Start())
	defer server.Close()

	// Start Client
	clientConfig, err := core.LoadConfig("json", strings.NewReader(clientConfigJSON))
	if err != nil { t.Fatalf("failed to load client config: %v", err) }
	client, err := core.New(clientConfig)
	if err != nil { t.Fatal(err) }
	common.Must(client.Start())
	defer client.Close()

	// Wait for servers to start
	time.Sleep(500 * time.Millisecond)

	// Connect to client's inbound (dokodemo-door)
	// We need to find the port of dokodemo-door inbound.
	// Since we set port to 0, it's dynamic. Let's fix the port to avoid complexity.
	// Re-generating config with fixed client port.
	tmpInboundLn, _ := net.Listen("tcp", "127.0.0.1:0")
	clientInboundPort := uint32(tmpInboundLn.Addr().(*net.TCPAddr).Port)
	tmpInboundLn.Close()
	clientConfigJSONFixed := fmt.Sprintf(`{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"port": %d,
			"protocol": "dokodemo-door",
			"settings": {
				"address": "127.0.0.1",
				"port": %d,
				"network": "tcp"
			}
		}],
		"outbounds": [{
			"protocol": "reflex",
			"settings": {
				"address": "127.0.0.1",
				"port": %d,
				"id": "%s"
			}
		}]
	}`, clientInboundPort, targetPort, serverPort, uID)

	client.Close()
	clientConfig, _ = core.LoadConfig("json", strings.NewReader(clientConfigJSONFixed))
	client, _ = core.New(clientConfig)
	common.Must(client.Start())

	time.Sleep(500 * time.Millisecond)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", clientInboundPort))
	if err != nil { t.Fatalf("failed to dial client: %v", err) }
	defer conn.Close()

	testData := []byte("integration test payload")
	conn.Write(testData)

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, buf)
	if err != nil { t.Fatalf("failed to read response: %v", err) }

	if string(buf) != string(testData) {
		t.Errorf("expected %s, got %s", string(testData), string(buf))
	}
}
