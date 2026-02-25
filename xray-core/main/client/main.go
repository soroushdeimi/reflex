package main

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func main() {
	fmt.Println("================================================")
	fmt.Println("  Reflex Protocol Demo  CLIENT")
	fmt.Println("  Steps 1-5: All features in one demo")
	fmt.Println("================================================")
	fmt.Println()

	// Step 1: Outbound config
	fmt.Println("[ Step 1 ] Outbound config loaded:")
	fmt.Println("          Server: 127.0.0.1:10086")
	fmt.Println("          UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	fmt.Println()

	time.Sleep(300 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:10086")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()
	fmt.Println("[ Step 1 ] Connected to server 127.0.0.1:10086")
	fmt.Println()

	// Step 2: Generate ephemeral X25519 key pair
	clientPriv, clientPub, _ := reflex.GenerateKeyPair()
	fmt.Printf("[ Step 2 ] Generated ephemeral X25519 keypair\n")
	fmt.Printf("[ Step 2 ] Client PubKey: %x...\n", clientPub[:8])

	// Step 2: Build handshake: magic(4) + clientPubKey(32) + userID(16) = 52 bytes
	var handshake [52]byte
	handshake[0] = reflex.ReflexMagicByte0
	handshake[1] = reflex.ReflexMagicByte1
	handshake[2] = reflex.ReflexMagicByte2
	handshake[3] = reflex.ReflexMagicByte3
	copy(handshake[4:36], clientPub[:])
	copy(handshake[36:52], []byte("a1b2c3d4e5f67890"))

	fmt.Println("[ Step 2 ] Sending implicit handshake (magic + X25519 PubKey + UUID)...")
	conn.Write(handshake[:])

	// Step 2: Wait for server public key response
	var serverPub [32]byte
	_, err = io.ReadFull(conn, serverPub[:])
	if err != nil {
		fmt.Println("[ Step 2 ] Error reading server pubkey:", err)
		return
	}
	fmt.Printf("[ Step 2 ] Server PubKey received: %x...\n", serverPub[:8])

	// Step 2: Derive session key using same salt (clientPub[:16])
	shared, _ := reflex.DeriveSharedSecret(clientPriv, serverPub)
	sessionKey, _ := reflex.DeriveSessionKey(shared, clientPub[:16])
	fmt.Printf("[ Step 2 ] Shared Secret:  %x... (X25519)\n", shared[:8])
	fmt.Printf("[ Step 2 ] Session Key:    %x... (HKDF-SHA256)\n", sessionKey[:8])
	fmt.Println("[ Step 2 ] Handshake complete!")
	fmt.Println()

	// Step 3: Send encrypted data frames with ChaCha20-Poly1305
	fw, _ := reflex.NewFrameWriter(conn, sessionKey)
	msg := []byte("Hello from Reflex client! This is encrypted.")
	fw.Write(msg)
	fmt.Println("[ Step 3 ] Encrypted frame sent (ChaCha20-Poly1305 AEAD)")
	fmt.Printf("[ Step 3 ] Plaintext:  %q\n", msg)
	fmt.Println()

	// Step 4: Fallback demo (conceptual  server used bufio.Peek)
	fmt.Println("[ Step 4 ] Note: Server used bufio.Peek to detect this as Reflex.")
	fmt.Println("           Any non-Reflex connection would have been forwarded to :8080")
	fmt.Println()

	// Step 5: Traffic Morphing
	p := reflex.Profiles["youtube"]
	if p != nil {
		fmt.Println("[ Step 5 ] Traffic morphing: YouTube profile active")
		delay := p.GetDelay()
		size := p.GetPacketSize()
		fmt.Printf("[ Step 5 ] Morphed packet size: %d bytes\n", size)
		fmt.Printf("[ Step 5 ] Morphed delay: %v\n", delay)
		time.Sleep(delay)
	}

	// Step 3: Read encrypted response
	fr, _ := reflex.NewFrameReader(conn, sessionKey)
	buf := make([]byte, 4096)
	n, err := fr.Read(buf)
	if err != nil {
		fmt.Printf("[ Step 3 ] Server response read: %v\n", err)
	} else {
		fmt.Printf("[ Step 3 ] Server response (decrypted): %q\n", buf[:n])
	}

	fmt.Println()
	fmt.Println("[ All Steps ] Demo complete.")
	fmt.Println("================================================")
}
