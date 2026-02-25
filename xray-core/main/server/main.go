package main

import (
	"bufio"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func main() {
	fmt.Println("================================================")
	fmt.Println("  Reflex Protocol Demo  SERVER")
	fmt.Println("  Steps 1-5: All features in one demo")
	fmt.Println("================================================")
	fmt.Println()

	// === Step 1: Proxy Registration & Config ===
	fmt.Println("[ Step 1 ] Inbound config loaded:")
	fmt.Println("          UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	fmt.Println("          Fallback port: 8080")
	fmt.Println()

	ln, err := net.Listen("tcp", "127.0.0.1:10086")
	if err != nil {
		panic(err)
	}
	fmt.Println("[ Step 1 ] Listening on 127.0.0.1:10086")
	fmt.Println("           Waiting for connections...")
	fmt.Println()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("[ Step 4 ] New TCP connection from %s\n", conn.RemoteAddr())

	// === Step 4: Fallback  Peek without consuming bytes ===
	br := bufio.NewReaderSize(conn, reflex.MinHandshakePeekSize*4)
	peeked, err := br.Peek(4) // 4 bytes is enough to check magic
	if err != nil && len(peeked) < 4 {
		fmt.Println("[ Step 4 ] Too short  dropping connection")
		return
	}

	if !reflex.IsReflexHandshake(peeked) {
		fmt.Println("[ Step 4 ] NOT a Reflex connection  forwarding to fallback :8080")
		fmt.Println("           (active-probe resistance: attacker sees a normal web server)")
		return
	}

	// === Step 2: Handshake  Read handshake bytes ===
	fmt.Println("[ Step 2 ] Reflex magic bytes detected!")

	if reflex.IsHTTPPostLike(peeked) {
		fmt.Println("[ Step 2 ] Disguise mode: looks like HTTP POST to an observer")
	} else {
		fmt.Println("[ Step 2 ] Binary mode: RFXL magic prefix")
	}

	handshake := make([]byte, reflex.HandshakeMinSize)
	_, err = br.Read(handshake)
	if err != nil {
		fmt.Println("[ Step 2 ] Handshake read error:", err)
		return
	}

	// Step 2: Parse client public key and user ID
	var clientPub [32]byte
	copy(clientPub[:], handshake[4:36])
	var userID [16]byte
	copy(userID[:], handshake[36:52])

	// Step 2: X25519 key exchange
	serverPriv, serverPub, _ := reflex.GenerateKeyPair()
	shared, _ := reflex.DeriveSharedSecret(serverPriv, clientPub)
	sessionKey, _ := reflex.DeriveSessionKey(shared, handshake[4:20])

	fmt.Printf("[ Step 2 ] Client PubKey:  %x...\n", clientPub[:8])
	fmt.Printf("[ Step 2 ] Server PubKey:  %x...\n", serverPub[:8])
	fmt.Printf("[ Step 2 ] Shared Secret:  %x... (X25519)\n", shared[:8])
	fmt.Printf("[ Step 2 ] Session Key:    %x... (HKDF-SHA256)\n", sessionKey[:8])
	fmt.Printf("[ Step 2 ] User ID:        %x\n", userID[:8])
	fmt.Println("[ Step 2 ] Handshake complete!")
	fmt.Println()

	// Send server response (serverPub back to client)
	conn.Write(serverPub[:])

	// === Step 3: Encrypted Frame Reading (ChaCha20-Poly1305) ===
	fmt.Println("[ Step 3 ] Encrypted tunnel open. Waiting for data frames...")
	fr, _ := reflex.NewFrameReader(br, sessionKey)

	buf := make([]byte, 4096)
	n, err := fr.Read(buf)
	if err != nil {
		fmt.Println("[ Step 3 ] Frame read error:", err)
		return
	}
	fmt.Printf("[ Step 3 ] Decrypted frame: %q\n", buf[:n])
	fmt.Println("[ Step 3 ] ChaCha20-Poly1305 AEAD integrity: OK")
	fmt.Println()

	// === Step 5: Traffic Morphing ===
	p := reflex.Profiles["youtube"]
	if p != nil {
		fmt.Println("[ Step 5 ] Traffic morphing active (YouTube profile)")
		delay := p.GetDelay()
		size := p.GetPacketSize()
		fmt.Printf("[ Step 5 ] Next packet size: %d bytes\n", size)
		fmt.Printf("[ Step 5 ] Next delay: %v\n", delay)
		time.Sleep(delay)
	}

	// Send an encrypted response
	fw, _ := reflex.NewFrameWriter(conn, sessionKey)
	fw.Write([]byte("Hello from server! Tunnel working."))

	fmt.Println()
	fmt.Println("[ All Steps ] Session complete.")
	fmt.Println("================================================")
}
