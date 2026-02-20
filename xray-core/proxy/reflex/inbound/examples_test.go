package inbound_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"github.com/xtls/xray-core/proxy/reflex"
)

func ExampleNewSession() {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return
	}

	session, err := reflex.NewSession(key)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
	_ = session
	fmt.Println("Session created successfully")
	// Output: Session created successfully
}

func ExampleSession_WriteFrame() {
	key := make([]byte, 32) // In real usage, derived from ECDH
	session, _ := reflex.NewSession(key)

	// Mock writer
	writer := io.Discard

	data := []byte("hello reflex")
	err := session.WriteFrame(writer, reflex.FrameTypeData, data)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
}

func ExampleSession_WriteFrameWithMorphing() {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)

	// Retrieve a specific profile
	profile := reflex.Profiles["youtube"]

	// Mock connection
	c1, _ := net.Pipe()

	data := []byte("video data")
	err := session.WriteFrameWithMorphing(c1, reflex.FrameTypeData, data, profile)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
}
