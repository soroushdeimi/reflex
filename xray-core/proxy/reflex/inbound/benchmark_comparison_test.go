package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

func BenchmarkReflexEncryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)
	data := make([]byte, 1024)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.WriteFrame(c1, reflex.FrameTypeData, data)
	}
}

func BenchmarkReflexHandshake(b *testing.B) {
	userID := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: userID.String()},
		},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	// Pre-generate handshake data
	_, pub, _ := reflex.GenerateKeyPair()
	var uID [16]byte
	copy(uID[:], userID.Bytes())

	clientHS := reflex.ClientHandshake{
		PublicKey: pub,
		UserID:    uID,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{1, 2, 3},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c1, c2 := stdnet.Pipe()

		go func() {
			handler.processHandshake(context.Background(), bufio.NewReader(c2), &MockConnection{Conn: c2}, nil, clientHS)
			c2.Close()
		}()

		io.Copy(io.Discard, c1)
		c1.Close()
	}
}

func BenchmarkReflexMorphing_YouTube(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)
	profile := reflex.Profiles["youtube"]
	if profile == nil {
		b.Log("youtube profile not found")
	}
	data := make([]byte, 1024)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 8192)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.WriteFrameWithMorphing(c1, reflex.FrameTypeData, data, profile)
	}
}

func BenchmarkReflexMorphing_Zoom(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)
	profile := reflex.Profiles["zoom"]
	data := make([]byte, 1024)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 8192)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.WriteFrameWithMorphing(c1, reflex.FrameTypeData, data, profile)
	}
}

func BenchmarkComparison(b *testing.B) {
	b.Run("Reflex-Encryption-Only", BenchmarkReflexEncryption)
	b.Run("Reflex-YouTube-Morphing", BenchmarkReflexMorphing_YouTube)
	b.Run("Reflex-Zoom-Morphing", BenchmarkReflexMorphing_Zoom)
}
