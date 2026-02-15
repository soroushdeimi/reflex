package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ReflexMagic = 0x5246584C

	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

func main() {
	serverAddr := "127.0.0.1:4433"

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("Connected to Reflex server")

	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	reader := bufio.NewReader(conn)

	var clientPriv [32]byte
	if _, err := rand.Read(clientPriv[:]); err != nil {
		panic(err)
	}

	clientPubBytes, err := curve25519.X25519(clientPriv[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	var clientPub [32]byte
	copy(clientPub[:], clientPubBytes)

	var magicBuf [4]byte
	binary.BigEndian.PutUint32(magicBuf[:], ReflexMagic)
	if _, err := conn.Write(magicBuf[:]); err != nil {
		panic(err)
	}

	if _, err := conn.Write(clientPub[:]); err != nil {
		panic(err)
	}

	// UUID is matched to server config.json
	u, err := uuid.Parse("9de7eecb-e9d5-46c5-bd96-f3df3268d099")
	if err != nil {
		panic(err)
	}
	if _, err := conn.Write(u[:]); err != nil {
		panic(err)
	}

	if err := binary.Write(conn, binary.BigEndian, time.Now().Unix()); err != nil {
		panic(err)
	}

	var nonce16 [16]byte
	if _, err := rand.Read(nonce16[:]); err != nil {
		panic(err)
	}
	if _, err := conn.Write(nonce16[:]); err != nil {
		panic(err)
	}

	if err := readUntilHTTP(reader); err != nil {
		panic(err)
	}

	fmt.Println("Handshake complete")

	var serverPub [32]byte
	if _, err := io.ReadFull(reader, serverPub[:]); err != nil {
		panic(err)
	}

	sharedBytes, err := curve25519.X25519(clientPriv[:], serverPub[:])
	if err != nil {
		panic(err)
	}
	var shared [32]byte
	copy(shared[:], sharedBytes)

	sessionKey := deriveSessionKey(shared, []byte("reflex-session"))

	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		panic(err)
	}

	payload := buildHTTPPayload()
	if err := writeFrame(conn, aead, FrameTypeData, payload, 0); err != nil {
		panic(err)
	}

	var readNonce uint64 = 0

	for {
		ft, plaintext, err := readFrame(reader, aead, readNonce)
		if err != nil {
			panic(err)
		}
		readNonce++

		if ft == FrameTypeClose {
			fmt.Println("\n[server closed]")
			return
		}

		if ft == FrameTypeData {
			fmt.Print(string(plaintext))
		}
	}
}

func buildHTTPPayload() []byte {
	host := "example.com"
	port := uint16(80)

	dest := make([]byte, 1+1+len(host)+2)
	dest[0] = 2
	dest[1] = byte(len(host))
	copy(dest[2:], host)
	binary.BigEndian.PutUint16(dest[2+len(host):], port)

	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

	return append(dest, httpReq...)
}

func readUntilHTTP(r *bufio.Reader) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" {
			return nil
		}
	}
}

func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	h := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	_, _ = h.Read(sessionKey)
	return sessionKey
}

func writeFrame(w io.Writer, aead cipher.AEAD, frameType uint8, plaintext []byte, nonceCounter uint64) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], nonceCounter)

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(ciphertext)))
	header[2] = frameType

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader, aead cipher.AEAD, nonceCounter uint64) (uint8, []byte, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return 0, nil, err
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], nonceCounter)

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, nil, err
	}

	return frameType, plaintext, nil
}
