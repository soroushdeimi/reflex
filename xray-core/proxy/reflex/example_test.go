package reflex_test

import (
	"bytes"
	"net"

	"github.com/xtls/xray-core/proxy/reflex"
)

func ExampleNewSession() {
	sessionKey := make([]byte, 32)
	// In production, derive from key exchange (e.g. X25519 + HKDF).
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		panic(err)
	}
	_ = session
	// Output:
}

func ExampleSession_WriteFrame() {
	sessionKey := make([]byte, 32)
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		panic(err)
	}

	// writer can be net.Conn, bytes.Buffer, or any io.Writer.
	var buf bytes.Buffer
	data := []byte("hello world")
	err = session.WriteFrame(&buf, reflex.FrameTypeData, data)
	if err != nil {
		panic(err)
	}
	_ = buf.Bytes()
	// Output:
}

func ExampleSession_WriteFrame_connection() {
	sessionKey := make([]byte, 32)
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		panic(err)
	}

	conn, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	err = session.WriteFrame(conn, reflex.FrameTypeData, []byte("payload"))
	if err != nil {
		panic(err)
	}
}
