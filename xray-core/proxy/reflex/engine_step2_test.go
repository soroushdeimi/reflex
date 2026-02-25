package reflex

import (
	"bufio"
	"net"
	"testing"
	"time"

	"crypto/ecdh"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex/codec"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
)

func TestHTTPHandshakeSuccess(t *testing.T) {
	// Arrange: a known UUID
	id, err := uuid.ParseString("d89d6641-3b1a-4f51-a194-9c9109fd21b6")
	if err != nil {
		t.Fatal(err)
	}
	var userID [handshake.UserIDSize]byte
	copy(userID[:], id.Bytes())

	// Validator with one client
	mv := NewMemoryValidator()
	if err := mv.Add(&ClientInfo{ID: id, Policy: "default"}); err != nil {
		t.Fatal(err)
	}

	eng := NewHandshakeEngine(mv)
	eng.Replay = handshake.NewReplayCache(0)

	// net.Pipe: client <-> server
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Server goroutine
	serverResCh := make(chan *SessionInfo, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		si, e := runServerHandshakeOnce(serverConn, eng)
		if e != nil {
			serverErrCh <- e
			return
		}
		serverResCh <- si
	}()

	// Client side
	clientEngine := NewClientHandshakeEngine(userID, "example.com")
	clientEngine.Now = func() time.Time { return time.Now() }

	siClient, err := clientEngine.DoHandshakeHTTP(clientConn)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	// Server result
	select {
	case e := <-serverErrCh:
		t.Fatalf("server handshake failed: %v", e)
	case siServer := <-serverResCh:
		// Assert: both derived the same session key
		if siServer == nil {
			t.Fatal("nil server session info")
		}
		if siServer.Flavor != WireHTTP {
			t.Fatalf("expected server flavor WireHTTP, got %v", siServer.Flavor)
		}
		if siClient.SessionKey != siServer.SessionKey {
			t.Fatalf("session keys mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server result")
	}
}

func TestHTTPHandshakeUnauthForbidden(t *testing.T) {
	// Server knows only this UUID
	idOK, err := uuid.ParseString("d89d6641-3b1a-4f51-a194-9c9109fd21b6")
	if err != nil {
		t.Fatal(err)
	}
	mv := NewMemoryValidator()
	if err := mv.Add(&ClientInfo{ID: idOK, Policy: "default"}); err != nil {
		t.Fatal(err)
	}
	eng := NewHandshakeEngine(mv)
	eng.Replay = handshake.NewReplayCache(0)

	// Client uses a different UUID (unauthorized)
	idBad, err := uuid.ParseString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	var badUserID [handshake.UserIDSize]byte
	copy(badUserID[:], idBad.Bytes())

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		defer serverConn.Close()
		_, _ = runServerHandshakeOnce(serverConn, eng) // wrapper will write 403-like response
	}()

	clientEngine := NewClientHandshakeEngine(badUserID, "example.com")
	_, err = clientEngine.DoHandshakeHTTP(clientConn)
	if err == nil {
		t.Fatal("expected unauth error, got nil")
	}
	// We don't require exact Kind here (client sees non-2xx -> unauth), just ensure it fails.
}

func TestHTTPHandshakeReplayNonce(t *testing.T) {
	id, err := uuid.ParseString("d89d6641-3b1a-4f51-a194-9c9109fd21b6")
	if err != nil {
		t.Fatal(err)
	}
	var userID [handshake.UserIDSize]byte
	copy(userID[:], id.Bytes())

	mv := NewMemoryValidator()
	if err := mv.Add(&ClientInfo{ID: id, Policy: "default"}); err != nil {
		t.Fatal(err)
	}

	eng := NewHandshakeEngine(mv)
	eng.Replay = handshake.NewReplayCache(0)

	// Fixed nonce to force replay
	var fixedNonce [handshake.NonceSize]byte
	for i := range fixedNonce {
		fixedNonce[i] = 0x11
	}
	ts := time.Now().Unix()

	// First attempt should succeed
	{
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		go func() {
			defer serverConn.Close()
			_, _ = runServerHandshakeOnce(serverConn, eng)
		}()

		// Build a deterministic client handshake using our codecs directly (so we can reuse nonce)
		hs, clientPriv := buildClientHandshakeForTest(t, userID, fixedNonce, ts)
		if err := codec.WriteHTTPClientHandshake(clientConn, hs, codec.DefaultHTTPOptions("example.com")); err != nil {
			t.Fatalf("write http client handshake: %v", err)
		}
		shs, err := codec.ReadHTTPServerHandshake(bufio.NewReader(clientConn))
		if err != nil {
			t.Fatalf("read http server handshake: %v", err)
		}
		shared, err := handshake.ComputeSharedKey(clientPriv, shs.PublicKey)
		if err != nil {
			t.Fatalf("compute shared: %v", err)
		}
		_, err = handshake.DeriveSessionKeyWithNonce(shared, fixedNonce)
		if err != nil {
			t.Fatalf("derive session key: %v", err)
		}
	}

	// Second attempt with SAME (userID, nonce) should fail (replay)
	{
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		go func() {
			defer serverConn.Close()
			_, _ = runServerHandshakeOnce(serverConn, eng) // wrapper returns 403-like for replay
		}()

		hs, _ := buildClientHandshakeForTest(t, userID, fixedNonce, ts)
		if err := codec.WriteHTTPClientHandshake(clientConn, hs, codec.DefaultHTTPOptions("example.com")); err != nil {
			t.Fatalf("write http client handshake: %v", err)
		}

		// Client should see non-2xx response and error
		_, err := codec.ReadHTTPServerHandshake(bufio.NewReader(clientConn))
		if err == nil {
			t.Fatal("expected replay to fail, got nil")
		}
	}
}

// runServerHandshakeOnce executes server handshake using the same error behavior as inbound.Process:
// if it looks HTTP and handshake fails => write 403/400/500-like response so client won't deadlock.
func runServerHandshakeOnce(serverConn net.Conn, eng *HandshakeEngine) (*SessionInfo, error) {
	r := bufio.NewReader(serverConn)
	peeked, _ := r.Peek(64)
	looksHTTP := codec.LooksLikeHTTPPost(peeked)

	si, err := eng.ServerDoHandshake(r, serverConn)
	if err != nil && looksHTTP {
		switch {
		case handshake.IsKind(err, handshake.KindUnauthenticated),
			handshake.IsKind(err, handshake.KindReplay):
			_ = WriteHTTPForbidden(serverConn)
		case handshake.IsKind(err, handshake.KindInvalidHandshake):
			_ = WriteHTTPBadRequest(serverConn)
		default:
			_, _ = serverConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"))
		}
	}
	return si, err
}

func buildClientHandshakeForTest(t *testing.T, userID [handshake.UserIDSize]byte, nonce [handshake.NonceSize]byte, ts int64) (*handshake.ClientHandshake, *ecdh.PrivateKey) {
	t.Helper()

	kp, err := handshake.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	policyReqPlain := []byte(`{"want":"default"}`)
	policyReqEnc, err := handshake.EncryptPolicyReq(userID, nonce, ts, policyReqPlain)
	if err != nil {
		t.Fatalf("encrypt policy req: %v", err)
	}

	hs := &handshake.ClientHandshake{
		PublicKey: kp.Public,
		UserID:    userID,
		PolicyReq: policyReqEnc,
		Timestamp: ts,
		Nonce:     nonce,
	}
	return hs, kp.Private
}
