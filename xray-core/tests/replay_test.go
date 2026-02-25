package tests

import (
	"bufio"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/codec"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
)

func TestReflex_ReplayProtection_Magic(t *testing.T) {
	// same UUID used in other tests
	idStr := "d89d6641-3b1a-4f51-a194-9c9109fd21b6"
	id, err := uuid.ParseString(idStr)
	if err != nil {
		t.Fatal(err)
	}

	// validator accepts this client
	mv := reflex.NewMemoryValidator()
	if err := mv.Add(&reflex.ClientInfo{ID: id, Policy: "default"}); err != nil {
		t.Fatal(err)
	}
	serverEng := reflex.NewHandshakeEngine(mv)

	// fixed userID + nonce (replay key is typically userID+nonce)
	var userID [handshake.UserIDSize]byte
	copy(userID[:], id.Bytes())

	var nonce [handshake.NonceSize]byte
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}

	// fresh timestamp to pass ValidateTimestamp inside server handshake
	ts := time.Now().Unix()

	// build a valid magic client handshake with encrypted policy
	kp, err := handshake.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	plainPolicy := []byte(`{"want":"default"}`)
	encPolicy, err := handshake.EncryptPolicyReq(userID, nonce, ts, plainPolicy)
	if err != nil {
		t.Fatalf("EncryptPolicyReq: %v", err)
	}

	ch := &handshake.ClientHandshake{
		PublicKey:  kp.Public,
		UserID:     userID,
		Timestamp:  ts,
		Nonce:      nonce,
		PolicyReq:  encPolicy,
	}

	// 1) First handshake should succeed
	if err := doMagicHandshakeOnce(t, serverEng, ch, false); err != nil {
		t.Fatalf("first handshake failed unexpectedly: %v", err)
	}

	// 2) Second handshake with SAME nonce should be rejected as replay
	if err := doMagicHandshakeOnce(t, serverEng, ch, true); err != nil {
		t.Fatalf("second handshake expected replay but got: %v", err)
	}
}

func doMagicHandshakeOnce(t *testing.T, serverEng *reflex.HandshakeEngine, ch *handshake.ClientHandshake, expectReplay bool) error {
	t.Helper()

	clientConn, serverConn := stdnet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))

	serverErrCh := make(chan error, 1)

	// server side
	go func() {
		defer serverConn.Close()
		br := bufio.NewReader(serverConn)
		_, err := serverEng.ServerDoHandshake(br, serverConn)
		serverErrCh <- err
	}()

	// client writes magic handshake
	if err := codec.WriteMagicClientHandshake(clientConn, ch); err != nil {
		return err
	}

	// client reads something to avoid blocking server writes on net.Pipe
	br := bufio.NewReader(clientConn)
	if !expectReplay {
		// success case: parse server handshake (magic)
		_, _ = codec.ReadMagicServerHandshake(br)
	} else {
		// replay case: server may write nothing or error-response; just try to read a bit
		tmp := make([]byte, 256)
		_, _ = br.Read(tmp)
	}

	// wait server result
	err := <-serverErrCh
	if !expectReplay {
		if err != nil {
			return err
		}
		return nil
	}

	// expect KindReplay
	if err == nil {
		return handshake.New(handshake.KindReplay, "expected replay error, got nil")
	}
	if !handshake.IsKind(err, handshake.KindReplay) {
		return err
	}
	return nil
}
