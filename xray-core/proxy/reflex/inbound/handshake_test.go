package inbound

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func TestKeyDerivation(t *testing.T) {
	clientPriv, clientPub, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, serverPub, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sharedClient := deriveSharedKey(clientPriv, serverPub)
	sharedServer := deriveSharedKey(serverPriv, clientPub)
	if !bytes.Equal(sharedClient[:], sharedServer[:]) {
		t.Fatal("shared secrets must match")
	}
	salt := []byte("reflex-session")
	keyClient := deriveSessionKey(sharedClient, salt)
	keyServer := deriveSessionKey(sharedServer, salt)
	if !bytes.Equal(keyClient, keyServer) {
		t.Fatal("session keys must match")
	}
	if len(keyClient) != 32 {
		t.Errorf("session key length = %d, want 32", len(keyClient))
	}
}

func TestAuthenticateUser(t *testing.T) {
	u := uuid.New()
	idStr := u.String()
	h := &Handler{
		clients: []*protocol.MemoryUser{
			{
				Email:   idStr,
				Account: &MemoryAccount{Id: idStr, Policy: "http2-api"},
			},
		},
	}
	user := h.authenticateUser(u)
	if user == nil {
		t.Fatal("authenticateUser with valid UUID should return user")
	}
	if user.Account.(*MemoryAccount).Id != idStr {
		t.Errorf("user id = %q, want %q", user.Account.(*MemoryAccount).Id, idStr)
	}
	// Wrong UUID
	var wrong [16]byte
	for i := range wrong {
		wrong[i] = ^u[i]
	}
	if h.authenticateUser(wrong) != nil {
		t.Error("authenticateUser with wrong UUID should return nil")
	}
}

func TestReadWriteHandshakeMagic(t *testing.T) {
	clientHS := &ClientHandshake{}
	_, _, _ = generateKeyPair()
	copy(clientHS.PublicKey[:], bytes.Repeat([]byte{0x01}, 32))
	uid := uuid.New()
	copy(clientHS.UserID[:], uid[:])
	clientHS.Timestamp = 12345
	copy(clientHS.Nonce[:], bytes.Repeat([]byte{0x02}, 16))
	var buf bytes.Buffer
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], ReflexMagic)
	buf.Write(magic[:])
	buf.Write(clientHS.PublicKey[:])
	buf.Write(clientHS.UserID[:])
	_ = binary.Write(&buf, binary.BigEndian, clientHS.Timestamp)
	buf.Write(clientHS.Nonce[:])
	// Read it back
	read, err := readClientHandshakeMagic(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read.PublicKey[:], clientHS.PublicKey[:]) ||
		!bytes.Equal(read.UserID[:], clientHS.UserID[:]) ||
		read.Timestamp != clientHS.Timestamp ||
		!bytes.Equal(read.Nonce[:], clientHS.Nonce[:]) {
		t.Error("roundtrip handshake mismatch")
	}
	// Server response
	serverHS := &ServerHandshake{}
	copy(serverHS.PublicKey[:], bytes.Repeat([]byte{0x03}, 32))
	if err := writeServerHandshakeMagic(&buf, serverHS); err != nil {
		t.Fatal(err)
	}
	// Just check it was written (no readServerHandshake in production; client parses it)
	if buf.Len() < 4+32+2 {
		t.Error("server handshake too short")
	}
}

