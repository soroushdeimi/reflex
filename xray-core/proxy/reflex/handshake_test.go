package reflex

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHandshakeFullCycle(t *testing.T) {
	clientPriv, clientPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	testUUID := uuid.New()
	var userID [16]byte
	copy(userID[:], testUUID[:])

	nonce, _ := GenerateNonce()

	clientHS := &ClientHandshake{
		PublicKey: clientPub,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
		PolicyReq: []byte("test-policy"),
	}

	marshaled := MarshalClientHandshake(clientHS)

	unmarshaled, err := UnmarshalClientHandshake(marshaled)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !bytes.Equal(unmarshaled.PublicKey[:], clientHS.PublicKey[:]) {
		t.Error("PublicKey mismatch")
	}
	if unmarshaled.UserID != clientHS.UserID {
		t.Error("UserID mismatch")
	}
	if !ValidateTimestamp(unmarshaled.Timestamp) {
		t.Error("Timestamp validation failed")
	}
	if !bytes.Equal(unmarshaled.PolicyReq, clientHS.PolicyReq) {
		t.Error("PolicyReq mismatch")
	}

	serverPriv, serverPub, _ := GenerateKeyPair()
	serverHS := &ServerHandshake{
		PublicKey:   serverPub,
		Timestamp:   time.Now().Unix(),
		PolicyGrant: []byte("grant-ok"),
	}

	serverMarshaled := MarshalServerHandshake(serverHS)
	serverUnmarshaled, err := UnmarshalServerHandshake(serverMarshaled)
	if err != nil {
		t.Fatalf("Server Unmarshal failed: %v", err)
	}

	if !bytes.Equal(serverUnmarshaled.PublicKey[:], serverPub[:]) {
		t.Error("Server PublicKey mismatch")
	}

	shared1, _ := DeriveSharedKey(clientPriv, serverPub)
	shared2, _ := DeriveSharedKey(serverPriv, clientPub)

	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Error("Shared secret DH exchange failed")
	}
}

func TestInvalidHandshake(t *testing.T) {
	shortData := make([]byte, 10)
	_, err := UnmarshalClientHandshake(shortData)
	if err == nil {
		t.Error("Should have failed on short data")
	}

	oldTimestamp := time.Now().Add(-5 * time.Minute).Unix()
	if ValidateTimestamp(oldTimestamp) {
		t.Error("Should have rejected old timestamp")
	}
}
