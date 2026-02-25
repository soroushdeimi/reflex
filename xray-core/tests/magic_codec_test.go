package tests

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex/codec"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
)

func TestMagicClientHandshake_RoundTrip(t *testing.T) {
	var hs handshake.ClientHandshake
	for i := range hs.PublicKey {
		hs.PublicKey[i] = byte(i + 1)
	}
	for i := range hs.UserID {
		hs.UserID[i] = byte(0x10 + i)
	}
	for i := range hs.Nonce {
		hs.Nonce[i] = byte(0xA0 + i)
	}
	hs.Timestamp = 1700000000
	hs.PolicyReq = []byte("policy-req-bytes")

	var buf bytes.Buffer
	if err := codec.WriteMagicClientHandshake(&buf, &hs); err != nil {
		t.Fatalf("WriteMagicClientHandshake: %v", err)
	}

	got, err := codec.ReadMagicClientHandshake(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadMagicClientHandshake: %v", err)
	}

	if got.Timestamp != hs.Timestamp {
		t.Fatalf("timestamp mismatch: got=%d want=%d", got.Timestamp, hs.Timestamp)
	}
	if got.PublicKey != hs.PublicKey {
		t.Fatal("public key mismatch")
	}
	if got.UserID != hs.UserID {
		t.Fatal("user id mismatch")
	}
	if got.Nonce != hs.Nonce {
		t.Fatal("nonce mismatch")
	}
	if !bytes.Equal(got.PolicyReq, hs.PolicyReq) {
		t.Fatalf("policy mismatch: got=%q want=%q", string(got.PolicyReq), string(hs.PolicyReq))
	}
}

func TestMagicClientHandshake_NotReflex(t *testing.T) {
	// 4 bytes wrong magic -> should return KindNotReflex
	data := []byte{0, 1, 2, 3}
	_, err := codec.ReadMagicClientHandshake(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !handshake.IsKind(err, handshake.KindNotReflex) {
		t.Fatalf("expected KindNotReflex, got: %v", err)
	}
}

func TestMagicClientHandshake_ReadPolicyTooLarge(t *testing.T) {
	// Build minimal canonical packet with policyLen > MaxPolicyReqSize
	var b bytes.Buffer
	b.Write(handshake.ReflexMagicBytes[:])
	b.Write(make([]byte, handshake.PublicKeySize))
	b.Write(make([]byte, handshake.UserIDSize))

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(1700000000))
	b.Write(ts[:])

	b.Write(make([]byte, handshake.NonceSize))

	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(handshake.MaxPolicyReqSize+1))
	b.Write(ln[:])

	_, err := codec.ReadMagicClientHandshake(bytes.NewReader(b.Bytes()))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !handshake.IsKind(err, handshake.KindInvalidHandshake) {
		t.Fatalf("expected KindInvalidHandshake, got: %v", err)
	}
}

func TestMagicServerHandshake_RoundTrip(t *testing.T) {
	var hs handshake.ServerHandshake
	for i := range hs.PublicKey {
		hs.PublicKey[i] = byte(0x55 + i)
	}
	hs.PolicyGrant = []byte("grant-bytes")

	var buf bytes.Buffer
	if err := codec.WriteMagicServerHandshake(&buf, &hs); err != nil {
		t.Fatalf("WriteMagicServerHandshake: %v", err)
	}

	got, err := codec.ReadMagicServerHandshake(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadMagicServerHandshake: %v", err)
	}
	if got.PublicKey != hs.PublicKey {
		t.Fatal("public key mismatch")
	}
	if !bytes.Equal(got.PolicyGrant, hs.PolicyGrant) {
		t.Fatalf("grant mismatch: got=%q want=%q", string(got.PolicyGrant), string(hs.PolicyGrant))
	}
}

func TestMagicClientHandshake_WriteNil_Fails(t *testing.T) {
	var buf bytes.Buffer
	if err := codec.WriteMagicClientHandshake(&buf, nil); err == nil {
		t.Fatal("expected error for nil handshake, got nil")
	}
}

func TestMagicServerHandshake_WriteNil_Fails(t *testing.T) {
	var buf bytes.Buffer
	if err := codec.WriteMagicServerHandshake(&buf, nil); err == nil {
		t.Fatal("expected error for nil handshake, got nil")
	}
}
