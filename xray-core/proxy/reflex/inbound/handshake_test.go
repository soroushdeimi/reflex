package inbound

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func TestCryptoDerivations(t *testing.T) {
	sk1, pk1, _ := generateKeyPair()
	sk2, pk2, _ := generateKeyPair()

	s1 := deriveSharedKey(sk1, pk2)
	s2 := deriveSharedKey(sk2, pk1)

	if s1 != s2 {
		t.Fatalf("ECDH mismatch")
	}

	hkdfSalt := []byte("reflex-session")
	k1 := deriveSessionKey(s1, hkdfSalt)
	k2 := deriveSessionKey(s2, hkdfSalt)

	if !bytes.Equal(k1, k2) || len(k1) != 32 {
		t.Fatalf("HKDF failed or bad length")
	}
}

func TestUserAuthValidation(t *testing.T) {
	fakeUUID := uuid.New()
	refStr := fakeUUID.String()

	inst := &Handler{
		clients: []*protocol.MemoryUser{
			{Email: refStr, Account: &MemoryAccount{Id: refStr, Policy: "test-pol"}},
		},
	}

	if res := inst.authenticateUser(fakeUUID); res == nil || res.Account.(*MemoryAccount).Id != refStr {
		t.Fatal("Valid user rejected")
	}

	badUUID := fakeUUID
	badUUID[0] ^= 0xFF
	if inst.authenticateUser(badUUID) != nil {
		t.Fatal("Invalid user accepted")
	}
}

func TestMagicReadWriteCycle(t *testing.T) {
	hsIn := &ClientHandshake{Timestamp: 987654321}
	copy(hsIn.PublicKey[:], bytes.Repeat([]byte{0xAA}, 32))
	copy(hsIn.UserID[:], bytes.Repeat([]byte{0xBB}, 16))
	copy(hsIn.Nonce[:], bytes.Repeat([]byte{0xCC}, 16))

	var stream bytes.Buffer
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, ReflexMagic)

	stream.Write(head)
	stream.Write(hsIn.PublicKey[:])
	stream.Write(hsIn.UserID[:])
	binary.Write(&stream, binary.BigEndian, hsIn.Timestamp)
	stream.Write(hsIn.Nonce[:])

	parsed, err := readClientHandshakeMagic(&stream)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Timestamp != hsIn.Timestamp || parsed.PublicKey != hsIn.PublicKey || parsed.UserID != hsIn.UserID || parsed.Nonce != hsIn.Nonce {
		t.Fatal("Data corruption during read")
	}

	srvHs := &ServerHandshake{}
	copy(srvHs.PublicKey[:], bytes.Repeat([]byte{0xDD}, 32))

	var outStream bytes.Buffer
	if err := writeServerHandshakeMagic(&outStream, srvHs); err != nil {
		t.Fatal(err)
	}

	if outStream.Len() != 38 {
		t.Fatalf("Wrong server handshake size: %d", outStream.Len())
	}
}