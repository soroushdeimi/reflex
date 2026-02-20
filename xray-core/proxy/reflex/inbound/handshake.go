package inbound

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

const ReflexMagic = 0x5246584C
const MinHandshakeSize = 76

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

var errNotReflex = errors.New("not reflex protocol")

func generateKeyPair() (priv [32]byte, pub [32]byte, e error) {
	if _, e = io.ReadFull(rand.Reader, priv[:]); e != nil {
		return
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func deriveSharedKey(priv, peer [32]byte) [32]byte {
	var out [32]byte
	curve25519.ScalarMult(&out, &priv, &peer)
	return out
}

func deriveSessionKey(secret [32]byte, salt []byte) []byte {
	extractor := hkdf.New(sha256.New, secret[:], salt, []byte("reflex-session"))
	res := make([]byte, 32)
	io.ReadFull(extractor, res)
	return res
}

func readClientHandshakeMagic(stream io.Reader) (*ClientHandshake, error) {
	rawBuf := make([]byte, MinHandshakeSize)
	if _, err := io.ReadFull(stream, rawBuf); err != nil {
		return nil, err
	}

	if binary.BigEndian.Uint32(rawBuf[:4]) != ReflexMagic {
		return nil, errNotReflex
	}

	req := &ClientHandshake{}
	copy(req.PublicKey[:], rawBuf[4:36])
	copy(req.UserID[:], rawBuf[36:52])
	req.Timestamp = int64(binary.BigEndian.Uint64(rawBuf[52:60]))
	copy(req.Nonce[:], rawBuf[60:76])

	return req, nil
}

func writeServerHandshakeMagic(w io.Writer, srv *ServerHandshake) error {
	sz := len(srv.PolicyGrant)
	if sz > 65535 {
		sz = 65535
	}

	outBuf := make([]byte, 0, 38+sz)

	magicArr := [4]byte{}
	binary.BigEndian.PutUint32(magicArr[:], ReflexMagic)
	outBuf = append(outBuf, magicArr[:]...)

	outBuf = append(outBuf, srv.PublicKey[:]...)

	lenArr := [2]byte{}
	binary.BigEndian.PutUint16(lenArr[:], uint16(sz))
	outBuf = append(outBuf, lenArr[:]...)

	if sz > 0 {
		outBuf = append(outBuf, srv.PolicyGrant[:sz]...)
	}

	_, err := w.Write(outBuf)
	return err
}

func (h *Handler) authenticateUser(uid [16]byte) *protocol.MemoryUser {
	parsed, err := uuid.ParseBytes(uid[:])
	if err != nil {
		return nil
	}

	target := parsed.String()
	for idx := range h.clients {
		if acc, ok := h.clients[idx].Account.(*MemoryAccount); ok && acc.Id == target {
			return h.clients[idx]
		}
	}
	return nil
}