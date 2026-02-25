package codec

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
)

// Magic codec implements the "fast detection" handshake encoding.
// Client packet starts with 4-byte magic, followed by canonical handshake fields.
// Server response is canonical ServerHandshake fields (no magic).
//
// Canonical client binary (after magic):
//   pubkey(32) | userid(16) | timestamp(8, big-endian) | nonce(16) | policyLen(2, big-endian) | policyReq(policyLen)
//
// Canonical server binary:
//   pubkey(32) | grantLen(2, big-endian) | policyGrant(grantLen)

func ReadMagicClientHandshake(r io.Reader) (*handshake.ClientHandshake, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read magic", err)
	}
	if magic != handshake.ReflexMagicBytes {
		// Not a Reflex magic handshake -> let caller fallback.
		return nil, handshake.New(handshake.KindNotReflex, "magic mismatch")
	}

	var hs handshake.ClientHandshake

	// PublicKey
	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read client public key", err)
	}

	// UserID (UUID bytes)
	if _, err := io.ReadFull(r, hs.UserID[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read user id", err)
	}

	// Timestamp (int64 big-endian)
	var tsBuf [8]byte
	if _, err := io.ReadFull(r, tsBuf[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read timestamp", err)
	}
	hs.Timestamp = int64(binary.BigEndian.Uint64(tsBuf[:]))

	// Nonce
	if _, err := io.ReadFull(r, hs.Nonce[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read nonce", err)
	}

	// PolicyReq length (uint16 big-endian)
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read policy length", err)
	}
	policyLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if policyLen < 0 || policyLen > handshake.MaxPolicyReqSize {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy request too large")
	}

	// PolicyReq bytes
	if policyLen > 0 {
		hs.PolicyReq = make([]byte, policyLen)
		if _, err := io.ReadFull(r, hs.PolicyReq); err != nil {
			return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read policy request", err)
		}
	} else {
		hs.PolicyReq = nil
	}

	return &hs, nil
}

func WriteMagicClientHandshake(w io.Writer, hs *handshake.ClientHandshake) error {
	if hs == nil {
		return errors.New("reflex codec: nil client handshake")
	}
	if len(hs.PolicyReq) > handshake.MaxPolicyReqSize {
		return handshake.New(handshake.KindInvalidHandshake, "policy request too large")
	}
	if len(hs.PolicyReq) > 0xFFFF {
		return handshake.New(handshake.KindInvalidHandshake, "policy request length overflow")
	}

	// magic
	if _, err := w.Write(handshake.ReflexMagicBytes[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write magic", err)
	}

	// pubkey
	if _, err := w.Write(hs.PublicKey[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write client public key", err)
	}

	// userid
	if _, err := w.Write(hs.UserID[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write user id", err)
	}

	// timestamp
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(hs.Timestamp))
	if _, err := w.Write(tsBuf[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write timestamp", err)
	}

	// nonce
	if _, err := w.Write(hs.Nonce[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write nonce", err)
	}

	// policyLen + policyReq
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hs.PolicyReq)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write policy length", err)
	}
	if len(hs.PolicyReq) > 0 {
		if _, err := w.Write(hs.PolicyReq); err != nil {
			return handshake.Wrap(handshake.KindInternal, "write policy request", err)
		}
	}

	return nil
}

func ReadMagicServerHandshake(r io.Reader) (*handshake.ServerHandshake, error) {
	var hs handshake.ServerHandshake

	// PublicKey
	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read server public key", err)
	}

	// Grant length
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read grant length", err)
	}
	grantLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if grantLen < 0 || grantLen > handshake.MaxPolicyGrantSize {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy grant too large")
	}

	// Grant bytes
	if grantLen > 0 {
		hs.PolicyGrant = make([]byte, grantLen)
		if _, err := io.ReadFull(r, hs.PolicyGrant); err != nil {
			return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read policy grant", err)
		}
	} else {
		hs.PolicyGrant = nil
	}

	return &hs, nil
}

func WriteMagicServerHandshake(w io.Writer, hs *handshake.ServerHandshake) error {
	if hs == nil {
		return errors.New("reflex codec: nil server handshake")
	}
	if len(hs.PolicyGrant) > handshake.MaxPolicyGrantSize {
		return handshake.New(handshake.KindInvalidHandshake, "policy grant too large")
	}
	if len(hs.PolicyGrant) > 0xFFFF {
		return handshake.New(handshake.KindInvalidHandshake, "policy grant length overflow")
	}

	// pubkey
	if _, err := w.Write(hs.PublicKey[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write server public key", err)
	}

	// grantLen + grant
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hs.PolicyGrant)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write grant length", err)
	}
	if len(hs.PolicyGrant) > 0 {
		if _, err := w.Write(hs.PolicyGrant); err != nil {
			return handshake.Wrap(handshake.KindInternal, "write policy grant", err)
		}
	}

	return nil
}
