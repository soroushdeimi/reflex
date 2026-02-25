package reflex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex/codec"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
)

// WireFlavor indicates which on-the-wire format was used for handshake.
type WireFlavor uint8

const (
	WireUnknown WireFlavor = iota
	WireMagic
	WireHTTP
)

// SessionInfo is the result of a successful handshake.
type SessionInfo struct {
	Flavor     WireFlavor
	User       *ClientInfo
	ClientHS   *handshake.ClientHandshake
	ServerHS   *handshake.ServerHandshake
	SessionKey [handshake.SessionKeySize]byte
}

// HandshakeEngine orchestrates Step2 handshake.
// It is intentionally independent from inbound/outbound Process to keep code clean & testable.
type HandshakeEngine struct {
	Validator Validator
	Replay    *handshake.ReplayCache
	Now       func() time.Time
}

func NewHandshakeEngine(v Validator) *HandshakeEngine {
	return &HandshakeEngine{
		Validator: v,
		Replay:    handshake.NewReplayCache(0),
		Now:       time.Now,
	}
}

// ServerDoHandshake reads the client handshake from r, validates/authenticates,
// derives session key, generates server handshake, and writes response to w.
//
// It supports both:
// - Magic binary codec
// - HTTP POST-like codec
func (e *HandshakeEngine) ServerDoHandshake(r *bufio.Reader, w io.Writer) (*SessionInfo, error) {
	if e == nil {
		return nil, handshake.New(handshake.KindInternal, "nil engine")
	}
	if e.Validator == nil {
		return nil, handshake.New(handshake.KindInternal, "nil validator")
	}
	if e.Replay == nil {
		e.Replay = handshake.NewReplayCache(0)
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if r == nil || w == nil {
		return nil, handshake.New(handshake.KindInternal, "nil reader/writer")
	}

	peeked, err := r.Peek(64)
	if err != nil {
		// Could be EOF or short read; treat as not-reflex for fallback.
		return nil, handshake.Wrap(handshake.KindNotReflex, "peek failed", err)
	}

	var (
		flavor WireFlavor
		client *handshake.ClientHandshake
	)

	// Decide codec without consuming bytes incorrectly.
	if len(peeked) >= 4 && bytes.Equal(peeked[:4], handshake.ReflexMagicBytes[:]) {
		flavor = WireMagic
		client, err = codec.ReadMagicClientHandshake(r)
		if err != nil {
			return nil, err
		}
	} else if codec.LooksLikeHTTPPost(peeked) {
		flavor = WireHTTP
		client, err = codec.ReadHTTPClientHandshake(r)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, handshake.New(handshake.KindNotReflex, "not reflex traffic")
	}

	now := e.Now()

	// 1) Timestamp validation
	if err := handshake.ValidateTimestamp(now, client.Timestamp); err != nil {
		return nil, err
	}

	// 2) Replay protection
	if err := e.Replay.CheckAndMark(now, client.UserID, client.Nonce); err != nil {
		return nil, err
	}

	// 3) Authenticate user
	user, ok := e.Validator.Get(client.UserID)
	if !ok || user == nil {
		return nil, handshake.New(handshake.KindUnauthenticated, "user not found")
	}

	// 4) ECDH + session key
	kp, err := handshake.GenerateX25519KeyPair()
	if err != nil {
		return nil, handshake.Wrap(handshake.KindInternal, "generate server keypair", err)
	}

	shared, err := handshake.ComputeSharedKey(kp.Private, client.PublicKey)
	if err != nil {
		return nil, err
	}

	sk, err := handshake.DeriveSessionKeyWithNonce(shared, client.Nonce)
	if err != nil {
		return nil, err
	}

	// 5) Decrypt policy request (optional for Step2; still validate if present)
	if len(client.PolicyReq) > 0 {
		if _, err := handshake.DecryptPolicyReq(client.UserID, client.Nonce, client.Timestamp, client.PolicyReq); err != nil {
			// If policy decrypt fails, treat as invalid handshake.
			return nil, err
		}
	}

	// 6) Create policy grant (minimal & deterministic)
	grantPlain, err := defaultPolicyGrantPayload(user)
	if err != nil {
		return nil, handshake.Wrap(handshake.KindInternal, "build policy grant", err)
	}

	grantEnc, err := handshake.EncryptPolicyGrant(client.UserID, client.Nonce, client.Timestamp, grantPlain)
	if err != nil {
		return nil, err
	}

	serverHS := &handshake.ServerHandshake{
		PublicKey:   kp.Public,
		PolicyGrant: grantEnc,
	}

	// 7) Write response using the same flavor
	switch flavor {
	case WireMagic:
		if err := codec.WriteMagicServerHandshake(w, serverHS); err != nil {
			return nil, err
		}
	case WireHTTP:
		if err := codec.WriteHTTPServerHandshake(w, serverHS); err != nil {
			return nil, err
		}
	default:
		return nil, handshake.New(handshake.KindInternal, "unknown wire flavor")
	}

	info := &SessionInfo{
		Flavor:     flavor,
		User:       user,
		ClientHS:   client,
		ServerHS:   serverHS,
		SessionKey: sk,
	}
	return info, nil
}

// defaultPolicyGrantPayload is a minimal grant body for Step2.
// We keep it JSON so it can evolve later without breaking parsing.
func defaultPolicyGrantPayload(user *ClientInfo) ([]byte, error) {
	type grant struct {
		Policy string `json:"policy"`
	}
	return json.Marshal(grant{Policy: user.Policy})
}

// WriteHTTPForbidden writes a normal-looking 403 response.
// Useful for error handling in inbound.Process when flavor is HTTP-like.
func WriteHTTPForbidden(w io.Writer) error {
	if w == nil {
		return errors.New("nil writer")
	}
	_, err := w.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"))
	return err
}

// WriteHTTPBadRequest writes a normal-looking 400 response.
func WriteHTTPBadRequest(w io.Writer) error {
	if w == nil {
		return errors.New("nil writer")
	}
	_, err := w.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"))
	return err
}
