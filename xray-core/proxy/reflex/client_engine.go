package reflex

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"io"
	"time"

	"github.com/xtls/xray-core/proxy/reflex/codec"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
)

// ClientHandshakeEngine orchestrates client-side Step2 handshake.
// For Step2 we default to HTTP-like packets (stealthier).
type ClientHandshakeEngine struct {
	UserID  [handshake.UserIDSize]byte
	Now     func() time.Time
	HTTPOpt codec.HTTPOptions
}

func NewClientHandshakeEngine(userID [handshake.UserIDSize]byte, host string) *ClientHandshakeEngine {
	return &ClientHandshakeEngine{
		UserID:  userID,
		Now:     time.Now,
		HTTPOpt: codec.DefaultHTTPOptions(host),
	}
}

// DoHandshakeHTTP performs an HTTP-like handshake over conn.
// It returns the derived session key and parsed handshakes.
func (e *ClientHandshakeEngine) DoHandshakeHTTP(conn io.ReadWriter) (*SessionInfo, error) {
	if e == nil {
		return nil, handshake.New(handshake.KindInternal, "nil client engine")
	}
	if e.Now == nil {
		e.Now = time.Now
	}

	// Build client handshake
	now := e.Now()
	ts := now.Unix()

	var nonce [handshake.NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInternal, "read nonce", err)
	}

	kp, err := handshake.GenerateX25519KeyPair()
	if err != nil {
		return nil, handshake.Wrap(handshake.KindInternal, "generate client keypair", err)
	}

	// Minimal, non-empty policy request (encrypted with PSK derived from UUID hash).
	policyReqPlain, err := defaultPolicyReqPayload()
	if err != nil {
		return nil, handshake.Wrap(handshake.KindInternal, "build policy request", err)
	}
	policyReqEnc, err := handshake.EncryptPolicyReq(e.UserID, nonce, ts, policyReqPlain)
	if err != nil {
		return nil, err
	}

	clientHS := &handshake.ClientHandshake{
		PublicKey: kp.Public,
		UserID:    e.UserID,
		PolicyReq: policyReqEnc,
		Timestamp: ts,
		Nonce:     nonce,
	}

	// Write HTTP-like request
	if err := codec.WriteHTTPClientHandshake(conn, clientHS, e.HTTPOpt); err != nil {
		return nil, err
	}

	// Read HTTP-like response
	reader := bufio.NewReader(conn)
	serverHS, err := codec.ReadHTTPServerHandshake(reader)
	if err != nil {
		return nil, err
	}

	// Derive session key
	shared, err := handshake.ComputeSharedKey(kp.Private, serverHS.PublicKey)
	if err != nil {
		return nil, err
	}
	sk, err := handshake.DeriveSessionKeyWithNonce(shared, nonce)
	if err != nil {
		return nil, err
	}

	// Validate/decrypt policy grant if present
	if len(serverHS.PolicyGrant) > 0 {
		if _, err := handshake.DecryptPolicyGrant(e.UserID, nonce, ts, serverHS.PolicyGrant); err != nil {
			return nil, err
		}
	}

	return &SessionInfo{
		Flavor:     WireHTTP,
		User:       nil,
		ClientHS:   clientHS,
		ServerHS:   serverHS,
		SessionKey: sk,
	}, nil
}

func defaultPolicyReqPayload() ([]byte, error) {
	// Keep it tiny + forward-compatible (JSON).
	type req struct {
		Want string `json:"want"`
	}
	return json.Marshal(req{Want: "default"})
}
