package outbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Client is a minimal Reflex outbound client.
//
// It is primarily used by tests in this repository.
type Client struct {
	Address          string
	Port             uint32
	UserID           [16]byte
	Policy           string
	UseHTTPHandshake bool
}

// NewClient builds a Client from OutboundConfig.
func NewClient(cfg *reflex.OutboundConfig) (*Client, error) {
	idBytes, err := reflex.ParseUUID(cfg.Id)
	if err != nil {
		return nil, err
	}
	c := &Client{
		Address:          cfg.Address,
		Port:             cfg.Port,
		UserID:           idBytes,
		Policy:           cfg.Policy,
		UseHTTPHandshake: cfg.UseHttpHandshake,
	}
	return c, nil
}

// Dial establishes a TCP connection, performs the Reflex handshake, and returns a session.
func (c *Client) Dial(ctx context.Context) (net.Conn, *reflex.Session, *reflex.TrafficProfile, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", c.Address, c.Port))
	if err != nil {
		return nil, nil, nil, err
	}
	sess, profile, err := c.Handshake(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	return conn, sess, profile, nil
}

// Handshake performs the Reflex handshake on an existing connection.
func (c *Client) Handshake(conn net.Conn) (*reflex.Session, *reflex.TrafficProfile, error) {
	// Generate ephemeral key.
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	// Encrypt policy request using UUID-derived PSK.
	psk := reflex.DerivePSK(c.UserID)
	var policyReq []byte
	if c.Policy != "" {
		policyReq, _ = reflex.EncryptPolicy(psk, []byte(c.Policy))
	}
	clientHS, err := reflex.NewClientHandshake(clientPub, c.UserID, policyReq)
	if err != nil {
		return nil, nil, err
	}

	// Send handshake.
	var req []byte
	if c.UseHTTPHandshake {
		req = reflex.EncodeClientHandshakeHTTP(clientHS, c.Address, reflex.DefaultHandshakePath)
	} else {
		req = reflex.EncodeClientHandshakeMagic(clientHS)
	}
	if _, err := conn.Write(req); err != nil {
		return nil, nil, err
	}

	// Read server response (HTTP-like).
	reader := bufio.NewReader(conn)
	serverHS, err := reflex.ReadServerHandshakeHTTP(reader)
	if err != nil {
		return nil, nil, err
	}

	// Optionally decrypt policy grant.
	policyName := c.Policy
	if len(serverHS.PolicyGrant) > 0 {
		if pt, err := reflex.DecryptPolicy(psk, serverHS.PolicyGrant); err == nil {
			if s := string(pt); s != "" {
				policyName = s
			}
		}
	}
	profile := reflex.CloneProfile(policyName)

	// Derive session key.
	shared, err := reflex.DeriveSharedSecret(clientPriv, serverHS.ServerPubKey)
	if err != nil {
		return nil, nil, err
	}
	sessionKey := reflex.DeriveSessionKey(shared, clientHS.Nonce[:])

	// Create session.
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return nil, nil, err
	}
	return sess, profile, nil
}

// SendRequest sends the initial destination request.
func (c *Client) SendRequest(sess *reflex.Session, writer net.Conn, addr string, port uint16, initial []byte, profile *reflex.TrafficProfile) error {
	b := make([]byte, 0, 1+len(addr)+2+len(initial))
	b = append(b, byte(len(addr)))
	b = append(b, []byte(addr)...)
	p := make([]byte, 2)
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	b = append(b, p...)
	b = append(b, initial...)
	return sess.WriteFrameWithMorphing(writer, reflex.FrameTypeData, b, profile)
}

// Handler implements Xray's outbound handler interface.
// It dials a Reflex server, performs handshake, sends the destination request,
// then proxies data using encrypted frames.
type Handler struct {
	cfg    *reflex.OutboundConfig
	userID [16]byte
}

// New builds a Reflex outbound handler from config.
func New(ctx context.Context, cfg *reflex.OutboundConfig) (proxy.Outbound, error) {
	_ = ctx
	idBytes, err := reflex.ParseUUID(cfg.Id)
	if err != nil {
		return nil, err
	}
	return &Handler{cfg: cfg, userID: idBytes}, nil
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("reflex: target not specified").AtError()
	}
	if ob.Target.Network != xnet.Network_TCP {
		return errors.New("reflex: only TCP is supported").AtError()
	}
	ob.Name = "reflex"

	port, err := xnet.PortFromInt(h.cfg.Port)
	if err != nil {
		return err
	}
	serverDest := xnet.TCPDestination(xnet.ParseAddress(h.cfg.Address), port)

	conn, err := dialer.Dial(ctx, serverDest)
	if err != nil {
		return errors.New("reflex: failed to dial server").Base(err).AtError()
	}
	defer func() { _ = conn.Close() }()

	// Reuse client handshake implementation.
	c := &Client{
		Address:          h.cfg.Address,
		Port:             h.cfg.Port,
		UserID:           h.userID,
		Policy:           h.cfg.Policy,
		UseHTTPHandshake: h.cfg.UseHttpHandshake,
	}

	sess, profile, err := c.Handshake(conn)
	if err != nil {
		return errors.New("reflex: handshake failed").Base(err).AtError()
	}

	addrStr := ob.Target.Address.String()
	if len(addrStr) > 255 {
		return errors.New("reflex: target address too long").AtError()
	}
	if err := c.SendRequest(sess, conn, addrStr, ob.Target.Port.Value(), nil, profile); err != nil {
		return errors.New("reflex: failed to send destination request").Base(err).AtError()
	}

	errCh := make(chan error, 2)

	// Uplink: Xray -> Reflex
	go func() {
		for {
			mb, rerr := link.Reader.ReadMultiBuffer()
			if rerr != nil {
				_ = sess.WriteFrame(conn, reflex.FrameTypeClose, nil)
				errCh <- rerr
				return
			}
			for _, b := range mb {
				if b == nil {
					continue
				}
				p := b.Bytes()
				if len(p) > 0 {
					if werr := sess.WriteFrameWithMorphing(conn, reflex.FrameTypeData, p, profile); werr != nil {
						buf.ReleaseMulti(mb)
						errCh <- werr
						return
					}
				}
			}
			buf.ReleaseMulti(mb)
		}
	}()

	// Downlink: Reflex -> Xray
	go func() {
		r := bufio.NewReader(conn)
		for {
			f, rerr := sess.ReadFrame(r)
			if rerr != nil {
				errCh <- rerr
				return
			}
			switch f.Type {
			case reflex.FrameTypeData:
				if len(f.Payload) == 0 {
					continue
				}
				mb := buf.MergeBytes(nil, f.Payload)
				if werr := link.Writer.WriteMultiBuffer(mb); werr != nil {
					buf.ReleaseMulti(mb)
					errCh <- werr
					return
				}
				buf.ReleaseMulti(mb)
			case reflex.FrameTypePadding, reflex.FrameTypeTiming:
				sess.HandleControlFrame(f, profile)
			case reflex.FrameTypeClose:
				errCh <- io.EOF
				return
			default:
				errCh <- errors.New("reflex: unknown frame type").AtError()
				return
			}
		}
	}()

	err = <-errCh
	if err == nil || err == io.EOF {
		return nil
	}
	return err
}

func init() {
	// Register config builder for completeness.
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}
