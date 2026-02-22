package outbound

import (
	"context"
	"os"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for Reflex protocol
type Handler struct {
	policyManager policy.Manager
	config        *Config
}

// New creates a new Reflex outbound handler
func New(ctx context.Context, config *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		config:        config,
	}

	return handler, nil
}

// Process implements proxy.Outbound.Process
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// Log to file
	f, _ := os.OpenFile("reflex-outbound.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		f.WriteString("REFLEX OUTBOUND PROCESS CALLED\n")
		f.Close()
	}

	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("no outbound").AtError()
	}

	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified").AtError()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Get server endpoint from vnext
	if len(h.config.Vnext) == 0 {
		return errors.New("no server configured").AtError()
	}

	server := h.config.Vnext[0]
	if server.Address == nil {
		return errors.New("server address not specified").AtError()
	}

	// Create a net address for the server from IPOrDomain
	var serverAddr net.Address
	if ip := server.Address.GetIp(); ip != nil {
		serverAddr = net.IPAddress(ip)
	} else if domain := server.Address.GetDomain(); domain != "" {
		serverAddr = net.DomainAddress(domain)
	} else {
		return errors.New("server address is empty").AtError()
	}

	serverPort := net.Port(server.Port)
	serverDestination := net.Destination{
		Network: net.Network_TCP,
		Address: serverAddr,
		Port:    serverPort,
	}

	// Dial to the reflex server (not the target)
	rawConn, err := dialer.Dial(ctx, serverDestination)
	if err != nil {
		return errors.New("failed to dial reflex server").Base(err).AtError()
	}
	defer rawConn.Close()

	target := ob.Target
	request := &protocol.RequestHeader{
		Version: 1,
		Address: target.Address,
		Port:    target.Port,
		Command: protocol.RequestCommandTCP,
	}

	if target.Network == net.Network_UDP {
		request.Command = protocol.RequestCommandUDP
	}

	// Get user account from config (vnext)
	// Use the first server's user account
	var account *reflex.MemoryAccount
	if server.User == nil {
		return errors.New("no user configured for server").AtError()
	}

	// Convert User to MemoryAccount
	memUser, err := server.User.ToMemoryUser()
	if err != nil {
		return errors.New("failed to parse user").Base(err).AtError()
	}

	if memUser.Account == nil {
		return errors.New("user has no account").AtError()
	}

	if reflexAccount, ok := memUser.Account.(*reflex.MemoryAccount); ok {
		account = reflexAccount
	} else {
		return errors.New("invalid account type").AtError()
	}

	// Perform handshake
	clientPrivateKey, clientPublicKey, err := encoding.GenerateKeyPair()
	if err != nil {
		return errors.New("failed to generate key pair").Base(err).AtError()
	}

	userIDBytes := encoding.UUIDToBytes(account.ID)
	var nonce [16]byte
	// TODO: Generate random nonce

	clientHS := &encoding.ClientHandshake{
		PublicKey: clientPublicKey,
		UserID:    userIDBytes,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	// Send client handshake (use pooled buffer)
	handshakeData := encoding.EncodeClientHandshake(clientHS)
	defer encoding.PutClientHandshakeBuffer(handshakeData)
	if _, err := rawConn.Write(handshakeData); err != nil {
		return errors.New("failed to send handshake").Base(err).AtError()
	}

	// Read server handshake response (40 bytes) - use pooled buffer
	responseData := encoding.GetServerHandshakeBuffer()
	defer encoding.PutServerHandshakeBuffer(responseData)
	if _, err := rawConn.Read(responseData); err != nil {
		return errors.New("failed to read handshake response").Base(err).AtError()
	}

	serverHS, err := encoding.DecodeServerHandshake(responseData)
	if err != nil {
		return errors.New("invalid server handshake").Base(err).AtError()
	}

	// Derive session key
	sharedKey := encoding.DeriveSharedKey(clientPrivateKey, serverHS.PublicKey)
	sessionKey, err := encoding.DeriveSessionKey(sharedKey, []byte("reflex-session-v1"))
	if err != nil {
		return errors.New("failed to derive session key").Base(err).AtError()
	}

	// Create frame encoder/decoder
	frameEncoder, err := encoding.NewFrameEncoder(sessionKey)
	if err != nil {
		return errors.New("failed to create frame encoder").Base(err).AtError()
	}

	frameDecoder, err := encoding.NewFrameDecoder(sessionKey)
	if err != nil {
		return errors.New("failed to create frame decoder").Base(err).AtError()
	}

	// Send request header as first frame
	requestData := encodeRequestHeader(request)
	firstFrame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: requestData,
	}
	if err := frameEncoder.WriteFrame(rawConn, firstFrame); err != nil {
		return errors.New("failed to send request").Base(err).AtError()
	}

	// Transfer data
	requestDone := func() error {
		// Read from link and write as frames
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}

			for _, b := range mb {
				frame := encoding.GetFrame()
				frame.Type = encoding.FrameTypeData
				frame.Payload = b.Bytes()

				if err := frameEncoder.WriteFrame(rawConn, frame); err != nil {
					encoding.PutFrame(frame)
					buf.ReleaseMulti(mb)
					return err
				}
				encoding.PutFrame(frame)
			}
			buf.ReleaseMulti(mb)
		}
	}

	responseDone := func() error {
		// Read frames and write to link
		for {
			frame, err := frameDecoder.ReadFrame(rawConn)
			if err != nil {
				return err
			}

			switch frame.Type {
			case encoding.FrameTypeData:
				// Use FromBytes to avoid allocation (unmanaged buffer - zero-copy)
				payload := buf.FromBytes(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
					encoding.PutFrame(frame)
					return err
				}
				encoding.PutFrame(frame)
			case encoding.FrameTypeClose:
				encoding.PutFrame(frame)
				return nil
			case encoding.FrameTypePadding, encoding.FrameTypeTiming:
				// Control frames - ignore for now
				encoding.PutFrame(frame)
				continue
			default:
				encoding.PutFrame(frame)
				return errors.New("unknown frame type: ", frame.Type).AtWarning()
			}
		}
	}

	// Run both directions concurrently
	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

// encodeRequestHeader encodes request header to bytes
// Format: [command(1)] + [port(2)] + [addrType(1)] + [address]
func encodeRequestHeader(request *protocol.RequestHeader) []byte {
	buf := make([]byte, 0, 256)

	// Command
	buf = append(buf, byte(request.Command))

	// Port (encode as big-endian uint16)
	portNum := uint16(request.Port)
	buf = append(buf, byte(portNum>>8), byte(portNum))

	// Address
	switch request.Address.Family() {
	case net.AddressFamilyIPv4:
		buf = append(buf, 1) // IPv4 type
		buf = append(buf, request.Address.IP()...)
	case net.AddressFamilyIPv6:
		buf = append(buf, 4) // IPv6 type
		buf = append(buf, request.Address.IP()...)
	case net.AddressFamilyDomain:
		buf = append(buf, 3) // Domain type
		domain := request.Address.Domain()
		buf = append(buf, byte(len(domain)))
		buf = append(buf, []byte(domain)...)
	}

	return buf
}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
