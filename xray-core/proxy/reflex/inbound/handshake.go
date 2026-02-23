package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// ReflexMagic is the magic number for quick protocol detection
	ReflexMagic = 0x5246584C // "REFX" in ASCII
	// ReflexMinHandshakeSize is minimum size for handshake detection
	ReflexMinHandshakeSize = 64
	// MaxHandshakeSize is maximum size for handshake packet
	MaxHandshakeSize = 1024
)

// ClientHandshake represents the client handshake packet
type ClientHandshake struct {
	PublicKey [32]byte // X25519 public key
	UserID    [16]byte // UUID (16 bytes)
	PolicyReq []byte   // Policy request (encrypted with pre-shared key)
	Timestamp int64    // Unix timestamp
	Nonce     [16]byte // Nonce for replay protection
}

// ServerHandshake represents the server handshake response
type ServerHandshake struct {
	PublicKey   [32]byte // Server public key
	PolicyGrant []byte   // Policy grant (encrypted)
}

// ClientHandshakePacket is the complete handshake packet with magic number
type ClientHandshakePacket struct {
	Magic     uint32          // Magic number
	Handshake ClientHandshake
}

// generateKeyPair generates a new X25519 key pair
func generateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	// Generate random private key
	if _, err = rand.Read(privateKey[:]); err != nil {
		return
	}
	
	// Clamp the private key (required for X25519)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	
	// Compute public key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// deriveSharedKey computes the shared secret from private and peer public key
func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	secret, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return shared
	}
	copy(shared[:], secret)
	return shared
}

// deriveSessionKey extracts session key from shared key using HKDF
func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	h := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(h, sessionKey); err != nil {
		return nil
	}
	return sessionKey
}

// authenticateUser authenticates user by UUID
func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userUUID := uuid.UUID(userID)
	userIDStr := userUUID.String()
	
	for _, user := range h.clients {
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		if account.Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

// isReflexMagic checks if data starts with Reflex magic number
func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == ReflexMagic
}


// readClientHandshakeMagic reads handshake packet with magic number
func (h *Handler) readClientHandshakeMagic(reader *bufio.Reader) (*ClientHandshake, error) {
	// Read magic number (already peeked, but we need to consume it)
	magicBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, magicBytes); err != nil {
		return nil, err
	}
	
	// Read handshake structure
	var hs ClientHandshake
	
	// Read public key (32 bytes)
	if _, err := io.ReadFull(reader, hs.PublicKey[:]); err != nil {
		return nil, err
	}
	
	// Read user ID (16 bytes)
	if _, err := io.ReadFull(reader, hs.UserID[:]); err != nil {
		return nil, err
	}
	
	// Read timestamp (8 bytes)
	if err := binary.Read(reader, binary.BigEndian, &hs.Timestamp); err != nil {
		return nil, err
	}
	
	// Read nonce (16 bytes)
	if _, err := io.ReadFull(reader, hs.Nonce[:]); err != nil {
		return nil, err
	}
	
	// Read policy request length (2 bytes)
	var policyReqLen uint16
	if err := binary.Read(reader, binary.BigEndian, &policyReqLen); err != nil {
		return nil, err
	}
	
	if policyReqLen > 0 && policyReqLen < MaxHandshakeSize {
		hs.PolicyReq = make([]byte, policyReqLen)
		if _, err := io.ReadFull(reader, hs.PolicyReq); err != nil {
			return nil, err
		}
	}
	
	return &hs, nil
}

// processHandshake processes the handshake and establishes session
func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS *ClientHandshake) error {
	// Generate server key pair
	serverPrivateKey, serverPublicKey, err := generateKeyPair()
	if err != nil {
		return err
	}
	
	// Compute shared key
	sharedKey := deriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))
	
	// Authenticate user
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		// If authentication fails, send error response and close
		errorResponse := []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"error\":\"authentication failed\"}")
		if _, writeErr := conn.Write(errorResponse); writeErr != nil {
			return errors.New("failed to write authentication error response").Base(writeErr)
		}
		return err
	}
	
	// Check timestamp (prevent replay attacks)
	now := time.Now().Unix()
	if clientHS.Timestamp < now-300 || clientHS.Timestamp > now+300 {
		// Timestamp is more than 5 minutes off
		errorResponse := []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"error\":\"invalid timestamp\"}")
		if _, writeErr := conn.Write(errorResponse); writeErr != nil {
			return errors.New("failed to write timestamp error response").Base(writeErr)
		}
		return errors.New("timestamp out of range")
	}
	
	// Create server handshake response
	serverHS := ServerHandshake{
		PublicKey:   serverPublicKey,
		PolicyGrant: []byte{}, // TODO: implement policy grant encryption
	}
	
	// Format and send HTTP 200 response
	response := h.formatHTTPResponse(serverHS)
	if _, err := conn.Write(response); err != nil {
		return err
	}
	
	// Get traffic profile from user policy
	var profile *TrafficProfile
	if user.Account != nil {
		if account, ok := user.Account.(*MemoryAccount); ok {
			// Get policy name from handler
			if policyName, ok := h.userPolicies[account.Id]; ok && policyName != "" {
				profile = GetProfileByName(policyName)
			}
		}
	}
	
	// Session established, now handle data frames
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user, profile)
}

// formatHTTPResponse formats server handshake as HTTP 200 response
func (h *Handler) formatHTTPResponse(serverHS ServerHandshake) []byte {
	// For now, send a simple JSON response
	// In production, this should be properly formatted HTTP response
	response := "HTTP/1.1 200 OK\r\n"
	response += "Content-Type: application/json\r\n"
	response += "Content-Length: 0\r\n"
	response += "\r\n"
	return []byte(response)
}

// handleReflexMagic handles handshake with magic number
func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	clientHS, err := h.readClientHandshakeMagic(reader)
	if err != nil {
		return err
	}
	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

// handleReflexHTTP handles handshake with HTTP POST-like format
func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	// TODO: Implement HTTP POST parsing for handshake
	// For now, fall back to fallback
	return h.handleFallback(ctx, reader, conn)
}

// handleSession handles the session after handshake
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser, profile *TrafficProfile) error {
	session, err := NewSession(sessionKey)
	if err != nil {
		return errors.New("failed to create session").Base(err)
	}
	
	// Set traffic profile if provided
	if profile != nil {
		session.profile = profile
		session.morphingEnabled = true
	}

	// Read frames and process them
	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return errors.New("failed to read frame").Base(err)
		}

		switch frame.Type {
		case FrameTypeData:
			// This is real user data, forward to upstream
			err := h.handleData(ctx, frame.Payload, conn, dispatcher, session, user, reader)
			if err != nil {
				return errors.New("failed to handle data").Base(err)
			}
			// After handleData returns, connection is handled
			return nil

		case FrameTypePadding:
			// Padding control frame - handle morphing
			session.HandleControlFrame(frame, session.profile)
			continue

		case FrameTypeTiming:
			// Timing control frame - handle morphing
			session.HandleControlFrame(frame, session.profile)
			continue

		case FrameTypeClose:
			// Close connection
			return nil

		default:
			return errors.New("unknown frame type")
		}
	}
}

