package inbound

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/xtls/xray-core/common/protocol"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/google/uuid"
)

type ClientHandshake struct {
	PublicKey [32]byte // کلید عمومی X25519
	UserID    [16]byte // UUID (16 بایت)
	PolicyReq []byte   // درخواست سیاست (رمزنگاری شده با pre-shared key)
	Timestamp int64    // مهر زمانی (Unix timestamp)
	Nonce     [16]byte // برای جلوگیری از replay
}

// ساختار کامل بسته اولیه (قبل از base64 encoding)
type ClientHandshakePacket struct {
	Magic     [4]byte // برای تشخیص سریع (اختیاری)
	Handshake ClientHandshake
}


type ServerHandshake struct {
	PublicKey   [32]byte // کلید عمومی سرور
	PolicyGrant []byte   // اعطای سیاست (رمزنگاری شده)
}

// یا می‌تونی از magic number استفاده کنی (ساده‌تر برای تشخیص)
const ReflexMagic = 0x5246584C // "REFX" در ASCII

func (h *Handler) isReflexMagic(data []byte) bool {
    if len(data) < 4 {
        return false
    }
    
    magic := binary.BigEndian.Uint32(data[0:4])
    return magic == ReflexMagic
}

func generateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	hkdf := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	hkdf.Read(sessionKey)
	return sessionKey
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
    // تبدیل [16]byte به string UUID
    userIDStr := uuid.UUID(userID).String()
    
    for _, user := range h.clients {
        if user.Account.(*MemoryAccount).Id == userIDStr {
            return user, nil
        }
    }
    return nil, errors.New("user not found")
}

// یا اگه می‌خوای مستقیماً با [16]byte کار کنی:
func (h *Handler) authenticateUserBytes(userID [16]byte) (*protocol.MemoryUser, error) {
    for _, user := range h.clients {
        accountID := user.Account.(*MemoryAccount).Id
        // تبدیل string UUID به [16]byte و مقایسه
        parsedUUID, err := uuid.Parse(accountID)
        if err != nil {
            continue
        }
        if parsedUUID == uuid.UUID(userID) {
            return user, nil
        }
    }
    return nil, errors.New("user not found")
}