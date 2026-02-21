package reflex

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/cryptobyte"
)

const (
	// ECH cipher suite IDs per RFC 9180 / draft-ietf-tls-esni
	echVersionDraft = 0xfe0d
	kemX25519       = 0x0020
	kdfHKDFSHA256   = 0x0001
	aeadAES128GCM   = 0x0001
	aeadChacha20    = 0x0003
)

// ECHKeySet holds a generated ECH config and its private key, suitable for
// configuring a TLS server that supports Encrypted Client Hello.
type ECHKeySet struct {
	ConfigID   uint8
	PublicName string
	PrivateKey []byte
	Config     []byte // Serialized ECHConfig
}

// GenerateECHKeySet creates a new X25519-based ECH keypair and serialized
// ECHConfig suitable for server-side tls.EncryptedClientHelloKeys.
func GenerateECHKeySet(configID uint8, publicName string) (*ECHKeySet, error) {
	curve := ecdh.X25519()

	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, errors.New("ECH: failed to generate random seed").Base(err)
	}

	privKey, err := curve.NewPrivateKey(seed)
	if err != nil {
		return nil, errors.New("ECH: failed to create X25519 private key").Base(err)
	}
	pubKeyBytes := privKey.PublicKey().Bytes()

	config, err := marshalECHConfig(configID, publicName, pubKeyBytes)
	if err != nil {
		return nil, errors.New("ECH: failed to marshal config").Base(err)
	}

	return &ECHKeySet{
		ConfigID:   configID,
		PublicName: publicName,
		PrivateKey: seed,
		Config:     config,
	}, nil
}

// marshalECHConfig builds a wire-format ECHConfig per draft-ietf-tls-esni-18.
func marshalECHConfig(configID uint8, publicName string, publicKey []byte) ([]byte, error) {
	var b cryptobyte.Builder

	b.AddUint16(echVersionDraft)
	b.AddUint16LengthPrefixed(func(contents *cryptobyte.Builder) {
		contents.AddUint8(configID)
		contents.AddUint16(kemX25519)
		// Public key (length-prefixed)
		contents.AddUint16(uint16(len(publicKey)))
		contents.AddBytes(publicKey)
		// Cipher suites
		contents.AddUint16LengthPrefixed(func(suites *cryptobyte.Builder) {
			// HKDF-SHA256 + AES-128-GCM
			suites.AddUint16(kdfHKDFSHA256)
			suites.AddUint16(aeadAES128GCM)
			// HKDF-SHA256 + ChaCha20-Poly1305
			suites.AddUint16(kdfHKDFSHA256)
			suites.AddUint16(aeadChacha20)
		})
		// Maximum name length
		contents.AddUint8(0)
		// Public name (length-prefixed)
		contents.AddUint8(uint8(len(publicName)))
		contents.AddBytes([]byte(publicName))
		// Extensions (empty)
		contents.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {})
	})

	return b.Bytes()
}

// MarshalECHConfigList wraps one or more ECHConfigs into an ECHConfigList
// suitable for tls.Config.EncryptedClientHelloConfigList.
func MarshalECHConfigList(configs ...[]byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, cfg := range configs {
			list.AddBytes(cfg)
		}
	})
	return b.Bytes()
}

// ApplyECHServer configures a tls.Config for server-side ECH using the
// provided key sets. This allows the Reflex inbound to accept ECH-enabled
// TLS connections, hiding the true SNI from network observers.
func ApplyECHServer(tlsConfig *tls.Config, keySets ...*ECHKeySet) error {
	if len(keySets) == 0 {
		return nil
	}

	echKeys := make([]tls.EncryptedClientHelloKey, 0, len(keySets))
	for _, ks := range keySets {
		echKeys = append(echKeys, tls.EncryptedClientHelloKey{
			Config:      ks.Config,
			PrivateKey:  ks.PrivateKey,
			SendAsRetry: true,
		})
	}

	tlsConfig.EncryptedClientHelloKeys = echKeys
	tlsConfig.MinVersion = tls.VersionTLS13
	return nil
}

// ApplyECHClient configures a tls.Config for client-side ECH. The
// echConfigList should be a serialized ECHConfigList obtained from DNS
// HTTPS records or out-of-band distribution.
func ApplyECHClient(tlsConfig *tls.Config, echConfigList []byte) {
	tlsConfig.EncryptedClientHelloConfigList = echConfigList
	tlsConfig.MinVersion = tls.VersionTLS13
}

// ECHConfig holds configuration for enabling ECH on Reflex connections.
type ECHConfig struct {
	Enabled    bool
	PublicName string // Outer SNI visible to observers (e.g., "cloudflare.com")
	ConfigID   uint8
	KeySet     *ECHKeySet // Server-side only
	ConfigList []byte     // Client-side only (serialized ECHConfigList)
}

// NewServerECHConfig generates a complete ECH configuration for a Reflex
// server, including keypair generation.
func NewServerECHConfig(publicName string, configID uint8) (*ECHConfig, error) {
	keySet, err := GenerateECHKeySet(configID, publicName)
	if err != nil {
		return nil, err
	}

	configList, err := MarshalECHConfigList(keySet.Config)
	if err != nil {
		return nil, err
	}

	return &ECHConfig{
		Enabled:    true,
		PublicName: publicName,
		ConfigID:   configID,
		KeySet:     keySet,
		ConfigList: configList,
	}, nil
}
