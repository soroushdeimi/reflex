package reflex

import (
	"crypto/tls"

	"github.com/xtls/xray-core/common/errors"
)

// BuildServerTLSConfig creates a tls.Config for server-side TLS+ECH from
// the proto ECHSettings. It loads the TLS certificate from disk and generates
// a fresh ECH keypair using the configured public name.
func BuildServerTLSConfig(ech *ECHSettings) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(ech.GetCertFile(), ech.GetKeyFile())
	if err != nil {
		return nil, errors.New("ECH: failed to load TLS certificate").Base(err)
	}

	publicName := ech.GetPublicName()
	if publicName == "" {
		publicName = "cloudflare.com"
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	echKeySet, err := GenerateECHKeySet(1, publicName)
	if err != nil {
		return nil, errors.New("ECH: failed to generate ECH key set").Base(err)
	}

	if err := ApplyECHServer(tlsCfg, echKeySet); err != nil {
		return nil, errors.New("ECH: failed to apply ECH server config").Base(err)
	}

	return tlsCfg, nil
}

// BuildClientTLSConfig creates a tls.Config for client-side TLS+ECH from
// the proto ECHSettings. For testing with self-signed certificates the
// insecure flag skips server certificate verification.
func BuildClientTLSConfig(ech *ECHSettings) (*tls.Config, error) {
	serverName := ech.GetServerName()
	if serverName == "" {
		serverName = ech.GetPublicName()
	}

	tlsCfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: ech.GetInsecure(),
	}

	return tlsCfg, nil
}
