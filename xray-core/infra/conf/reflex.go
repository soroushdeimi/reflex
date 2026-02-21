package conf

import (
	"encoding/base64"

	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexInboundConfig struct {
	Clients  []ReflexUser `json:"clients"`
	Fallback *ReflexFallback `json:"fallback"`
	TLS      *ReflexTLSSettings `json:"tls"`
}

type ReflexUser struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallback struct {
	Dest uint32 `json:"dest"`
}

type ReflexTLSSettings struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name"`
	ECHKey     string `json:"ech_key"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		Clients: make([]*reflex.User, 0, len(c.Clients)),
	}
	for _, client := range c.Clients {
		config.Clients = append(config.Clients, &reflex.User{
			Id:     client.ID,
			Policy: client.Policy,
		})
	}
	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}
	if c.TLS != nil {
		config.Tls = &reflex.TLSSettings{
			Enabled:    c.TLS.Enabled,
			ServerName: c.TLS.ServerName,
			CertFile:   c.TLS.CertFile,
			KeyFile:    c.TLS.KeyFile,
		}
		if c.TLS.ECHKey != "" {
			key, err := base64.StdEncoding.DecodeString(c.TLS.ECHKey)
			if err != nil {
				return nil, err
			}
			config.Tls.EchKey = key
		}
	}
	return config, nil
}

type ReflexOutboundConfig struct {
	Address string             `json:"address"`
	Port    uint32             `json:"port"`
	ID      string             `json:"id"`
	TLS     *ReflexTLSSettings `json:"tls"`
}

func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.ID,
	}
	if c.TLS != nil {
		config.Tls = &reflex.TLSSettings{
			Enabled:    c.TLS.Enabled,
			ServerName: c.TLS.ServerName,
			CertFile:   c.TLS.CertFile,
			KeyFile:    c.TLS.KeyFile,
		}
		if c.TLS.ECHKey != "" {
			key, err := base64.StdEncoding.DecodeString(c.TLS.ECHKey)
			if err != nil {
				return nil, err
			}
			config.Tls.EchKey = key
		}
	}
	return config, nil
}
