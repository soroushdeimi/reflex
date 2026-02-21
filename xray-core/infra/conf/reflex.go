package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
}

type ReflexECHConfig struct {
	Enabled    bool   `json:"enabled"`
	PublicName string `json:"publicName"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	ServerName string `json:"serverName"`
	Insecure   bool   `json:"insecure"`
}

type ReflexInboundConfig struct {
	Clients  []*ReflexUserConfig   `json:"clients"`
	Fallback *ReflexFallbackConfig `json:"fallback"`
	ECH      *ReflexECHConfig      `json:"ech"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{}

	for _, rawUser := range c.Clients {
		if rawUser.ID == "" {
			return nil, errors.New("Reflex client: missing id")
		}
		config.Clients = append(config.Clients, &reflex.User{
			Id:     rawUser.ID,
			Policy: rawUser.Policy,
		})
	}

	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	if c.ECH != nil && c.ECH.Enabled {
		if c.ECH.CertFile == "" || c.ECH.KeyFile == "" {
			return nil, errors.New("Reflex ECH: certFile and keyFile are required for server-side ECH")
		}
		config.Ech = &reflex.ECHSettings{
			Enabled:    true,
			PublicName: c.ECH.PublicName,
			CertFile:   c.ECH.CertFile,
			KeyFile:    c.ECH.KeyFile,
		}
	}

	return config, nil
}

type ReflexOutboundConfig struct {
	Address string          `json:"address"`
	Port    uint32          `json:"port"`
	ID      string          `json:"id"`
	Policy  string          `json:"policy"`
	ECH     *ReflexECHConfig `json:"ech"`
}

func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	if c.Address == "" {
		return nil, errors.New("Reflex outbound: missing server address")
	}
	if c.Port == 0 {
		return nil, errors.New("Reflex outbound: missing server port")
	}
	if c.ID == "" {
		return nil, errors.New("Reflex outbound: missing client id")
	}

	outConfig := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.ID,
		Policy:  c.Policy,
	}

	if c.ECH != nil && c.ECH.Enabled {
		outConfig.Ech = &reflex.ECHSettings{
			Enabled:    true,
			PublicName: c.ECH.PublicName,
			ServerName: c.ECH.ServerName,
			Insecure:   c.ECH.Insecure,
		}
	}

	return outConfig, nil
}
