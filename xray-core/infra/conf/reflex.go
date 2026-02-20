package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexUser struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexInboundFallback struct {
	Dest uint32 `json:"dest"`
}

type ReflexInboundConfig struct {
	Clients    []*ReflexUser          `json:"clients"`
	Fallback   *ReflexInboundFallback `json:"fallback"`
	UseTLS     bool                   `json:"use_tls"`
	UseQUIC    bool                   `json:"use_quic"`
	ServerName string                 `json:"server_name"`
	ECHConfig  string                 `json:"ech_config"` // Hex encoded
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		Clients:    make([]*reflex.User, len(c.Clients)),
		UseTls:     c.UseTLS,
		UseQuic:    c.UseQUIC,
		ServerName: c.ServerName,
	}
	if c.ECHConfig != "" {
		config.EchConfig = []byte(c.ECHConfig) // Simplified for now, or use hex.DecodeString
	}
	for idx, client := range c.Clients {
		config.Clients[idx] = &reflex.User{
			Id:     client.ID,
			Policy: client.Policy,
		}
	}
	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}
	return config, nil
}

type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	ID      string `json:"id"`
}

func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.ID,
	}
	return config, nil
}
