package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ============================================================
// Inbound
// ============================================================

// ReflexInboundConfig is the JSON configuration for a reflex inbound.
type ReflexInboundConfig struct {
	Clients []struct {
		ID     string `json:"id"`
		Policy string `json:"policy"`
	} `json:"clients"`

	Fallback *struct {
		Dest uint32 `json:"dest"`
	} `json:"fallback"`
}

// Build implements Buildable — converts JSON config to proto message.
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{}

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

	return config, nil
}

// ============================================================
// Outbound
// ============================================================

// ReflexOutboundConfig is the JSON configuration for a reflex outbound.
// Fields map to reflex.OutboundConfig proto fields (address, port, id).
type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	ID      string `json:"id"`
}

// Build implements Buildable — converts JSON config to proto message.
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	return &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.ID,
	}, nil
}
