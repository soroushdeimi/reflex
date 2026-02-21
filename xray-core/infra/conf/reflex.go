package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexInboundConfig
//
// This struct parses JSON configuration for the Reflex inbound protocol.
// It acts as an intermediate layer between JSON config and the protobuf
// configuration (reflex.InboundConfig).
//
// JSON  --->  ReflexInboundConfig  --->  reflex.InboundConfig (protobuf)
type ReflexInboundConfig struct {
	Clients []struct {
		ID     string `json:"id"`
		Policy string `json:"policy"`
	} `json:"clients"`

	Fallback *struct {
		Dest uint32 `json:"dest"`
	} `json:"fallback"`
}

// Build converts the JSON-based configuration into the protobuf-based
// reflex.InboundConfig which is used internally by the Reflex handler.
//
// This is required because Xray internally works with protobuf configs,
// not raw JSON.
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{}

	// Convert client definitions
	for _, client := range c.Clients {
		config.Clients = append(config.Clients, &reflex.User{
			Id:     client.ID,
			Policy: client.Policy,
		})
	}

	// Convert fallback configuration (if present)
	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}
