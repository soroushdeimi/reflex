package conf

import (
	//"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexUser struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallback struct {
	Dest uint32 `json:"dest"`
}
type ReflexInboundConfig struct {
	Clients  []*ReflexUser   `json:"clients"`
	Fallback *ReflexFallback `json:"fallback"`
}

// This function convert ReflexInboundConfig into reflex.InboundConfig.
// Build validates the inbound config, converts clients and fallback into reflex internal config, and returns a ready InboundConfig.

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	cfg := &reflex.InboundConfig{
		Clients: make([]*reflex.User, 0, len(c.Clients)),
	}

	for _, raw := range c.Clients {
		if raw.ID == "" {
			return nil, errors.New("user ID not available")
		}

		client := &reflex.User{
			Id:     raw.ID,
			Policy: raw.Policy,
		}

		cfg.Clients = append(cfg.Clients, client)
	}

	if c.Fallback != nil {
		cfg.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return cfg, nil
}
