package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexInboundConfig struct {
	Clients  []*ReflexUserConfig   `json:"clients"`
	Fallback *ReflexFallbackConfig `json:"fallback"`
}

type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		Clients: make([]*reflex.User, len(c.Clients)),
	}

	for i, client := range c.Clients {
		config.Clients[i] = &reflex.User{
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
