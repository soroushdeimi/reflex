package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexInboundConfig struct {
	Clients []struct {
		ID     string `json:"id"`
		Policy string `json:"policy"`
	} `json:"clients"`

	Fallback *struct {
		Dest uint32 `json:"dest"`
	} `json:"fallback"`
}

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
