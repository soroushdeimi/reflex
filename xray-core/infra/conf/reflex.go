package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexUser struct {
	Id     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexInboundConfig struct {
	Clients  []ReflexUser `json:"clients"`
	Fallback *struct {
		Dest uint32 `json:"dest"`
	} `json:"fallback"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		Clients: make([]*reflex.User, 0, len(c.Clients)),
	}

	for _, client := range c.Clients {
		config.Clients = append(config.Clients, &reflex.User{
			Id:     client.Id,
			Policy: client.Policy,
		})
	}

	if c.Fallback != nil {
		config.Fallback = &reflex.FallbackDest{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}

type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Id      string `json:"id"`
}

func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	return &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.Id,
	}, nil
}
