package proxy

import (
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/reflex"
)

type ReflexInboundConfig struct {
	Clients  []ReflexUser `json:"clients"`
	Fallback *ReflexFallback `json:"fallback"`
}

type ReflexUser struct {
	Id     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallback struct {
	Dest uint32 `json:"dest"`
}

func (c *ReflexInboundConfig) Build() (interface{}, error) {
	config := &reflex.InboundConfig{}

	for _, client := range c.Clients {
		config.Clients = append(config.Clients, reflex.User{
			Id:     client.Id,
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

func init() {
	conf.RegisterConfigCreator("reflex", func() interface{} {
		return new(ReflexInboundConfig)
	})
}
