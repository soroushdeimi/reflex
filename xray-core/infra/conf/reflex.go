package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexUserConfig is the JSON shape for a Reflex user (inbound client).
type ReflexUserConfig struct {
	Id     string `json:"id"`
	Policy string `json:"policy"`
}

// ReflexInboundFallback is the JSON shape for Reflex inbound fallback.
type ReflexInboundFallback struct {
	Dest uint32 `json:"dest"`
}

// ReflexInboundConfig is the JSON-parsed Reflex inbound settings.
type ReflexInboundConfig struct {
	Clients   []*ReflexUserConfig      `json:"clients"`
	Fallback  *ReflexInboundFallback   `json:"fallback"`
}

// Build implements Buildable.
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{}
	if len(c.Clients) > 0 {
		config.Clients = make([]*reflex.User, 0, len(c.Clients))
		for _, u := range c.Clients {
			config.Clients = append(config.Clients, &reflex.User{
				Id:     u.Id,
				Policy: u.Policy,
			})
		}
	}
	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}
	return config, nil
}

// ReflexOutboundConfig is the JSON-parsed Reflex outbound settings.
type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Id      string `json:"id"`
}

// Build implements Buildable.
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.Id,
	}
	return config, nil
}
