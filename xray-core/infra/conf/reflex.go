package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// Inbound Config

// ReflexUserConfig user settings in JSON
type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

// ReflexFallbackConfig fallback settings in JSON
type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
}

// ReflexInboundConfig Inbound settings in JSON
type ReflexInboundConfig struct {
	Clients  []*ReflexUserConfig   `json:"clients"`
	Fallback *ReflexFallbackConfig `json:"fallback"`
}

// Build (convert Json to Proto) (impl interface Buildable)
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{}

	// convert users
	if c.Clients != nil {
		config.Clients = make([]*reflex.User, len(c.Clients))
		for idx, user := range c.Clients {
			config.Clients[idx] = &reflex.User{
				Id:     user.ID,
				Policy: user.Policy,
			}
		}
	}

	// set fallback
	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}

//Outbound Config

// ReflexOutboundConfig Outbound settings in JSON
type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	ID      string `json:"id"`
}

// Build (convert Json to Proto)  (impl interface Buildable)
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.ID,
	}

	return config, nil
}
