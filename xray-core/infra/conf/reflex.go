package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexUserConfig is user configuration
type ReflexUserConfig struct {
	Id     string `json:"id"`
	Policy string `json:"policy"`
}

// ReflexInboundConfig is Inbound configuration
type ReflexInboundConfig struct {
	Clients  []*ReflexUserConfig `json:"clients"`
	Fallback *ReflexFallback     `json:"fallback"`
}

// ReflexFallback is fallback configuration
type ReflexFallback struct {
	Dest uint32 `json:"dest"`
}

// Build implements Buildable
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		Clients: make([]*reflex.User, len(c.Clients)),
	}

	for idx, rawUser := range c.Clients {
		if rawUser.Id == "" {
			return nil, errors.New("reflex user id is not set")
		}

		config.Clients[idx] = &reflex.User{
			Id:     rawUser.Id,
			Policy: rawUser.Policy,
		}
	}

	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}

// ReflexOutboundConfig is configuration of reflex servers
type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Id      string `json:"id"`
}

// Build implements Buildable
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	if c.Address == "" {
		return nil, errors.New("reflex server address is not set")
	}
	if c.Port == 0 {
		return nil, errors.New("invalid reflex port")
	}
	if c.Id == "" {
		return nil, errors.New("reflex id is not specified")
	}

	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    uint32(c.Port),
		Id:      c.Id,
	}

	return config, nil
}
