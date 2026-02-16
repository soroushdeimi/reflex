package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexUserConfig struct {
	Id     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
}

type ReflexInboundConfig struct {
	Clients  []*ReflexUserConfig   `json:"clients"`
	Fallback *ReflexFallbackConfig `json:"fallback"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		Clients: make([]*reflex.User, 0, len(c.Clients)),
	}

	for _, client := range c.Clients {
		if client == nil {
			continue
		}
		if client.Id == "" {
			return nil, errors.New("reflex client id is empty")
		}
		config.Clients = append(config.Clients, &reflex.User{
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

type ReflexOutboundConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	Id      string   `json:"id"`
}

func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("reflex outbound address is not set")
	}
	if c.Port == 0 {
		return nil, errors.New("reflex outbound port is not set")
	}

	return &reflex.OutboundConfig{
		Address: c.Address.Address.String(),
		Port:    uint32(c.Port),
		Id:      c.Id,
	}, nil
}
