package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexUserConfig matches inbound.settings.clients items.
type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexInboundFallbackConfig struct {
	Dest uint16 `json:"dest"`
}

// ReflexInboundConfig matches inbound.settings for protocol "reflex".
type ReflexInboundConfig struct {
	Clients  []ReflexUserConfig           `json:"clients"`
	Fallback *ReflexInboundFallbackConfig `json:"fallback"`
}

// Build implements Buildable.
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	cfg := &reflex.InboundConfig{}

	if len(c.Clients) == 0 {
		return nil, errors.New(`Reflex inbound settings: "clients" must not be empty`)
	}

	cfg.Clients = make([]*reflex.User, 0, len(c.Clients))
	for _, u := range c.Clients {
		if u.ID == "" {
			return nil, errors.New(`Reflex inbound settings: client "id" is empty`)
		}
		parsed, err := uuid.ParseString(u.ID)
		if err != nil {
			return nil, errors.New(`Reflex inbound settings: invalid client "id"`).Base(err)
		}

		cfg.Clients = append(cfg.Clients, &reflex.User{
			Id:     parsed.String(),
			Policy: u.Policy,
		})
	}

	if c.Fallback != nil {
		if c.Fallback.Dest == 0 {
			return nil, errors.New(`Reflex inbound settings: fallback "dest" is invalid`)
		}
		cfg.Fallback = &reflex.Fallback{
			Dest: uint32(c.Fallback.Dest),
		}
	}

	return cfg, nil
}

// ReflexOutboundConfig matches outbound.settings for protocol "reflex".
type ReflexOutboundConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	ID      string   `json:"id"`
}

// Build implements Buildable.
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New(`Reflex outbound settings: "address" is not set`)
	}
	if c.Port == 0 {
		return nil, errors.New(`Reflex outbound settings: "port" is invalid`)
	}
	if c.ID == "" {
		return nil, errors.New(`Reflex outbound settings: "id" is empty`)
	}
	parsed, err := uuid.ParseString(c.ID)
	if err != nil {
		return nil, errors.New(`Reflex outbound settings: invalid "id"`).Base(err)
	}

	return &reflex.OutboundConfig{
		Address: c.Address.Address.String(),
		Port:    uint32(c.Port),
		Id:      parsed.String(),
	}, nil
}
