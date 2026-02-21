package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexUserConfig is one inbound Reflex user entry.
type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

// ReflexInboundConfig is the JSON inbound settings for protocol=reflex.
type ReflexInboundConfig struct {
	Clients  []json.RawMessage `json:"clients"`
	Fallback *struct {
		Dest uint32 `json:"dest"`
	} `json:"fallback"`
}

// Build implements Buildable.
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{Clients: make([]*reflex.User, 0, len(c.Clients))}
	for _, rawUser := range c.Clients {
		user := new(ReflexUserConfig)
		if err := json.Unmarshal(rawUser, user); err != nil {
			return nil, errors.New("invalid Reflex user").Base(err)
		}
		u, err := uuid.ParseString(user.ID)
		if err != nil {
			return nil, err
		}
		config.Clients = append(config.Clients, &reflex.User{Id: u.String(), Policy: user.Policy})
	}
	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{Dest: c.Fallback.Dest}
	}
	return config, nil
}

// ReflexOutboundConfig is the JSON outbound settings for protocol=reflex.
type ReflexOutboundConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	ID      string   `json:"id"`
}

// Build implements Buildable.
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("Reflex outbound: address is not set")
	}
	if c.Port == 0 {
		return nil, errors.New("Reflex outbound: port is not set")
	}
	u, err := uuid.ParseString(c.ID)
	if err != nil {
		return nil, err
	}
	return &reflex.OutboundConfig{Address: c.Address.String(), Port: uint32(c.Port), Id: u.String()}, nil
}
