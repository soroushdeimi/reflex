package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexInboundConfig struct {
	Clients   []json.RawMessage `json:"clients"`
	Fallback  *ReflexFallback   `json:"fallback"`
}

type ReflexFallback struct {
	Dest uint32 `json:"dest"`
}

// Build implements Buildable
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := new(reflex.InboundConfig)
	config.Clients = make([]*reflex.User, len(c.Clients))

	for idx, rawUser := range c.Clients {
		user := new(reflex.User)
		if err := json.Unmarshal(rawUser, user); err != nil {
			return nil, errors.New(`Reflex clients: invalid user`).Base(err)
		}

		u, err := uuid.ParseString(user.Id)
		if err != nil {
			return nil, errors.New(`Reflex clients: invalid UUID`).Base(err)
		}
		user.Id = u.String()

		config.Clients[idx] = user
	}

	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}

type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Id      string `json:"id"`
}

// Build implements Buildable
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	config := new(reflex.OutboundConfig)
	config.Address = c.Address
	config.Port = uint32(c.Port)
	config.Id = c.Id

	u, err := uuid.ParseString(c.Id)
	if err != nil {
		return nil, errors.New(`Reflex outbound: invalid UUID`).Base(err)
	}
	config.Id = u.String()

	return config, nil
}

