package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexAccount struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexServerTarget struct {
	Address string          `json:"address"`
	Port    uint16          `json:"port"`
	Users   []ReflexAccount `json:"users"`
}

type ReflexClientConfig struct {
	Servers               []*ReflexServerTarget `json:"servers"`
}

type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
	Path string `json:"path"`
}

type ReflexServerConfig struct {
	Clients               []*ReflexUserConfig   `json:"clients"`
	Fallback              *ReflexFallbackConfig `json:"fallback"`
}

func (c *ReflexClientConfig) Build() (proto.Message, error) {
	config := new(reflex.OutboundConfig)
	if len(c.Servers) == 0 {
		return nil, errors.New("no server specified in reflex outbound config")
	}

	server := c.Servers[0]
	config.Address = server.Address
	config.Port = uint32(server.Port)

	if len(server.Users) > 0 {
		config.Id = server.Users[0].ID
	}

	return config, nil
}

func (c *ReflexServerConfig) Build() (proto.Message, error) {
	config := new(reflex.InboundConfig)
	config.Clients = make([]*reflex.User, len(c.Clients))

	for idx, user := range c.Clients {
		config.Clients[idx] = &reflex.User{
			Id:     user.ID,
			Policy: user.Policy,
		}
	}

	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}