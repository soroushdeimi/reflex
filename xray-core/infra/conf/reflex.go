package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexUserConfig is user configuration for Reflex inbound.
type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

// ReflexServerConfig is Reflex inbound configuration.
type ReflexServerConfig struct {
	Clients   []*ReflexUserConfig `json:"clients"`
	Fallback  *ReflexFallback    `json:"fallback"`
}

// ReflexFallback is fallback destination (e.g. port).
type ReflexFallback struct {
	Dest uint32 `json:"dest"`
}

// Build implements Buildable.
func (c *ReflexServerConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		Clients: make([]*reflex.User, 0, len(c.Clients)),
	}

	for _, u := range c.Clients {
		if u == nil || u.ID == "" {
			continue
		}
		config.Clients = append(config.Clients, &reflex.User{
			Id:     u.ID,
			Policy: u.Policy,
		})
	}

	if c.Fallback != nil && c.Fallback.Dest != 0 {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}

// ReflexClientTarget is a single Reflex server (for outbound).
type ReflexClientTarget struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	ID      string   `json:"id"`
}

// ReflexClientConfig is Reflex outbound configuration.
type ReflexClientConfig struct {
	Servers []*ReflexClientTarget `json:"servers"`
}

// Build implements Buildable.
func (c *ReflexClientConfig) Build() (proto.Message, error) {
	if len(c.Servers) == 0 {
		return nil, errors.New("Reflex outbound: no server specified")
	}
	server := c.Servers[0]
	if server.Address == nil {
		return nil, errors.New("Reflex server address is not set")
	}
	if server.Port == 0 {
		return nil, errors.New("Reflex server port is not set")
	}
	if server.ID == "" {
		return nil, errors.New("Reflex server id (UUID) is not set")
	}

	config := &reflex.OutboundConfig{
		Address: server.Address.Build().AsAddress().String(),
		Port:    uint32(server.Port),
		Id:      server.ID,
	}

	// OutboundConfig is used by the outbound handler; we need to return
	// a type that the core expects. The core expects a proto.Message for
	// proxy settings. reflex.OutboundConfig is already a proto message.
	return config, nil
}
