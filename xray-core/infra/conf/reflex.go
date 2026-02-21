package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexInboundConfig represents JSON configuration for Reflex inbound handler.
type ReflexInboundConfig struct {
	Clients  []json.RawMessage `json:"clients"`
	Fallback *ReflexFallback   `json:"fallback"`
}

// ReflexFallback represents fallback configuration in JSON.
type ReflexFallback struct {
	Dest uint32 `json:"dest"`
}

// ReflexOutboundConfig represents JSON configuration for Reflex outbound handler.
type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Id      string `json:"id"`
}

// Build implements Buildable interface for ReflexInboundConfig.
// Converts JSON config to protobuf InboundConfig.
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := new(reflex.InboundConfig)
	config.Clients = make([]*reflex.User, len(c.Clients))

	// Parse each client from JSON
	for idx, rawUser := range c.Clients {
		user := new(reflex.User)
		if err := json.Unmarshal(rawUser, user); err != nil {
			return nil, errors.New("Reflex clients: invalid user").Base(err)
		}

		// Validate UUID format
		if _, err := uuid.ParseString(user.Id); err != nil {
			return nil, errors.New("Reflex clients: invalid UUID format").Base(err)
		}

		config.Clients[idx] = user
	}

	// Parse fallback if present
	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}

// Build implements Buildable interface for ReflexOutboundConfig.
// Converts JSON config to protobuf OutboundConfig.
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	// Validate UUID format
	if _, err := uuid.ParseString(c.Id); err != nil {
		return nil, errors.New("Reflex outbound: invalid UUID format").Base(err)
	}

	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      c.Id,
	}

	return config, nil
}
