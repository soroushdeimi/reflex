package conf

import (
	//"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexUser struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexInboundConfig struct {
	Clients []*ReflexUser `json:"clients"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	cfg := new(reflex.InboundConfig)

	for _, raw := range c.Clients {
		client := new(reflex.User)

		if raw.ID == "" {
			return nil, errors.New("User ID not available.")
		}

		cfg.Clients = append(cfg.Clients, client)
	}

	return cfg, nil
}
