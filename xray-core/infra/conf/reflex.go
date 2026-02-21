package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ReflexUserConfig mirrors the JSON structure for a single Reflex client.
type ReflexUserConfig struct {
	Id     string `json:"id"`
	Policy string `json:"policy"`
}

// ReflexFallbackConfig mirrors the JSON structure for Reflex fallback.
type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
}

// ReflexInboundConfig is the JSON-level inbound config for Reflex.
// Example:
// {
//   "protocol": "reflex",
//   "settings": {
//     "clients": [
//       { "id": "uuid-string", "policy": "mimic-http2-api" }
//     ],
//     "fallback": { "dest": 80 }
//   }
// }
type ReflexInboundConfig struct {
	Clients  []*ReflexUserConfig     `json:"clients"`
	Fallback *ReflexFallbackConfig   `json:"fallback"`
}

// Build implements Buildable and converts JSON config into protobuf InboundConfig.
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	cfg := &reflex.InboundConfig{}

	for _, u := range c.Clients {
		if u == nil {
			continue
		}
		cfg.Clients = append(cfg.Clients, &reflex.User{
			Id:     u.Id,
			Policy: u.Policy,
		})
	}

	if c.Fallback != nil {
		cfg.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return cfg, nil
}

