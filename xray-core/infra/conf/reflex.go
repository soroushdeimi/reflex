package conf

import (
	"encoding/json"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
)

// ReflexInboundConfig is the JSON config wrapper for Reflex inbound
type ReflexInboundConfig struct {
	Clients   []json.RawMessage `json:"clients"`
	Fallbacks []*FallbackConfig  `json:"fallbacks"`
}

type FallbackConfig struct {
	Name string `json:"name"`
	Alpn string `json:"alpn"`
	Path string `json:"path"`
	Type string `json:"type"`
	Dest string `json:"dest"`
	Xver uint64 `json:"xver"`
}

// Build converts ReflexInboundConfig to proto.Message
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	cfg := &inbound.Config{
		Clients: make([]*protocol.User, 0, len(c.Clients)),
	}

	// Process clients
	for _, rawUser := range c.Clients {
		// First extract the client metadata
		var userObj struct {
			ID       string          `json:"id"`
			Level    uint32          `json:"level"`
			Email    string          `json:"email"`
			Account  json.RawMessage `json:"account"`
		}
		if err := json.Unmarshal(rawUser, &userObj); err != nil {
			return nil, errors.New("failed to parse user").Base(err).AtError()
		}

		// Create the User object
		user := &protocol.User{
			Level: userObj.Level,
			Email: userObj.Email,
		}

		// Process account
		if userObj.Account != nil {
			// Parse the account as a reflex Account
			var accountObj struct {
				Type   string `json:"type"`
				ID     string `json:"id"`
				Policy string `json:"policy"`
			}
			if err := json.Unmarshal(userObj.Account, &accountObj); err == nil {
				reflexAccount := &reflex.Account{
					Id:     accountObj.ID,
					Policy: accountObj.Policy,
				}
				user.Account = serial.ToTypedMessage(reflexAccount)
			}
		}

		cfg.Clients = append(cfg.Clients, user)
	}

	for _, fb := range c.Fallbacks {
		cfg.Fallbacks = append(cfg.Fallbacks, &inbound.Fallback{
			Name: fb.Name,
			Alpn: fb.Alpn,
			Path: fb.Path,
			Type: fb.Type,
			Dest: fb.Dest,
			Xver: fb.Xver,
		})
	}
	return cfg, nil
}

// ReflexOutboundConfig is the JSON config wrapper for Reflex outbound
type ReflexOutboundConfig struct {
	Vnext []json.RawMessage `json:"vnext"`
}

// Build converts ReflexOutboundConfig to proto.Message
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	cfg := &outbound.Config{
		Vnext: make([]*protocol.ServerEndpoint, 0, len(c.Vnext)),
	}

	// Process vnext endpoints
	for _, rawEndpoint := range c.Vnext {
		// Parse the endpoint JSON manually to handle Account properly
		var endpointObj struct {
			Address string `json:"address"`
			Port    uint32 `json:"port"`
			User    struct {
				ID       string          `json:"id"`
				Level    uint32          `json:"level"`
				Email    string          `json:"email"`
				Account  json.RawMessage `json:"account"`
			} `json:"user"`
		}
		if err := json.Unmarshal(rawEndpoint, &endpointObj); err != nil {
			return nil, errors.New("failed to parse server endpoint").Base(err).AtError()
		}

		// Create the endpoint
		addr := net.ParseAddress(endpointObj.Address)
		ipOrDomain := &net.IPOrDomain{}

		// Set the appropriate address type based on the parsed address
		if ipAddr := addr.IP(); ipAddr != nil {
			ipOrDomain.Address = &net.IPOrDomain_Ip{Ip: ipAddr}
		} else if domain := addr.Domain(); domain != "" {
			ipOrDomain.Address = &net.IPOrDomain_Domain{Domain: domain}
		}

		endpoint := &protocol.ServerEndpoint{
			Address: ipOrDomain,
			Port:    endpointObj.Port,
		}

		// Create the user
		if endpointObj.User.ID != "" || endpointObj.User.Account != nil {
			user := &protocol.User{
				Level: endpointObj.User.Level,
				Email: endpointObj.User.Email,
			}

			// Process account
			if endpointObj.User.Account != nil {
				// Parse the account as a reflex Account
				var accountObj struct {
					Type   string `json:"type"`
					ID     string `json:"id"`
					Policy string `json:"policy"`
				}
				if err := json.Unmarshal(endpointObj.User.Account, &accountObj); err == nil {
					reflexAccount := &reflex.Account{
						Id:     accountObj.ID,
						Policy: accountObj.Policy,
					}
					user.Account = serial.ToTypedMessage(reflexAccount)
				}
			}
			endpoint.User = user
		}

		cfg.Vnext = append(cfg.Vnext, endpoint)
	}

	return cfg, nil
}
