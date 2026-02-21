package reflex

import (
    "github.com/xtls/xray-core/infra/conf"
    "github.com/xtls/xray-core/proxy/reflex"
    "google.golang.org/protobuf/proto"
)

type UserConfig struct {
    ID     string `json:"id"`
    Policy string `json:"policy"`
}
type FallbackConfig struct {
    Dest uint32 `json:"dest"`
}
type InboundConfig struct {
    Clients  []*UserConfig   `json:"clients"`
    Fallback *FallbackConfig `json:"fallback"`
}
func (c *InboundConfig) Build() (proto.Message, error) {
    config := &reflex.InboundConfig{}
    if c.Fallback != nil { config.Fallback = &reflex.Fallback{Dest: c.Fallback.Dest} }
    for _, client := range c.Clients {
        config.Clients = append(config.Clients, &reflex.User{Id: client.ID, Policy: client.Policy})
    }
    return config, nil
}
type OutboundConfig struct {
    Address string `json:"address"`
    Port    uint32 `json:"port"`
    ID      string `json:"id"`
}
func (c *OutboundConfig) Build() (proto.Message, error) {
    return &reflex.OutboundConfig{Address: c.Address, Port: c.Port, Id: c.ID}, nil
}
func init() {
    conf.RegisterConfigCreator("reflex", func() interface{} { return new(InboundConfig) })
}
