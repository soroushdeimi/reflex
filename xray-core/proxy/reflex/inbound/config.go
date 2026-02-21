package inbound

import (
	"encoding/json"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Config is the configuration for Reflex inbound
type Config struct {
	Clients  []*ClientConfig
	Fallback *FallbackConfig
}

func (c *Config) Reset()         { *c = Config{} }
func (c *Config) String() string { return "reflex inbound config" }
func (c *Config) ProtoMessage()  {}
func (c *Config) ProtoReflect() protoreflect.Message {
	return nil
}

func init() {
	common.Must(serial.RegisterCustomCodec(
		(*Config)(nil),
		"xray.proxy.reflex.inbound.Config",
		func(message proto.Message) ([]byte, error) {
			return json.Marshal(message.(*Config))
		},
		func(data []byte, message proto.Message) error {
			return json.Unmarshal(data, message.(*Config))
		},
	))
}

// ClientConfig represents client configuration
type ClientConfig struct {
	ID     string
	Policy string
}

// FallbackConfig represents fallback configuration
type FallbackConfig struct {
	Dest string
	ALPN string
}
