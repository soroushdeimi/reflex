package outbound

import (
	"encoding/json"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Config is the configuration for Reflex outbound
type Config struct {
	Address string
	Port    uint32
	UserID  string
	Policy  string
}

func (c *Config) Reset()         { *c = Config{} }
func (c *Config) String() string { return "reflex outbound config" }
func (c *Config) ProtoMessage()  {}
func (c *Config) ProtoReflect() protoreflect.Message {
	return nil
}

func init() {
	common.Must(serial.RegisterCustomCodec(
		(*Config)(nil),
		"xray.proxy.reflex.outbound.Config",
		func(message proto.Message) ([]byte, error) {
			return json.Marshal(message.(*Config))
		},
		func(data []byte, message proto.Message) error {
			return json.Unmarshal(data, message.(*Config))
		},
	))
}
