package outbound

import (
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
