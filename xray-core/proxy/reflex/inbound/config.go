package inbound

import (
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
