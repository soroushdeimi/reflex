package reflex

import (
	"google.golang.org/protobuf/reflect/protoreflect"
)

func (*InboundConfig) ProtoReflect() protoreflect.Message  { return nil }
func (*OutboundConfig) ProtoReflect() protoreflect.Message { return nil }
