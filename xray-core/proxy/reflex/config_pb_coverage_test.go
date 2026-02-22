package reflex

import "testing"

func TestConfigPbGeneratedCoverage(t *testing.T) {
	msgs := []any{
		&User{},
		&Account{},
		&InboundConfig{},
		&Fallback{},
		&OutboundConfig{},
	}

	for _, m := range msgs {
		if x, ok := m.(interface{ Reset() }); ok {
			x.Reset()
		}
		if x, ok := m.(interface{ String() string }); ok {
			_ = x.String()
		}
		if x, ok := m.(interface{ ProtoMessage() }); ok {
			x.ProtoMessage()
		}
		if x, ok := m.(interface{ ProtoReflect() any }); ok {
			_ = x.ProtoReflect()
		}
	}

	_, _ = (&User{}).Descriptor()
	_, _ = (&Account{}).Descriptor()
	_, _ = (&InboundConfig{}).Descriptor()
	_, _ = (&Fallback{}).Descriptor()
	_, _ = (&OutboundConfig{}).Descriptor()
}
