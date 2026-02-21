package reflex

import (
	"github.com/xtls/xray-core/common/protocol"
)

type Policy struct {
	Name     string
	MaxSpeed int64
	RouteTag string
}

func BuildPolicy(req []byte, user *protocol.MemoryUser) *Policy {
	p := &Policy{
		Name:     "default",
		MaxSpeed: 0,
		RouteTag: "",
	}

	if len(req) > 0 {
		p.Name = string(req)
	}

	return p
}

func EncodePolicy(p *Policy) []byte {
	// نسخهٔ ساده: فقط نام را برمی‌گردانیم
	return []byte(p.Name)
}
