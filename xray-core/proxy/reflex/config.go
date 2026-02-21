package reflex

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
)

// MemoryAccount is an in-memory representation of a Reflex account.
type MemoryAccount struct {
	ID string
}

func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		ID: a.GetId(),
	}, nil
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.ID == account.ID
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Id: a.ID,
	}
}
