package reflex

import (
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount represents an in-memory account for Reflex protocol
type MemoryAccount struct {
	ID     string
	Policy string
}

// Equals implements protocol.Account interface
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID == reflexAccount.ID
}

// ToProto implements protocol.Account interface
func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Id: a.ID,
	}
}

// AsAccount converts proto Account to MemoryAccount
func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		ID: a.Id,
	}, nil
}
