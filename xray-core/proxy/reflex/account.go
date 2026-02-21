package reflex

import (
	"encoding/json"

	"github.com/xtls/xray-core/common"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
)

// Account represents a Reflex user account configuration
type Account struct {
	ID     string
	Policy string
}

func (a *Account) Reset()         { *a = Account{} }
func (a *Account) String() string { return a.ID }
func (a *Account) ProtoMessage()  {}
func (a *Account) ProtoReflect() protoreflect.Message {
	return nil
}

// MemoryAccount is the in-memory form of a Reflex account
type MemoryAccount struct {
	ID     *protocol.ID
	Policy string
}

// Equals implements protocol.Account interface
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID.Equals(reflexAccount.ID)
}

// ToProto converts MemoryAccount to proto.Message
func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		ID:     a.ID.String(),
		Policy: a.Policy,
	}
}

func init() {
	common.Must(serial.RegisterCustomCodec(
		(*Account)(nil),
		"xray.proxy.reflex.Account",
		func(message proto.Message) ([]byte, error) {
			return json.Marshal(message.(*Account))
		},
		func(data []byte, message proto.Message) error {
			return json.Unmarshal(data, message.(*Account))
		},
	))
}

// AsAccount converts Account to MemoryAccount
func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.ID)
	if err != nil {
		return nil, errors.New("failed to parse account ID").Base(err)
	}
	return &MemoryAccount{
		ID:     protocol.NewID(id),
		Policy: a.Policy,
	}, nil
}
