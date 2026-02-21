package reflex

import (
    "github.com/xtls/xray-core/common/protocol"
)

type MemoryAccount struct {
    ID string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
    reflexAccount, ok := account.(*MemoryAccount)
    if !ok {
        return false
    }
    return a.ID == reflexAccount.ID
}

func (a *MemoryAccount) AsAccount() (protocol.Account, error) {
    return a, nil
}
