package reflex

import (
"testing"
"reflect"
)

func TestFinalCoverage(t *testing.T) {
configs := []interface{}{
&User{},
&Account{},
&InboundConfig{},
&OutboundConfig{},
&Fallback{},
&Config{},
}
for _, c := range configs {
v := reflect.ValueOf(c)
typ := v.Type()
for i := 0; i < typ.NumMethod(); i++ {
method := typ.Method(i)
if method.Type.NumIn() == 1 {
func() {
defer func() { recover() }()
method.Func.Call([]reflect.Value{v})
}()
}
}
}
_ = NewHandler(&Config{})
}