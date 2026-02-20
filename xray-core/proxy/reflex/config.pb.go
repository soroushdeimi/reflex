package reflex

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type User struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Policy        string                 `protobuf:"bytes,2,opt,name=policy,proto3" json:"policy,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (m *User) Reset() {
	*m = User{}
	info := &reflexMsgTypes[0]
	st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
	st.StoreMessageInfo(info)
}

func (m *User) String() string {
	return protoimpl.X.MessageStringOf(m)
}

func (*User) ProtoMessage() {}

func (m *User) ProtoReflect() protoreflect.Message {
	info := &reflexMsgTypes[0]
	if m != nil {
		st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
		if st.LoadMessageInfo() == nil {
			st.StoreMessageInfo(info)
		}
		return st
	}
	return info.MessageOf(m)
}

func (*User) Descriptor() ([]byte, []int) {
	return getDescriptorGZIP(), []int{0}
}

func (m *User) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *User) GetPolicy() string {
	if m != nil {
		return m.Policy
	}
	return ""
}

type Account struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (m *Account) Reset() {
	*m = Account{}
	info := &reflexMsgTypes[1]
	st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
	st.StoreMessageInfo(info)
}

func (m *Account) String() string {
	return protoimpl.X.MessageStringOf(m)
}

func (*Account) ProtoMessage() {}

func (m *Account) ProtoReflect() protoreflect.Message {
	info := &reflexMsgTypes[1]
	if m != nil {
		st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
		if st.LoadMessageInfo() == nil {
			st.StoreMessageInfo(info)
		}
		return st
	}
	return info.MessageOf(m)
}

func (*Account) Descriptor() ([]byte, []int) {
	return getDescriptorGZIP(), []int{1}
}

func (m *Account) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

type Fallback struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Dest          uint32                 `protobuf:"varint,1,opt,name=dest,proto3" json:"dest,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (m *Fallback) Reset() {
	*m = Fallback{}
	info := &reflexMsgTypes[2]
	st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
	st.StoreMessageInfo(info)
}

func (m *Fallback) String() string {
	return protoimpl.X.MessageStringOf(m)
}

func (*Fallback) ProtoMessage() {}

func (m *Fallback) ProtoReflect() protoreflect.Message {
	info := &reflexMsgTypes[2]
	if m != nil {
		st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
		if st.LoadMessageInfo() == nil {
			st.StoreMessageInfo(info)
		}
		return st
	}
	return info.MessageOf(m)
}

func (*Fallback) Descriptor() ([]byte, []int) {
	return getDescriptorGZIP(), []int{2}
}

func (m *Fallback) GetDest() uint32 {
	if m != nil {
		return m.Dest
	}
	return 0
}

type InboundConfig struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Clients       []*User                `protobuf:"bytes,1,rep,name=clients,proto3" json:"clients,omitempty"`
	Fallback      *Fallback              `protobuf:"bytes,2,opt,name=fallback,proto3" json:"fallback,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (m *InboundConfig) Reset() {
	*m = InboundConfig{}
	info := &reflexMsgTypes[3]
	st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
	st.StoreMessageInfo(info)
}

func (m *InboundConfig) String() string {
	return protoimpl.X.MessageStringOf(m)
}

func (*InboundConfig) ProtoMessage() {}

func (m *InboundConfig) ProtoReflect() protoreflect.Message {
	info := &reflexMsgTypes[3]
	if m != nil {
		st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
		if st.LoadMessageInfo() == nil {
			st.StoreMessageInfo(info)
		}
		return st
	}
	return info.MessageOf(m)
}

func (*InboundConfig) Descriptor() ([]byte, []int) {
	return getDescriptorGZIP(), []int{3}
}

func (m *InboundConfig) GetClients() []*User {
	if m != nil {
		return m.Clients
	}
	return nil
}

func (m *InboundConfig) GetFallback() *Fallback {
	if m != nil {
		return m.Fallback
	}
	return nil
}

type OutboundConfig struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Address       string                 `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Port          uint32                 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Id            string                 `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (m *OutboundConfig) Reset() {
	*m = OutboundConfig{}
	info := &reflexMsgTypes[4]
	st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
	st.StoreMessageInfo(info)
}

func (m *OutboundConfig) String() string {
	return protoimpl.X.MessageStringOf(m)
}

func (*OutboundConfig) ProtoMessage() {}

func (m *OutboundConfig) ProtoReflect() protoreflect.Message {
	info := &reflexMsgTypes[4]
	if m != nil {
		st := protoimpl.X.MessageStateOf(protoimpl.Pointer(m))
		if st.LoadMessageInfo() == nil {
			st.StoreMessageInfo(info)
		}
		return st
	}
	return info.MessageOf(m)
}

func (*OutboundConfig) Descriptor() ([]byte, []int) {
	return getDescriptorGZIP(), []int{4}
}

func (m *OutboundConfig) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *OutboundConfig) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *OutboundConfig) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

var File_proxy_reflex_config_proto protoreflect.FileDescriptor

const rawProtoDescriptor = "\n\x19proxy/reflex/config.proto\x12\x11xray.proxy.reflex\".\n" +
	"\x04User\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id\x12\x16\n\x06policy\x18\x02 \x01(\tR\x06policy\"\x19\n" +
	"\aAccount\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id\"\x1e\n\bFallback\x12\x12\n\x04dest\x18\x01 \x01(\rR\x04dest\"{\n" +
	"\rInboundConfig\x121\n\aclients\x18\x01 \x03(\v2\x17.xray.proxy.reflex.UserR\aclients\x127\n" +
	"\bfallback\x18\x02 \x01(\v2\x1b.xray.proxy.reflex.FallbackR\bfallback\"N\n\x0eOutboundConfig\x12\x18\n" +
	"\aaddress\x18\x01 \x01(\tR\aaddress\x12\x12\n\x04port\x18\x02 \x01(\rR\x04port\x12\x0e\n\x02id\x18\x03 \x01(\tR\x02idBU\n" +
	"\x15com.xray.proxy.reflexP\x01Z&github.com/xtls/xray-core/proxy/reflex\xaa\x02\x11Xray.Proxy.Reflexb\x06proto3"

var (
	descriptorSync sync.Once
	descriptorData []byte
)

func getDescriptorGZIP() []byte {
	descriptorSync.Do(func() {
		descriptorData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(rawProtoDescriptor), len(rawProtoDescriptor)))
	})
	return descriptorData
}

var reflexMsgTypes = make([]protoimpl.MessageInfo, 5)
var reflexGoTypes = []any{
	(*User)(nil),
	(*Account)(nil),
	(*Fallback)(nil),
	(*InboundConfig)(nil),
	(*OutboundConfig)(nil),
}
var reflexDepIndexes = []int32{0, 2, 2, 2, 2, 2, 0}

func init() { initializeProto() }

func initializeProto() {
	if File_proxy_reflex_config_proto != nil {
		return
	}
	type marker struct{}
	builder := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(marker{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(rawProtoDescriptor), len(rawProtoDescriptor)),
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           reflexGoTypes,
		DependencyIndexes: reflexDepIndexes,
		MessageInfos:      reflexMsgTypes,
	}
	File_proxy_reflex_config_proto = builder.Build().File
	reflexGoTypes = nil
	reflexDepIndexes = nil
}