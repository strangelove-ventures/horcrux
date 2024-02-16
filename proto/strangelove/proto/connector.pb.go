// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v3.13.0
// source: strangelove/proto/connector.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PubKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChainId string `protobuf:"bytes,1,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
}

func (x *PubKeyRequest) Reset() {
	*x = PubKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_strangelove_proto_connector_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PubKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PubKeyRequest) ProtoMessage() {}

func (x *PubKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_strangelove_proto_connector_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PubKeyRequest.ProtoReflect.Descriptor instead.
func (*PubKeyRequest) Descriptor() ([]byte, []int) {
	return file_strangelove_proto_connector_proto_rawDescGZIP(), []int{0}
}

func (x *PubKeyRequest) GetChainId() string {
	if x != nil {
		return x.ChainId
	}
	return ""
}

type PubKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PubKey []byte `protobuf:"bytes,1,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
}

func (x *PubKeyResponse) Reset() {
	*x = PubKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_strangelove_proto_connector_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PubKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PubKeyResponse) ProtoMessage() {}

func (x *PubKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_strangelove_proto_connector_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PubKeyResponse.ProtoReflect.Descriptor instead.
func (*PubKeyResponse) Descriptor() ([]byte, []int) {
	return file_strangelove_proto_connector_proto_rawDescGZIP(), []int{1}
}

func (x *PubKeyResponse) GetPubKey() []byte {
	if x != nil {
		return x.PubKey
	}
	return nil
}

var File_strangelove_proto_connector_proto protoreflect.FileDescriptor

var file_strangelove_proto_connector_proto_rawDesc = []byte{
	0x0a, 0x21, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c, 0x6f, 0x76, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x11, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c, 0x6f, 0x76, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c,
	0x6f, 0x76, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x2a, 0x0a, 0x0d, 0x50, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64,
	0x22, 0x29, 0x0a, 0x0e, 0x50, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x70, 0x75, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x32, 0xb1, 0x01, 0x0a, 0x09,
	0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x4f, 0x0a, 0x06, 0x50, 0x75, 0x62,
	0x4b, 0x65, 0x79, 0x12, 0x20, 0x2e, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c, 0x6f, 0x76,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c,
	0x6f, 0x76, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x75, 0x62, 0x4b, 0x65, 0x79,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x53, 0x0a, 0x04, 0x53, 0x69,
	0x67, 0x6e, 0x12, 0x23, 0x2e, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c, 0x6f, 0x76, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67,
	0x65, 0x6c, 0x6f, 0x76, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x69, 0x67, 0x6e,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x41, 0x5a, 0x3f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x74,
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c, 0x6f, 0x76, 0x65, 0x2d, 0x76, 0x65, 0x6e, 0x74, 0x75, 0x72,
	0x65, 0x73, 0x2f, 0x68, 0x6f, 0x72, 0x63, 0x72, 0x75, 0x78, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6c, 0x6f, 0x76, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_strangelove_proto_connector_proto_rawDescOnce sync.Once
	file_strangelove_proto_connector_proto_rawDescData = file_strangelove_proto_connector_proto_rawDesc
)

func file_strangelove_proto_connector_proto_rawDescGZIP() []byte {
	file_strangelove_proto_connector_proto_rawDescOnce.Do(func() {
		file_strangelove_proto_connector_proto_rawDescData = protoimpl.X.CompressGZIP(file_strangelove_proto_connector_proto_rawDescData)
	})
	return file_strangelove_proto_connector_proto_rawDescData
}

var file_strangelove_proto_connector_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_strangelove_proto_connector_proto_goTypes = []interface{}{
	(*PubKeyRequest)(nil),     // 0: strangelove.proto.PubKeyRequest
	(*PubKeyResponse)(nil),    // 1: strangelove.proto.PubKeyResponse
	(*SignBlockRequest)(nil),  // 2: strangelove.proto.SignBlockRequest
	(*SignBlockResponse)(nil), // 3: strangelove.proto.SignBlockResponse
}
var file_strangelove_proto_connector_proto_depIdxs = []int32{
	0, // 0: strangelove.proto.Connector.PubKey:input_type -> strangelove.proto.PubKeyRequest
	2, // 1: strangelove.proto.Connector.Sign:input_type -> strangelove.proto.SignBlockRequest
	1, // 2: strangelove.proto.Connector.PubKey:output_type -> strangelove.proto.PubKeyResponse
	3, // 3: strangelove.proto.Connector.Sign:output_type -> strangelove.proto.SignBlockResponse
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_strangelove_proto_connector_proto_init() }
func file_strangelove_proto_connector_proto_init() {
	if File_strangelove_proto_connector_proto != nil {
		return
	}
	file_strangelove_proto_node_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_strangelove_proto_connector_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PubKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_strangelove_proto_connector_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PubKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_strangelove_proto_connector_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_strangelove_proto_connector_proto_goTypes,
		DependencyIndexes: file_strangelove_proto_connector_proto_depIdxs,
		MessageInfos:      file_strangelove_proto_connector_proto_msgTypes,
	}.Build()
	File_strangelove_proto_connector_proto = out.File
	file_strangelove_proto_connector_proto_rawDesc = nil
	file_strangelove_proto_connector_proto_goTypes = nil
	file_strangelove_proto_connector_proto_depIdxs = nil
}
