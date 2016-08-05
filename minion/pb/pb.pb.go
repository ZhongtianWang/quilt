// Code generated by protoc-gen-go.
// source: pb/pb.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	pb/pb.proto

It has these top-level messages:
	MinionConfig
	Reply
	Request
	EtcdMembers
*/
package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type MinionConfig_Role int32

const (
	MinionConfig_NONE   MinionConfig_Role = 0
	MinionConfig_WORKER MinionConfig_Role = 1
	MinionConfig_MASTER MinionConfig_Role = 2
)

var MinionConfig_Role_name = map[int32]string{
	0: "NONE",
	1: "WORKER",
	2: "MASTER",
}
var MinionConfig_Role_value = map[string]int32{
	"NONE":   0,
	"WORKER": 1,
	"MASTER": 2,
}

func (x MinionConfig_Role) String() string {
	return proto.EnumName(MinionConfig_Role_name, int32(x))
}
func (MinionConfig_Role) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 0} }

type MinionConfig struct {
	ID        string            `protobuf:"bytes,1,opt,name=ID,json=iD" json:"ID,omitempty"`
	Role      MinionConfig_Role `protobuf:"varint,2,opt,name=role,enum=MinionConfig_Role" json:"role,omitempty"`
	PrivateIP string            `protobuf:"bytes,3,opt,name=PrivateIP,json=privateIP" json:"PrivateIP,omitempty"`
	Spec      string            `protobuf:"bytes,4,opt,name=Spec,json=spec" json:"Spec,omitempty"`
	Provider  string            `protobuf:"bytes,5,opt,name=Provider,json=provider" json:"Provider,omitempty"`
	Size      string            `protobuf:"bytes,6,opt,name=Size,json=size" json:"Size,omitempty"`
	Region    string            `protobuf:"bytes,7,opt,name=Region,json=region" json:"Region,omitempty"`
}

func (m *MinionConfig) Reset()                    { *m = MinionConfig{} }
func (m *MinionConfig) String() string            { return proto.CompactTextString(m) }
func (*MinionConfig) ProtoMessage()               {}
func (*MinionConfig) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type Reply struct {
	Success bool   `protobuf:"varint,1,opt,name=Success,json=success" json:"Success,omitempty"`
	Error   string `protobuf:"bytes,2,opt,name=Error,json=error" json:"Error,omitempty"`
}

func (m *Reply) Reset()                    { *m = Reply{} }
func (m *Reply) String() string            { return proto.CompactTextString(m) }
func (*Reply) ProtoMessage()               {}
func (*Reply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type Request struct {
}

func (m *Request) Reset()                    { *m = Request{} }
func (m *Request) String() string            { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()               {}
func (*Request) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

type EtcdMembers struct {
	IPs []string `protobuf:"bytes,1,rep,name=IPs,json=iPs" json:"IPs,omitempty"`
}

func (m *EtcdMembers) Reset()                    { *m = EtcdMembers{} }
func (m *EtcdMembers) String() string            { return proto.CompactTextString(m) }
func (*EtcdMembers) ProtoMessage()               {}
func (*EtcdMembers) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func init() {
	proto.RegisterType((*MinionConfig)(nil), "MinionConfig")
	proto.RegisterType((*Reply)(nil), "Reply")
	proto.RegisterType((*Request)(nil), "Request")
	proto.RegisterType((*EtcdMembers)(nil), "EtcdMembers")
	proto.RegisterEnum("MinionConfig_Role", MinionConfig_Role_name, MinionConfig_Role_value)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion3

// Client API for Minion service

type MinionClient interface {
	SetMinionConfig(ctx context.Context, in *MinionConfig, opts ...grpc.CallOption) (*Reply, error)
	GetMinionConfig(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MinionConfig, error)
	BootEtcd(ctx context.Context, in *EtcdMembers, opts ...grpc.CallOption) (*Reply, error)
}

type minionClient struct {
	cc *grpc.ClientConn
}

func NewMinionClient(cc *grpc.ClientConn) MinionClient {
	return &minionClient{cc}
}

func (c *minionClient) SetMinionConfig(ctx context.Context, in *MinionConfig, opts ...grpc.CallOption) (*Reply, error) {
	out := new(Reply)
	err := grpc.Invoke(ctx, "/Minion/SetMinionConfig", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *minionClient) GetMinionConfig(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MinionConfig, error) {
	out := new(MinionConfig)
	err := grpc.Invoke(ctx, "/Minion/GetMinionConfig", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *minionClient) BootEtcd(ctx context.Context, in *EtcdMembers, opts ...grpc.CallOption) (*Reply, error) {
	out := new(Reply)
	err := grpc.Invoke(ctx, "/Minion/BootEtcd", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Minion service

type MinionServer interface {
	SetMinionConfig(context.Context, *MinionConfig) (*Reply, error)
	GetMinionConfig(context.Context, *Request) (*MinionConfig, error)
	BootEtcd(context.Context, *EtcdMembers) (*Reply, error)
}

func RegisterMinionServer(s *grpc.Server, srv MinionServer) {
	s.RegisterService(&_Minion_serviceDesc, srv)
}

func _Minion_SetMinionConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MinionConfig)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MinionServer).SetMinionConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Minion/SetMinionConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MinionServer).SetMinionConfig(ctx, req.(*MinionConfig))
	}
	return interceptor(ctx, in, info, handler)
}

func _Minion_GetMinionConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MinionServer).GetMinionConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Minion/GetMinionConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MinionServer).GetMinionConfig(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _Minion_BootEtcd_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EtcdMembers)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MinionServer).BootEtcd(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Minion/BootEtcd",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MinionServer).BootEtcd(ctx, req.(*EtcdMembers))
	}
	return interceptor(ctx, in, info, handler)
}

var _Minion_serviceDesc = grpc.ServiceDesc{
	ServiceName: "Minion",
	HandlerType: (*MinionServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SetMinionConfig",
			Handler:    _Minion_SetMinionConfig_Handler,
		},
		{
			MethodName: "GetMinionConfig",
			Handler:    _Minion_GetMinionConfig_Handler,
		},
		{
			MethodName: "BootEtcd",
			Handler:    _Minion_BootEtcd_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: fileDescriptor0,
}

func init() { proto.RegisterFile("pb/pb.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 344 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x5c, 0x51, 0x5d, 0x4b, 0xeb, 0x40,
	0x10, 0x6d, 0xbe, 0x93, 0x69, 0x6f, 0x5b, 0x86, 0xcb, 0x65, 0x29, 0x17, 0x94, 0x3c, 0x48, 0x11,
	0x89, 0x50, 0x1f, 0x7c, 0x56, 0x1b, 0xa4, 0x48, 0xdb, 0xb0, 0x11, 0x7c, 0x36, 0xe9, 0x5a, 0x16,
	0x6a, 0x37, 0xee, 0xa6, 0x05, 0xfd, 0x01, 0xfe, 0x58, 0x7f, 0x85, 0x9b, 0xb5, 0x62, 0xeb, 0xdb,
	0x39, 0x67, 0xce, 0xce, 0x9c, 0x99, 0x85, 0x76, 0x55, 0x9c, 0x57, 0x45, 0x52, 0x49, 0x51, 0x8b,
	0xf8, 0xc3, 0x82, 0xce, 0x94, 0xaf, 0xb9, 0x58, 0xdf, 0x88, 0xf5, 0x13, 0x5f, 0x62, 0x17, 0xec,
	0xc9, 0x98, 0x58, 0xc7, 0xd6, 0x30, 0xa2, 0x36, 0x1f, 0xe3, 0x09, 0xb8, 0x52, 0xac, 0x18, 0xb1,
	0xb5, 0xd2, 0x1d, 0x61, 0xb2, 0x6f, 0x4e, 0xa8, 0xae, 0x50, 0x53, 0xc7, 0xff, 0x10, 0x65, 0x92,
	0x6f, 0x1f, 0x6b, 0x36, 0xc9, 0x88, 0x63, 0x9e, 0x47, 0xd5, 0xb7, 0x80, 0x08, 0x6e, 0x5e, 0xb1,
	0x92, 0xb8, 0xa6, 0xe0, 0x2a, 0x8d, 0x71, 0x00, 0x61, 0x26, 0xc5, 0x96, 0x2f, 0x98, 0x24, 0x9e,
	0xd1, 0xc3, 0x6a, 0xc7, 0x8d, 0x9f, 0xbf, 0x31, 0xe2, 0xef, 0xfc, 0x1a, 0xe3, 0x3f, 0xf0, 0x29,
	0x5b, 0xea, 0xe1, 0x24, 0x30, 0xaa, 0x2f, 0x0d, 0x8b, 0x87, 0xe0, 0x36, 0x39, 0x30, 0x04, 0x77,
	0x36, 0x9f, 0xa5, 0xfd, 0x16, 0x02, 0xf8, 0x0f, 0x73, 0x7a, 0x97, 0xd2, 0xbe, 0xd5, 0xe0, 0xe9,
	0x55, 0x7e, 0xaf, 0xb1, 0x1d, 0x5f, 0x82, 0x47, 0x59, 0xb5, 0x7a, 0x45, 0x02, 0x41, 0xbe, 0x29,
	0x4b, 0xa6, 0x94, 0xd9, 0x34, 0xa4, 0x81, 0xfa, 0xa2, 0xf8, 0x17, 0xbc, 0x54, 0x4a, 0x21, 0xcd,
	0xbe, 0x11, 0xf5, 0x58, 0x43, 0xe2, 0x08, 0x02, 0xca, 0x5e, 0x36, 0x4c, 0xd5, 0xf1, 0x11, 0xb4,
	0xd3, 0xba, 0x5c, 0x4c, 0xd9, 0x73, 0xc1, 0xa4, 0xc2, 0x3e, 0x38, 0x93, 0xac, 0xe9, 0xe2, 0x68,
	0xb7, 0xc3, 0x33, 0x35, 0x7a, 0xb7, 0xf4, 0x44, 0x73, 0x24, 0x3c, 0x85, 0x5e, 0xce, 0xea, 0x83,
	0xf3, 0xfe, 0x39, 0x38, 0xe0, 0xc0, 0x4f, 0x4c, 0xa0, 0xb8, 0x85, 0x67, 0xd0, 0xbb, 0xfd, 0xe5,
	0x0d, 0x93, 0xdd, 0xd0, 0xc1, 0xe1, 0x2b, 0xed, 0x8e, 0x21, 0xbc, 0x16, 0xa2, 0x6e, 0x92, 0x60,
	0x27, 0xd9, 0x0b, 0xf4, 0xd3, 0xb1, 0xf0, 0xcd, 0x0f, 0x5f, 0x7c, 0x06, 0x00, 0x00, 0xff, 0xff,
	0x89, 0x60, 0x91, 0x75, 0xf0, 0x01, 0x00, 0x00,
}
