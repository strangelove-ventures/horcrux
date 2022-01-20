package signer

import (
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/raft"
	"github.com/tendermint/tendermint/libs/log"
	tmnet "github.com/tendermint/tendermint/libs/net"
	"github.com/tendermint/tendermint/libs/service"
	server "github.com/tendermint/tendermint/rpc/jsonrpc/server"
	rpc_types "github.com/tendermint/tendermint/rpc/jsonrpc/types"
)

type RpcRaftEmitEphemeralSecretRequest struct {
	SourceID            int
	DestinationID       int
	EphemeralSecretPart CosignerGetEphemeralSecretPartResponse
}

type RpcRaftEmitEphemeralSecretReceiptRequest struct {
	HRS           HRSKey
	SourceID      int
	DestinationID int
}

type RpcRaftEmitSignatureRequest struct {
	HRS          HRSKey
	SourceID     int
	SignResponse CosignerSignResponse
}

type RpcJoinRaftRequest struct {
	NodeID  string
	Address string
}

type RpcRaftRequest struct {
	Key   string
	Value string
}

type CosignerRpcServerConfig struct {
	Logger             log.Logger
	ListenAddress      string
	Cosigner           Cosigner
	Peers              []RemoteCosigner
	Timeout            time.Duration
	RaftStore          *RaftStore
	ThresholdValidator *ThresholdValidator
}

type RpcJoinRaftResponse struct{}

type RpcRaftResponse struct {
	Key   string
	Value string
}

type RpcRaftSignBlockRequest struct {
	ChainID string
	Block   *block
}

type RpcRaftSignBlockResponse struct {
	Signature []byte
}

// CosignerRpcServer responds to rpc sign requests using a cosigner instance
type CosignerRpcServer struct {
	service.BaseService

	logger             log.Logger
	listenAddress      string
	listener           net.Listener
	cosigner           Cosigner
	peers              []RemoteCosigner
	timeout            time.Duration
	raftStore          *RaftStore
	thresholdValidator *ThresholdValidator
}

// NewCosignerRpcServer instantiates a local cosigner with the specified key and sign state
func NewCosignerRpcServer(config *CosignerRpcServerConfig) *CosignerRpcServer {
	cosignerRpcServer := &CosignerRpcServer{
		cosigner:           config.Cosigner,
		listenAddress:      config.ListenAddress,
		peers:              config.Peers,
		logger:             config.Logger,
		timeout:            config.Timeout,
		raftStore:          config.RaftStore,
		thresholdValidator: config.ThresholdValidator,
	}

	cosignerRpcServer.BaseService = *service.NewBaseService(config.Logger, "CosignerRpcServer", cosignerRpcServer)
	return cosignerRpcServer
}

// OnStart starts the rpm server to respond to remote CosignerSignRequests
func (rpcServer *CosignerRpcServer) OnStart() error {
	proto, address := tmnet.ProtocolAndAddress(rpcServer.listenAddress)

	lis, err := net.Listen(proto, address)
	if err != nil {
		return err
	}
	rpcServer.listener = lis

	routes := map[string]*server.RPCFunc{
		"EmitEphemeralSecretPart":        server.NewRPCFunc(rpcServer.rpcRaftEmitEphemeralSecretPartRequest, "arg"),
		"EmitEphemeralSecretPartReceipt": server.NewRPCFunc(rpcServer.rpcRaftEmitEphemeralSecretPartReceiptRequest, "arg"),
		"EmitSignature":                  server.NewRPCFunc(rpcServer.rpcRaftEmitSignatureRequest, "arg"),
		"GetRaftLeader":                  server.NewRPCFunc(rpcServer.rpcRaftGetLeaderRequest, "arg"),
		"SignBlock":                      server.NewRPCFunc(rpcServer.rpcRaftSignBlockRequest, "arg"),
	}

	mux := http.NewServeMux()
	server.RegisterRPCFuncs(mux, routes, log.NewFilter(rpcServer.Logger, log.AllowError()))

	tcpLogger := rpcServer.Logger.With("socket", "tcp")
	tcpLogger = log.NewFilter(tcpLogger, log.AllowError())
	config := server.DefaultConfig()

	go func() {
		defer lis.Close()
		server.Serve(lis, mux, tcpLogger, config)
	}()

	return nil
}

func (rpcServer *CosignerRpcServer) Addr() net.Addr {
	if rpcServer.listener == nil {
		return nil
	}
	return rpcServer.listener.Addr()
}

func (rpcServer *CosignerRpcServer) rpcRaftGetLeaderRequest(ctx *rpc_types.Context, req RpcRaftRequest) (raft.ServerAddress, error) {
	return rpcServer.raftStore.GetLeader(), nil
}

func (rpcServer *CosignerRpcServer) rpcRaftSignBlockRequest(ctx *rpc_types.Context, req RpcRaftSignBlockRequest) (*RpcRaftSignBlockResponse, error) {
	res, _, err := rpcServer.thresholdValidator.SignBlock(req.ChainID, req.Block)
	if err != nil {
		return nil, err
	}
	return &RpcRaftSignBlockResponse{
		Signature: res,
	}, nil
}

func (rpcServer *CosignerRpcServer) rpcRaftEmitEphemeralSecretPartRequest(ctx *rpc_types.Context, req RpcRaftEmitEphemeralSecretRequest) (*RpcRaftResponse, error) {
	return rpcServer.raftStore.LeaderEmitEphemeralSecretPart(req)
}

func (rpcServer *CosignerRpcServer) rpcRaftEmitEphemeralSecretPartReceiptRequest(ctx *rpc_types.Context, req RpcRaftEmitEphemeralSecretReceiptRequest) (*RpcRaftResponse, error) {
	return rpcServer.raftStore.LeaderEmitEphemeralSecretPartReceipt(req)
}

func (rpcServer *CosignerRpcServer) rpcRaftEmitSignatureRequest(ctx *rpc_types.Context, req RpcRaftEmitSignatureRequest) (*RpcRaftResponse, error) {
	return rpcServer.raftStore.LeaderEmitSignature(req)
}
