package signer

import (
	"net"
	"net/http"
	"time"

	"github.com/tendermint/tendermint/libs/log"
	tmnet "github.com/tendermint/tendermint/libs/net"
	"github.com/tendermint/tendermint/libs/service"
	server "github.com/tendermint/tendermint/rpc/jsonrpc/server"
	rpc_types "github.com/tendermint/tendermint/rpc/jsonrpc/types"
)

type EmptyRPCResponse struct{}

type CosignerRPCServerConfig struct {
	Logger             log.Logger
	ListenAddress      string
	Cosigner           Cosigner
	Peers              []RemoteCosigner
	Timeout            time.Duration
	RaftStore          *RaftStore
	ThresholdValidator *ThresholdValidator
}

// CosignerRPCServer responds to rpc sign requests using a cosigner instance
type CosignerRPCServer struct {
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

// NewCosignerRPCServer instantiates a local cosigner with the specified key and sign state
func NewCosignerRPCServer(config *CosignerRPCServerConfig) *CosignerRPCServer {
	cosignerRPCServer := &CosignerRPCServer{
		cosigner:           config.Cosigner,
		listenAddress:      config.ListenAddress,
		peers:              config.Peers,
		logger:             config.Logger,
		timeout:            config.Timeout,
		raftStore:          config.RaftStore,
		thresholdValidator: config.ThresholdValidator,
	}

	cosignerRPCServer.BaseService = *service.NewBaseService(config.Logger, "CosignerRPCServer", cosignerRPCServer)
	return cosignerRPCServer
}

// OnStart starts the rpm server to respond to remote CosignerSignRequests
func (rpcServer *CosignerRPCServer) OnStart() error {
	proto, address := tmnet.ProtocolAndAddress(rpcServer.listenAddress)

	lis, err := net.Listen(proto, address)
	if err != nil {
		return err
	}
	rpcServer.listener = lis

	routes := map[string]*server.RPCFunc{
		"SignBlock":                      server.NewRPCFunc(rpcServer.rpcRaftSignBlockRequest, "arg"),
		"SetEphemeralSecretPart":         server.NewRPCFunc(rpcServer.rpcRaftSetEphemeralSecretPartRequest, "arg"),
		"EmitEphemeralSecretPartReceipt": server.NewRPCFunc(rpcServer.rpcRaftEmitEphemeralSecretPartReceiptRequest, "arg"),
		"Sign":                           server.NewRPCFunc(rpcServer.rpcSignRequest, "arg"),
	}

	mux := http.NewServeMux()
	server.RegisterRPCFuncs(mux, routes, log.NewFilter(rpcServer.Logger, log.AllowError()))

	tcpLogger := rpcServer.Logger.With("socket", "tcp")
	tcpLogger = log.NewFilter(tcpLogger, log.AllowError())
	config := server.DefaultConfig()

	go func() {
		defer lis.Close()
		err := server.Serve(lis, mux, tcpLogger, config)
		if err != nil {
			rpcServer.logger.Error("Error starting RPC server", err.Error())
		}
	}()

	return nil
}

func (rpcServer *CosignerRPCServer) Addr() net.Addr {
	if rpcServer.listener == nil {
		return nil
	}
	return rpcServer.listener.Addr()
}

func (rpcServer *CosignerRPCServer) rpcRaftSignBlockRequest(
	ctx *rpc_types.Context, req CosignerSignBlockRequest) (*CosignerSignBlockResponse, error) {
	res, _, err := rpcServer.thresholdValidator.SignBlock(req.ChainID, req.Block)
	if err != nil {
		return nil, err
	}
	return &CosignerSignBlockResponse{
		Signature: res,
	}, nil
}

func (rpcServer *CosignerRPCServer) rpcRaftEmitEphemeralSecretPartReceiptRequest(
	ctx *rpc_types.Context, req CosignerEmitEphemeralSecretReceiptRequest) (*EmptyRPCResponse, error) {
	err := rpcServer.raftStore.EmitEphemeralSecretPartReceipt(req)
	if err != nil {
		return nil, err
	}
	return &EmptyRPCResponse{}, nil
}

func (rpcServer *CosignerRPCServer) rpcSignRequest(
	ctx *rpc_types.Context, req CosignerSignRequest) (*CosignerSignResponse, error) {
	response := &CosignerSignResponse{}

	resp, err := rpcServer.cosigner.Sign(req)
	if err != nil {
		return response, err
	}

	response.Timestamp = resp.Timestamp
	response.Signature = resp.Signature
	return response, nil
}

func (rpcServer *CosignerRPCServer) rpcRaftSetEphemeralSecretPartRequest(
	ctx *rpc_types.Context, req CosignerEphemeralSecretPart) (*EmptyRPCResponse, error) {
	err := rpcServer.cosigner.SetEphemeralSecretPart(req)
	if err != nil {
		return nil, err
	}
	go func() {
		err := rpcServer.raftStore.EmitEphemeralSecretPartReceipt(CosignerEmitEphemeralSecretReceiptRequest{
			DestinationID: rpcServer.cosigner.GetID(),
			SourceID:      req.SourceID,
			HRS: HRSKey{
				Height: req.Height,
				Round:  req.Round,
				Step:   req.Step,
			},
		})
		if err != nil {
			rpcServer.logger.Error("EmitEphemeralSecretPartReceipt Error", err.Error())
		}
	}()
	return &EmptyRPCResponse{}, nil
}
