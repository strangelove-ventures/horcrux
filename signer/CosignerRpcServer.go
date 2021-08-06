package signer

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/tendermint/tendermint/libs/log"
	tmnet "github.com/tendermint/tendermint/libs/net"
	"github.com/tendermint/tendermint/libs/service"
	server "github.com/tendermint/tendermint/rpc/jsonrpc/server"
	rpc_types "github.com/tendermint/tendermint/rpc/jsonrpc/types"
)

type RpcSignRequest struct {
	SignBytes []byte
}

type RpcSignResponse struct {
	Timestamp time.Time
	Signature []byte
}

type RpcGetEphemeralSecretPartRequest struct {
	ID     int
	Height int64
	Round  int64
	Step   int8
}

type RpcGetEphemeralSecretPartResponse struct {
	SourceID                       int
	SourceEphemeralSecretPublicKey []byte
	EncryptedSharePart             []byte
	SourceSig                      []byte
}

type CosignerRpcServerConfig struct {
	Logger        log.Logger
	ListenAddress string
	Cosigner      Cosigner
	Peers         []RemoteCosigner
}

// CosignerRpcServer responds to rpc sign requests using a cosigner instance
type CosignerRpcServer struct {
	service.BaseService

	logger        log.Logger
	listenAddress string
	listener      net.Listener
	cosigner      Cosigner
	peers         []RemoteCosigner
}

// NewCosignerRpcServer instantiates a local cosigner with the specified key and sign state
func NewCosignerRpcServer(config *CosignerRpcServerConfig) *CosignerRpcServer {
	cosignerRpcServer := &CosignerRpcServer{
		cosigner:      config.Cosigner,
		listenAddress: config.ListenAddress,
		peers:         config.Peers,
		logger:        config.Logger,
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
		"Sign":                   server.NewRPCFunc(rpcServer.rpcSignRequest, "arg"),
		"GetEphemeralSecretPart": server.NewRPCFunc(rpcServer.rpcGetEphemeralSecretPart, "arg"),
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

func (rpcServer *CosignerRpcServer) rpcSignRequest(ctx *rpc_types.Context, req RpcSignRequest) (*RpcSignResponse, error) {
	response := &RpcSignResponse{}

	height, round, step, err := UnpackHRS(req.SignBytes)
	if err != nil {
		return response, err
	}

	wg := sync.WaitGroup{}
	wg.Add(len(rpcServer.peers))

	// ping peers for our ephemeral share part
	for _, peer := range rpcServer.peers {
		request := func(peer RemoteCosigner) {

			// need to do these requests in parallel..!!

			// RPC requests are blocking
			// to prevent it from hanging our process indefinitely, we use a timeout context and a goroutine
			partReqCtx, partReqCtxCancel := context.WithTimeout(context.Background(), time.Second)

			go func() {
				partRequest := CosignerGetEphemeralSecretPartRequest{
					ID:     rpcServer.cosigner.GetID(),
					Height: height,
					Round:  round,
					Step:   step,
				}

				// if we already have an ephemeral secret part for this HRS, we don't need to re-query for it
				hasResp, err := rpcServer.cosigner.HasEphemeralSecretPart(CosignerHasEphemeralSecretPartRequest{
					ID:     peer.GetID(),
					Height: height,
					Round:  round,
					Step:   step,
				})

				if err != nil {
					rpcServer.logger.Error("HasEphemeralSecretPart req error", "error", err)
					return
				}

				if hasResp.Exists {
					partReqCtxCancel()
					return
				}

				partResponse, err := peer.GetEphemeralSecretPart(partRequest)
				if err != nil {
					rpcServer.logger.Error("GetEphemeralSecretPart req error", "error", err)
					return
				}

				// no need to contine if timed out
				select {
				case <-partReqCtx.Done():
					return
				default:
				}

				defer partReqCtxCancel()

				// set the share part from the response
				err = rpcServer.cosigner.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
					SourceID:                       partResponse.SourceID,
					SourceEphemeralSecretPublicKey: partResponse.SourceEphemeralSecretPublicKey,
					EncryptedSharePart:             partResponse.EncryptedSharePart,
					Height:                         height,
					Round:                          round,
					Step:                           step,
					SourceSig:                      partResponse.SourceSig,
				})
				if err != nil {
					rpcServer.logger.Error("SetEphemeralSecretPart req error", "error", err)
				}
			}()

			// wait for timeout or done
			select {
			case <-partReqCtx.Done():
			}

			wg.Done()
		}

		go request(peer)
	}

	wg.Wait()

	// after getting any share parts we could, we sign
	resp, err := rpcServer.cosigner.Sign(CosignerSignRequest{
		SignBytes: req.SignBytes,
	})
	if err != nil {
		return response, err
	}

	response.Timestamp = resp.Timestamp
	response.Signature = resp.Signature
	return response, nil
}

func (rpcServer *CosignerRpcServer) rpcGetEphemeralSecretPart(ctx *rpc_types.Context, req RpcGetEphemeralSecretPartRequest) (*RpcGetEphemeralSecretPartResponse, error) {
	response := &RpcGetEphemeralSecretPartResponse{}

	partResp, err := rpcServer.cosigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
		ID:     req.ID,
		Height: req.Height,
		Round:  req.Round,
		Step:   req.Step,
	})
	if err != nil {
		return response, nil
	}

	response.SourceID = partResp.SourceID
	response.SourceEphemeralSecretPublicKey = partResp.SourceEphemeralSecretPublicKey
	response.EncryptedSharePart = partResp.EncryptedSharePart
	response.SourceSig = partResp.SourceSig

	return response, nil
}
