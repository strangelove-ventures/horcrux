package signer

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/libs/log"
	server "github.com/tendermint/tendermint/rpc/jsonrpc/server"
	rpc_types "github.com/tendermint/tendermint/rpc/jsonrpc/types"
)

func rpcSignRequest(ctx *rpc_types.Context, req RpcSignRequest) (*RpcSignResponse, error) {
	return &RpcSignResponse{Signature: []byte("hello world")}, nil
}

func rpcGetEphemeralSecretPart(ctx *rpc_types.Context, req RpcGetEphemeralSecretPartRequest) (*RpcGetEphemeralSecretPartResponse, error) {
	response := &RpcGetEphemeralSecretPartResponse{
		SourceID:                       1,
		SourceEphemeralSecretPublicKey: []byte("foo"),
		EncryptedSharePart:             []byte("bar"),
	}
	return response, nil
}

func TestRemoteCosignerSign(test *testing.T) {
	lis, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(test, err)
	defer lis.Close()

	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	serv := func() {
		routes := map[string]*server.RPCFunc{
			"Sign":                   server.NewRPCFunc(rpcSignRequest, "arg"),
			"GetEphemeralSecretPart": server.NewRPCFunc(rpcGetEphemeralSecretPart, "arg"),
		}

		mux := http.NewServeMux()
		server.RegisterRPCFuncs(mux, routes, logger)

		tcpLogger := logger.With("socket", "tcp")
		config := server.DefaultConfig()
		server.Serve(lis, mux, tcpLogger, config)
	}
	go serv()

	port := lis.Addr().(*net.TCPAddr).Port
	cosigner := NewRemoteCosigner(2, fmt.Sprintf("tcp://0.0.0.0:%d", port))

	resp, err := cosigner.Sign(CosignerSignRequest{})
	require.NoError(test, err)
	require.Equal(test, resp.Signature, []byte("hello world"))
}

func TestRemoteCosignerGetEphemeralSecretPart(test *testing.T) {
	lis, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(test, err)
	defer lis.Close()

	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	serv := func() {
		routes := map[string]*server.RPCFunc{
			"Sign":                   server.NewRPCFunc(rpcSignRequest, "arg"),
			"GetEphemeralSecretPart": server.NewRPCFunc(rpcGetEphemeralSecretPart, "arg"),
		}

		mux := http.NewServeMux()
		server.RegisterRPCFuncs(mux, routes, logger)

		tcpLogger := logger.With("socket", "tcp")
		config := server.DefaultConfig()
		server.Serve(lis, mux, tcpLogger, config)
	}
	go serv()

	port := lis.Addr().(*net.TCPAddr).Port
	cosigner := NewRemoteCosigner(2, fmt.Sprintf("tcp://0.0.0.0:%d", port))

	resp, err := cosigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{})
	require.NoError(test, err)
	require.Equal(test, resp, CosignerGetEphemeralSecretPartResponse{
		SourceID:                       1,
		SourceEphemeralSecretPublicKey: []byte("foo"),
		EncryptedSharePart:             []byte("bar"),
	})
}
