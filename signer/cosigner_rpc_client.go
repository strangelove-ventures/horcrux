package signer

import (
	"context"
	"time"

	client "github.com/tendermint/tendermint/rpc/jsonrpc/client"
)

const (
	rpcTimeout = 4 * time.Second
)

func getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

func CallRPC(address string, method string, req interface{}, res interface{}) error {
	remoteClient, err := client.New(address)
	if err != nil {
		return err
	}
	params := map[string]interface{}{
		"arg": req,
	}
	ctx, ctxCancel := getContext()
	defer ctxCancel()
	_, err = remoteClient.Call(ctx, method, params, res)
	if err != nil {
		return err
	}
	return nil
}
