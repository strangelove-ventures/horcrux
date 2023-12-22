package multiresolver_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	grpccosigner "github.com/strangelove-ventures/horcrux/v3/grpc/cosigner"
	"github.com/strangelove-ventures/horcrux/v3/signer"
	"github.com/strangelove-ventures/horcrux/v3/signer/multiresolver"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createListener(nodeID string, homedir string) (string, func(), error) {
	sock, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	port := strconv.Itoa(sock.Addr().(*net.TCPAddr).Port)

	s := signer.NewRaftStore(
		nodeID,
		homedir,
		"127.0.0.1:"+port,
		500*time.Millisecond,
		nil, nil, nil)

	transportManager, err := s.Open()
	if err != nil {
		return "", nil, err
	}

	grpcServer := grpc.NewServer()
	grpccosigner.RegisterCosignerServer(grpcServer, signer.NewCosignerGRPCServer(nil, nil, s))
	transportManager.Register(grpcServer)

	go func() {
		_ = grpcServer.Serve(sock)
	}()

	return port, func() {
		grpcServer.Stop()
	}, nil
}

func TestMultiResolver(t *testing.T) {
	targetIP, targetDNS := "multi:///", "multi:///"

	tmp := t.TempDir()

	for i := 0; i < 3; i++ {
		port, c, err := createListener(strconv.Itoa(i+1), filepath.Join(tmp, fmt.Sprintf("cosigner%d", i+1)))
		require.NoError(t, err)
		defer c()

		if i != 0 {
			targetIP += ","
			targetDNS += ","
		}

		targetIP += "127.0.0.1:" + port
		targetDNS += "localhost:" + port
	}

	multiresolver.Register()

	serviceConfig := `{"loadBalancingConfig": [ { "round_robin": {} } ]}`
	retryOpts := []grpcretry.CallOption{
		grpcretry.WithBackoff(grpcretry.BackoffExponential(100 * time.Millisecond)),
		grpcretry.WithMax(5),
	}

	connDNS, err := grpc.Dial(targetDNS,
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)),
	)
	require.NoError(t, err)
	defer connDNS.Close()

	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	grpcClient := grpccosigner.NewCosignerClient(connDNS)
	_, err = grpcClient.GetLeader(ctx, &grpccosigner.GetLeaderRequest{})
	require.NoError(t, err)

	connIP, err := grpc.Dial(targetIP,
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)),
	)
	require.NoError(t, err)
	defer connIP.Close()

	grpcClient = grpccosigner.NewCosignerClient(connIP)
	_, err = grpcClient.GetLeader(ctx, &grpccosigner.GetLeaderRequest{})
	require.NoError(t, err)
}
