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
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/strangelove-ventures/horcrux/signer/multiresolver"
	"github.com/strangelove-ventures/horcrux/signer/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createListener(nodeID string, homedir string) (net.Listener, func(), error) {
	sock, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}

	s := signer.NewRaftStore(nodeID, homedir, "127.0.0.1:"+strconv.Itoa(sock.Addr().(*net.TCPAddr).Port), 500*time.Millisecond, nil, nil, nil)

	transportManager, err := s.Open()
	if err != nil {
		return nil, nil, err
	}

	grpcServer := grpc.NewServer()
	proto.RegisterCosignerGRPCServer(grpcServer, signer.NewGRPCServer(nil, nil, s))
	transportManager.Register(grpcServer)

	go grpcServer.Serve(sock)

	return sock, func() {
		grpcServer.Stop()
	}, nil
}

func TestMultiResolver(t *testing.T) {
	targetIP, targetDNS := "multi:///", "multi:///"

	tmp := t.TempDir()

	for i := 0; i < 3; i++ {
		l, c, err := createListener(strconv.Itoa(i+1), filepath.Join(tmp, fmt.Sprintf("cosigner%d", i+1)))
		require.NoError(t, err)
		defer c()

		if i != 0 {
			targetIP += ","
			targetDNS += ","
		}

		targetIP += "127.0.0.1:"
		targetDNS += "localhost:"

		port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)

		targetIP += port
		targetDNS += port
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

	grpcClient := proto.NewCosignerGRPCClient(connDNS)
	_, err = grpcClient.GetLeader(ctx, &proto.CosignerGRPCGetLeaderRequest{})
	require.NoError(t, err)

	connIP, err := grpc.Dial(targetIP,
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)),
	)
	require.NoError(t, err)
	defer connIP.Close()

	grpcClient = proto.NewCosignerGRPCClient(connIP)
	_, err = grpcClient.GetLeader(ctx, &proto.CosignerGRPCGetLeaderRequest{})
	require.NoError(t, err)
}
