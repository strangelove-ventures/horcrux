package multiresolver_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/node"

	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/strangelove-ventures/horcrux/pkg/multiresolver"
	"github.com/strangelove-ventures/horcrux/pkg/proto"
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

	s := node.NewRaftStore(
		nodeID,
		homedir,
		"127.0.0.1:"+port,
		500*time.Millisecond,
		nil)

	// Need to set pointers to avoid nil pointers.
	var cosigners []node.ICosigner
	var timeDuration time.Duration
	thresholdvalidator := node.NewThresholdValidator(nil, nil, 0, timeDuration, 0, nil, cosigners, nil)
	s.SetThresholdValidator(thresholdvalidator)

	transportManager, err := s.Open()
	if err != nil {
		return "", nil, err
	}

	grpcServer := grpc.NewServer()
	proto.RegisterICosignerGRPCServer(grpcServer, node.NewGRPCServer(nil, nil, s))
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

	grpcClient := proto.NewICosignerGRPCClient(connDNS)
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

	grpcClient = proto.NewICosignerGRPCClient(connIP)
	_, err = grpcClient.GetLeader(ctx, &proto.CosignerGRPCGetLeaderRequest{})
	require.NoError(t, err)
}
