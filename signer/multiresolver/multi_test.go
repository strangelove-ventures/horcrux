package multiresolver_test

import (
	"net"
	"strconv"
	"testing"

	"github.com/strangelove-ventures/horcrux/signer/multiresolver"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createListener() (net.Listener, func(), error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, nil, err
	}
	return l, func() {
		_ = l.Close()
	}, nil
}

func TestMultiResolver(t *testing.T) {
	targetIP, targetDNS := "multi:///", "multi:///"

	for i := 0; i < 3; i++ {
		l, close, err := createListener()
		require.NoError(t, err)
		defer close()

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

	connDNS, err := grpc.Dial(targetDNS, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer connDNS.Close()

	connIP, err := grpc.Dial(targetIP, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer connIP.Close()
}
