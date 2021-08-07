package test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
)

var (
	chainid = "horcrux"
)

func SetupTestRun(t *testing.T, numNodes int) (context.Context, string, *dockertest.Pool, *docker.Network, TestNodes) {

	home, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	network, err := CreateTestNetwork(pool, fmt.Sprintf("horcrux-%s", RandLowerCaseLetterString(8)), t)
	require.NoError(t, err)

	return context.Background(), home, pool, network, MakeTestNodes(numNodes, home, chainid, simdChain, pool, t)
}

// GetHostPort returns a resource's published port with an address.
func GetHostPort(cont *docker.Container, portID string) string {
	if cont == nil || cont.NetworkSettings == nil {
		return ""
	}

	m, ok := cont.NetworkSettings.Ports[docker.Port(portID)]
	if !ok || len(m) == 0 {
		return ""
	}

	ip := m[0].HostIP
	if ip == "0.0.0.0" {
		ip = "localhost"
	}
	return net.JoinHostPort(ip, m[0].HostPort)
}

func CreateTestNetwork(pool *dockertest.Pool, name string, t *testing.T) (*docker.Network, error) {
	return pool.Client.CreateNetwork(docker.CreateNetworkOptions{
		Name:           name,
		Options:        map[string]interface{}{},
		Labels:         map[string]string{"horcrux-test": t.Name()},
		CheckDuplicate: true,
		Internal:       false,
		EnableIPv6:     false,
		Context:        context.Background(),
	})
}
