package test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
)

var (
	signerPort  = "2222"
	signerImage = "horcrux-test"
)

// TestSigner represents an MPC validator instance
type TestSigner struct {
	Home      string
	Index     int
	Pool      *dockertest.Pool
	Container *docker.Container
	Key       signer.CosignerKey
	t         *testing.T
}

type TestSigners []*TestSigner

// BuildTestSignerContainer builds a Docker image for horcrux from current Dockerfile
func BuildTestSignerContainer(pool *dockertest.Pool, t *testing.T) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	dockerfile := path.Join("docker/horcrux/Dockerfile")
	return pool.Client.BuildImage(docker.BuildImageOptions{
		Name:                signerImage,
		Dockerfile:          dockerfile,
		OutputStream:        ioutil.Discard,
		SuppressOutput:      false,
		Pull:                false,
		RmTmpContainer:      true,
		ForceRmTmpContainer: false,
		Auth:                docker.AuthConfiguration{},
		AuthConfigs:         docker.AuthConfigurations{},
		ContextDir:          path.Dir(dir),
	})
}

func StartSignerContainers(t *testing.T, testSigners TestSigners, node *TestNode, threshold, total int, network *docker.Network) {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// init config files/directory for each signer node
	for _, s := range testSigners {
		s := s
		eg.Go(func() error { return s.InitSignerConfig(ctx, TestNodes{node}, testSigners, s.Index, threshold) })
	}
	require.NoError(t, eg.Wait())

	// generate key shares from node private key
	node.t.Logf("{%s} -> Creating Private Key Shares...", node.Name())
	shares := node.CreateKeyShares(int64(threshold), int64(total))
	for i, signer := range testSigners {
		signer := signer
		signer.Key = shares[i]
	}

	// write key share to file in each signer nodes config directory
	for _, s := range testSigners {
		// signer := signer
		s.t.Logf("{%s} -> Writing Key Share To File... ", s.Name())
		privateFilename := fmt.Sprintf("%sshare.json", s.Dir())
		require.NoError(t, signer.WriteCosignerShareFile(s.Key, privateFilename))
	}

	// create containers & start signer nodes
	for _, signer := range testSigners {
		signer := signer
		eg.Go(func() error {
			return signer.CreateSignerContainer(network.ID)
		})
	}
	require.NoError(t, eg.Wait())

	for _, s := range testSigners {
		s := s
		t.Logf("{%s} => starting container...", s.Name())
		eg.Go(func() error {
			return s.StartContainer()
		})
	}
	require.NoError(t, eg.Wait())
}

// PeerString returns a string representing a signer nodes connectable private peers
func (ts TestSigners) PeerString(skip int) string {
	var out strings.Builder
	for i, s := range ts {
		// Skip over the calling signer so its peer list does not include itself; we use i+1 to keep Cosigner IDs >0 as required in cosigner.go
		if i+1 != skip {
			// TODO:
			out.WriteString(fmt.Sprintf("tcp://%s:%s|%d,", s.Name(), signerPort, s.Index))
		}
	}
	return strings.TrimSuffix(out.String(), ",")
}

// MakeTestSigners creates the TestSigner objects required for bootstrapping tests
func MakeTestSigners(count int, home string, pool *dockertest.Pool, t *testing.T) (out TestSigners) {
	for i := 0; i < count; i++ {
		ts := &TestSigner{
			Home:      home,
			Index:     i + 1, // +1 is to ensure all Cosigner IDs end up being >0 as required in cosigner.go
			Pool:      pool,
			Container: nil,
			Key:       signer.CosignerKey{},
			t:         t,
		}
		out = append(out, ts)
	}
	return
}

// MkDir creates the directory for the TestSigner files
func (ts *TestSigner) MkDir() {
	if err := os.MkdirAll(ts.Dir(), 0755); err != nil {
		panic(err)
	}
}

// Dir is the directory where the TestSigner files are stored
func (ts *TestSigner) Dir() string {
	return fmt.Sprintf("%s/%s/", ts.Home, ts.Name())
}

// Name is the hostname of the TestSigner container
func (ts *TestSigner) Name() string {
	return fmt.Sprintf("signer-%d", ts.Index)
}

// InitSignerConfig creates and runs a container to init a signer nodes config files, and blocks until the container exits
func (ts *TestSigner) InitSignerConfig(ctx context.Context, listenNodes TestNodes, peers TestSigners, skip, threshold int) error {
	container := RandLowerCaseLetterString(10)
	cmd := []string{
		chainid, "config", "init",
		chainid, listenNodes.ListenAddrs(),
		"--cosigner",
		fmt.Sprintf("--peers=%s", peers.PeerString(skip)),
		fmt.Sprintf("--threshold=%d", threshold),
		fmt.Sprintf("--config=%s", ts.Dir()),
	}
	ts.t.Logf("{%s}[%s] -> '%s'", ts.Name(), container, strings.Join(cmd, " "))
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: container,
		Config: &docker.Config{
			User:     getDockerUserString(),
			Hostname: container,
			ExposedPorts: map[docker.Port]struct{}{
				docker.Port(fmt.Sprintf("%s/tcp", signerPort)): {},
			},
			Image:  signerImage,
			Cmd:    cmd,
			Labels: map[string]string{"horcrux-test": ts.t.Name()},
		},
		HostConfig: &docker.HostConfig{
			PublishAllPorts: true,
			AutoRemove:      true,
			Mounts: []docker.HostMount{
				{
					Type:        "bind",
					Source:      ts.Home,
					Target:      ts.Home,
					ReadOnly:    false,
					BindOptions: nil,
				},
			},
		},
		NetworkingConfig: &docker.NetworkingConfig{
			EndpointsConfig: map[string]*docker.EndpointConfig{},
		},
		Context: nil,
	})
	if err != nil {
		return err
	}
	if err := ts.Pool.Client.StartContainer(cont.ID, nil); err != nil {
		return err
	}
	return handleNodeJobError(ts.Pool.Client.WaitContainerWithContext(cont.ID, ctx))
}

// StartContainer starts a TestSigners container and assigns the new running container to replace the old one
func (ts *TestSigner) StartContainer() error {
	if err := ts.Pool.Client.StartContainer(ts.Container.ID, nil); err != nil {
		return err
	}

	c, err := ts.Pool.Client.InspectContainer(ts.Container.ID)
	if err != nil {
		return err
	}
	ts.Container = c

	return nil
}

// StopContainer stops a TestSigners docker container
func (ts *TestSigner) StopContainer() error {
	return ts.Pool.Client.StopContainer(ts.Container.ID, uint(time.Second*30))
}

// CreateSignerContainer creates a docker container to run an mpc validator node
func (ts *TestSigner) CreateSignerContainer(networkID string) error {
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: ts.Name(),
		Config: &docker.Config{
			User:     getDockerUserString(),
			Cmd:      []string{"horcrux", "cosigner", "start", fmt.Sprintf("--config=%sconfig.yaml", ts.Dir())},
			Hostname: ts.Name(),
			ExposedPorts: map[docker.Port]struct{}{
				docker.Port(fmt.Sprintf("%s/tcp", signerPort)): {},
			},
			DNS:    []string{},
			Image:  signerImage,
			Labels: map[string]string{"horcrux-test": ts.t.Name()},
		},
		HostConfig: &docker.HostConfig{
			PublishAllPorts: true,
			AutoRemove:      true,
			Mounts: []docker.HostMount{
				{
					Type:        "bind",
					Source:      ts.Dir(),
					Target:      ts.Dir(),
					ReadOnly:    false,
					BindOptions: nil,
				},
			},
		},
		NetworkingConfig: &docker.NetworkingConfig{
			EndpointsConfig: map[string]*docker.EndpointConfig{
				networkID: {},
			},
		},
		Context: nil,
	})
	if err != nil {
		return err
	}
	ts.Container = cont
	return nil
}
