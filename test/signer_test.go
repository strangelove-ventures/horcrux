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

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"golang.org/x/sync/errgroup"
)

var (
	signerPort  = "2222"
	signerImage = "horcrux-test"
)

// TestSigner represents a remote signer instance
type TestSigner struct {
	Home      string
	Index     int
	Pool      *dockertest.Pool
	Container *docker.Container
	Key       signer.CosignerKey
	t         *testing.T
}

type TestSigners []*TestSigner

// BuildTestSignerImage builds a Docker image for horcrux from current Dockerfile
func BuildTestSignerImage(pool *dockertest.Pool) error {
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

// StartSingleSignerContainers will generate the necessary config files for the signer node, copy over the validators
// priv_validator_key.json file, and start the signer
func StartSingleSignerContainers(t *testing.T, testSigners TestSigners, validator *TestNode, sentryNodes TestNodes, network *docker.Network) {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// init config files/directory for signer node
	for _, s := range testSigners {
		s := s
		eg.Go(func() error { return s.InitSingleSignerConfig(ctx, sentryNodes) })
	}
	require.NoError(t, eg.Wait())

	// Get Validators Priv Val key & copy it over to the signers home directory
	pv, err := validator.GetPrivVal()
	require.NoError(t, err)

	pvFile, err := tmjson.Marshal(pv)
	require.NoError(t, err)

	err = ioutil.WriteFile(path.Join(testSigners[0].Dir(), "priv_validator_key.json"), pvFile, 0600)
	require.NoError(t, err)

	// create containers & start signer nodes
	for _, s := range testSigners {
		s := s
		eg.Go(func() error {
			return s.CreateSingleSignerContainer(network.ID)
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

// StartCosignerContainers will generate the necessary config files for the signer nodes, shard the validator's
// priv_validator_key.json file, write the sharded key shares to the appropriate signer nodes directory and start the
// signer nodes. Passing a negative number or zero will enable the default behavior of connecting all signers to the
// same validator node
func StartCosignerContainers(t *testing.T, testSigners TestSigners, validator *TestNode, sentryNodes TestNodes, threshold, total, sentriesPerSigner int, network *docker.Network) {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// init config files/directory for each signer node
	switch {
	// Each signer node is connected to a unique sentry node
	case sentriesPerSigner == 1:
		var peers TestNodes

		for i, s := range testSigners {
			s := s

			// for the last signer don't use an ending index to avoid index out of range err
			if i == len(testSigners)-1 {
				peers = sentryNodes[i:]
			} else {
				peers = sentryNodes[i : i+1]
			}

			peers := peers
			eg.Go(func() error { return s.InitCosignerConfig(ctx, peers, testSigners, s.Index, threshold) })
		}

	// Each signer node is connected to the number of sentry nodes specified by sentriesPerSigner
	case sentriesPerSigner > 1:
		leftIndex := 0
		rightIndex := sentriesPerSigner
		var peers TestNodes

		for i, s := range testSigners {
			s := s

			// for the last signer don't use an ending index to avoid index out of range err
			if i == len(testSigners)-1 {
				peers = sentryNodes[i+leftIndex:]
			} else {
				peers = sentryNodes[i+leftIndex : i+rightIndex]
			}

			leftIndex += sentriesPerSigner - 1
			rightIndex += sentriesPerSigner - 1
			peers := peers
			eg.Go(func() error { return s.InitCosignerConfig(ctx, peers, testSigners, s.Index, threshold) })
		}

	// All signer nodes are connected to the same validator
	default:
		for _, s := range testSigners {
			s := s
			eg.Go(func() error { return s.InitCosignerConfig(ctx, TestNodes{validator}, testSigners, s.Index, threshold) })
		}
	}
	require.NoError(t, eg.Wait())

	// generate key shares from validator private key
	validator.t.Logf("{%s} -> Creating Private Key Shares...", validator.Name())
	shares := validator.CreateKeyShares(int64(threshold), int64(total))
	for i, s := range testSigners {
		s := s
		s.Key = shares[i]
	}

	// write key share to file in each signer nodes config directory
	for _, s := range testSigners {
		s := s
		s.t.Logf("{%s} -> Writing Key Share To File... ", s.Name())
		privateFilename := path.Join(s.Dir(), "share.json")
		require.NoError(t, signer.WriteCosignerShareFile(s.Key, privateFilename))
	}

	// create containers & start signer nodes
	for _, s := range testSigners {
		s := s
		eg.Go(func() error {
			return s.CreateCosignerContainer(network.ID)
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

// GetConfigFile returns the direct path to the signers config file as a string
func (ts *TestSigner) GetConfigFile() string {
	return path.Join(ts.Dir(), "config.yaml")
}

// Name is the hostname of the TestSigner container
func (ts *TestSigner) Name() string {
	return fmt.Sprintf("signer-%d", ts.Index)
}

// InitSingleSignerConfig creates and runs a container to init a single signers config files, and blocks until the container exits
func (ts *TestSigner) InitSingleSignerConfig(ctx context.Context, listenNodes TestNodes) error {
	container := RandLowerCaseLetterString(10)
	cmd := []string{
		chainid, "config", "init",
		chainid, listenNodes.ListenAddrs(),
		fmt.Sprintf("--home=%s", ts.Dir()),
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

// InitCosignerConfig creates and runs a container to init a signer nodes config files, and blocks until the container exits
func (ts *TestSigner) InitCosignerConfig(ctx context.Context, listenNodes TestNodes, peers TestSigners, skip, threshold int) error {
	container := RandLowerCaseLetterString(10)
	cmd := []string{
		chainid, "config", "init",
		chainid, listenNodes.ListenAddrs(),
		"--cosigner",
		fmt.Sprintf("--peers=%s", peers.PeerString(skip)),
		fmt.Sprintf("--threshold=%d", threshold),
		fmt.Sprintf("--home=%s", ts.Dir()),
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

// CreateSingleSignerContainer creates a docker container to run a single signer
func (ts *TestSigner) CreateSingleSignerContainer(networkID string) error {
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: ts.Name(),
		Config: &docker.Config{
			User:     getDockerUserString(),
			Cmd:      []string{"horcrux", "cosigner", "start", "--single", fmt.Sprintf("--home=%s", ts.Dir())},
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

// CreateCosignerContainer creates a docker container to run a mpc validator node
func (ts *TestSigner) CreateCosignerContainer(networkID string) error {
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: ts.Name(),
		Config: &docker.Config{
			User:     getDockerUserString(),
			Cmd:      []string{"horcrux", "cosigner", "start", fmt.Sprintf("--home=%s", ts.Dir())},
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
