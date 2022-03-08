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
func StartSingleSignerContainers(
	t *testing.T,
	testSigners TestSigners,
	validator *TestNode,
	sentryNodes TestNodes,
	network *docker.Network,
) {
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

// StartCosignerContainers will generate the necessary config files for the nodes in the signer cluster,
// shard the validator's priv_validator_key.json key, write the sharded key shares to the appropriate
// signer nodes directory and start the signer cluster.
// NOTE: Zero or negative values for sentriesPerSigner configures the nodes in the signer cluster to connect to the
//       same sentry node.
func StartCosignerContainers(
	t *testing.T,
	signers TestSigners,
	validator *TestNode,
	sentries TestNodes,
	threshold, total,
	sentriesPerSigner int,
	network *docker.Network,
) {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// init config files, for each node in the signer cluster, with the appropriate number of sentries in front of the node
	switch {
	// Each node in the signer cluster is connected to a unique sentry node
	case sentriesPerSigner == 1:
		var peers TestNodes
		for i, s := range signers {
			s := s

			if i == len(signers)-1 {
				// for the last signer don't use an ending index to avoid index out of range err
				peers = sentries[i:]
			} else {
				peers = sentries[i : i+1]
			}

			p := peers
			eg.Go(func() error { return s.InitCosignerConfig(ctx, p, signers, s.Index, threshold) })
		}

	// Each node in the signer cluster is connected to the number of sentry nodes specified by sentriesPerSigner
	case sentriesPerSigner > 1:
		var peers TestNodes
		sentriesIndex := 0
		for _, s := range signers {
			s := s
			peers = nil
			// if we are indexing sentries up to the end of the slice
			switch {
			case sentriesIndex+sentriesPerSigner-1 == len(sentries)-1:
				peers = append(peers, sentries[sentriesIndex:]...)
				sentriesIndex += 1

				// if there aren't enough sentries left in the slice use the sentries left in slice,
				// calculate how many more are needed, then start back at the beginning of
				// the slice to grab the rest. After, check if index into slice of sentries needs reset
			case sentriesIndex+sentriesPerSigner-1 > len(sentries)-1:
				sentriesLeftInSlice := len(sentries[sentriesIndex:])
				peers = append(peers, sentries[sentriesIndex:]...)

				neededSentries := sentriesPerSigner - sentriesLeftInSlice
				peers = append(peers, sentries[0:neededSentries]...)

				sentriesIndex += 1
				if sentriesIndex > len(sentries)-1 {
					sentriesIndex = 0
				}
			default:
				peers = sentries[sentriesIndex : sentriesIndex+sentriesPerSigner]
				sentriesIndex += 1
			}
			p := peers
			eg.Go(func() error { return s.InitCosignerConfig(ctx, p, signers, s.Index, threshold) })
		}

	// All nodes in the signer cluster are connected to the same sentry node
	default:
		for _, s := range signers {
			s := s
			eg.Go(func() error { return s.InitCosignerConfig(ctx, TestNodes{validator}, signers, s.Index, threshold) })
		}
	}
	require.NoError(t, eg.Wait())

	// generate key shares from validator private key
	validator.t.Logf("{%s} -> Creating Private Key Shares...", validator.Name())
	shares := validator.CreateKeyShares(int64(threshold), int64(total))
	for i, s := range signers {
		s := s
		s.Key = shares[i]
	}

	// write key share to file in each signer nodes config directory
	for _, s := range signers {
		s := s
		s.t.Logf("{%s} -> Writing Key Share To File... ", s.Name())
		privateFilename := path.Join(s.Dir(), "share.json")
		require.NoError(t, signer.WriteCosignerShareFile(s.Key, privateFilename))
	}

	// create containers & start signer nodes
	for _, s := range signers {
		s := s
		eg.Go(func() error {
			return s.CreateCosignerContainer(network.ID)
		})
	}
	require.NoError(t, eg.Wait())

	for _, s := range signers {
		s := s
		t.Logf("{%s} => starting container...", s.Name())
		eg.Go(func() error {
			return s.StartContainer()
		})
	}
	require.NoError(t, eg.Wait())
}

// PeerString returns a string representing a TestSigner's connectable private peers
// skip is the calling TestSigner's index
func (ts TestSigners) PeerString(skip int) string {
	var out strings.Builder
	for _, s := range ts {
		// Skip over the calling signer so its peer list does not include itself
		if s.Index != skip {
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

func (ts *TestSigner) GetHosts() (out Hosts) {
	host := ContainerPort{
		Name:      ts.Name(),
		Container: ts.Container,
		Port:      docker.Port(fmt.Sprintf("%s/tcp", signerPort)),
	}
	out = append(out, host)
	return
}

func (ts TestSigners) GetHosts() (out Hosts) {
	for _, s := range ts {
		out = append(out, s.GetHosts()...)
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
	return fmt.Sprintf("signer-%d-%s", ts.Index, ts.t.Name())
}

// InitSingleSignerConfig creates and runs a container to init a single signers config files
// blocks until the container exits
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

// InitCosignerConfig creates and runs a container to init a signer nodes config files
// blocks until the container exits
func (ts *TestSigner) InitCosignerConfig(
	ctx context.Context, listenNodes TestNodes, peers TestSigners, skip, threshold int) error {
	container := RandLowerCaseLetterString(10)
	cmd := []string{
		chainid, "config", "init",
		chainid, listenNodes.ListenAddrs(),
		"--cosigner",
		fmt.Sprintf("--peers=%s", peers.PeerString(skip)),
		fmt.Sprintf("--threshold=%d", threshold),
		fmt.Sprintf("--home=%s", ts.Dir()),
		fmt.Sprintf("--listen=tcp://%s:%s", ts.Name(), signerPort),
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

func (ts *TestSigner) PauseContainer() error {
	return ts.Pool.Client.PauseContainer(ts.Container.ID)
}

func (ts *TestSigner) UnpauseContainer() error {
	return ts.Pool.Client.UnpauseContainer(ts.Container.ID)
}

// CreateSingleSignerContainer creates a docker container to run a single signer
func (ts *TestSigner) CreateSingleSignerContainer(networkID string) error {
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: ts.Name(),
		Config: &docker.Config{
			User:     getDockerUserString(),
			Cmd:      []string{"horcrux", "signer", "start", fmt.Sprintf("--home=%s", ts.Dir())},
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
