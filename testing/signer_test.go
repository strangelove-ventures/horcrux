package testing

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/jackzampolin/horcrux/internal/signer"
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
)

var (
	imageName   = "horcrux-test"
	imageVer    = "latest"
	dockerFile  = "./docker/horcrux/Dockerfile"
	ctxDir      = "%s/src/github.com/jackzampolin/horcrux/"
	signerPorts = map[docker.Port]struct{}{
		"2222/tcp": struct{}{},
	}
)

func TestBuildSignerContainer(t *testing.T) {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	require.NoError(t, BuildTestSignerContainer(pool))
}

type TestSigner struct {
	Home      string
	Index     int
	Pool      *dockertest.Pool
	Container *docker.Container
	Key       signer.CosignerKey
	t         *testing.T
}

func BuildTestSignerContainer(pool *dockertest.Pool) error {
	return pool.Client.BuildImage(docker.BuildImageOptions{
		Name:                fmt.Sprintf("%s:%s", imageName, imageVer),
		Dockerfile:          "./docker/horcrux/Dockerfile",
		OutputStream:        ioutil.Discard,
		SuppressOutput:      false,
		Pull:                false,
		RmTmpContainer:      true,
		ForceRmTmpContainer: false,
		Auth:                docker.AuthConfiguration{},
		AuthConfigs:         docker.AuthConfigurations{},
		ContextDir:          fmt.Sprintf(ctxDir, os.Getenv("GOPATH")),
	})
}

type TestSigners []*TestSigner

func (ts TestSigners) PeerString() string {
	var out strings.Builder
	for _, s := range ts {
		out.WriteString(fmt.Sprintf("tcp://%s:2222|%d,", s.Name(), s.Index))
	}
	return strings.TrimSuffix(out.String(), ",")
}

// InitSignerConfig run a container for a specific job and block until the container exits
func (ts *TestSigner) InitSignerConfig(ctx context.Context, listenNode string, peers TestSigners, threshold int) error {
	container := RandLowerCaseLetterString(10)
	cmd := []string{
		"horcrux", "config", "init",
		chainid, listenNode,
		"--cosigner",
		fmt.Sprintf("--peers='%s'", peers.PeerString()),
		fmt.Sprintf("--threshold='%d'", threshold),
	}
	ts.t.Logf("{%s}[%s] -> '%s'", ts.Name(), container, strings.Join(cmd, " "))
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: container,
		Config: &docker.Config{
			Hostname:     container,
			ExposedPorts: signerPorts,
			Image:        fmt.Sprintf("%s:%s", imageName, imageVer),
			Cmd:          cmd,
		},
		HostConfig: &docker.HostConfig{
			Binds:           ts.Bind(),
			PublishAllPorts: true,
			AutoRemove:      true,
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

func (ts *TestSigner) Name() string {
	return fmt.Sprintf("signer-%d", ts.Index)
}

// Bind returns the home folder bind point for running the node
func (ts *TestSigner) Bind() []string {
	return []string{fmt.Sprintf("%s:/root/.horcrux", ts.Dir())}
}

// Dir is the directory where the test node files are stored
func (ts *TestSigner) Dir() string {
	return fmt.Sprintf("%s/%s/", ts.Home, ts.Name())
}

func (ts *TestSigner) StartContainer() error {

	return nil
}

func (ts *TestSigner) StopContainer() error {
	return nil
}

func (ts *TestSigner) CreateContainer() error {
	return nil
}

func (ts *TestSigner) InitHomeDir() error {
	return nil
}

func (ts *TestSigner) HomeDir() string {
	return ""
}

func (ts *TestSigner) CreateConfig() error {
	return nil
}

func (ts *TestSigner) CopyKeyShare(tn *TestNode) error {
	return nil
}

func (ts *TestSigner) WriteKeyToFile() error {
	return nil
}
