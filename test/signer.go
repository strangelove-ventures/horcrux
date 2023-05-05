package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/strangelove-ventures/horcrux/signer/proto"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	signerPort       = "2222"
	signerImage      = "horcrux-test"
	binary           = "horcrux"
	signerPortDocker = signerPort + "/tcp"
)

// Signer represents a remote signer instance
type Signer struct {
	Home           string
	Index          int
	ValidatorIndex int
	Pool           *dockertest.Pool
	networkID      string
	Container      *docker.Container
	Key            signer.CosignerEd25519Key
	tl             Logger
}

type Signers []*Signer

// BuildSignerImage builds a Docker image for horcrux from current Dockerfile
func BuildSignerImage(pool *dockertest.Pool) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	dockerfile := "docker/horcrux/native.Dockerfile"
	return pool.Client.BuildImage(docker.BuildImageOptions{
		Name:                signerImage,
		Dockerfile:          dockerfile,
		OutputStream:        io.Discard,
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
	testSigners Signers,
	validator *Node,
	sentryNodes Nodes,
) error {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// init config files/directory for signer node
	for _, s := range testSigners {
		s := s
		eg.Go(func() error { return s.InitSingleSignerConfig(ctx, sentryNodes) })
	}
	if err := eg.Wait(); err != nil {
		return err
	}

	// Get Validators Priv Val key & copy it over to the signers home directory
	pv, err := validator.GetPrivVal()
	if err != nil {
		return err
	}

	pvFile, err := cometjson.Marshal(pv)
	if err != nil {
		return err
	}

	err = os.WriteFile(
		filepath.Join(
			testSigners[0].Dir(),
			fmt.Sprintf("%s_priv_validator_key.json", validator.ChainID),
		),
		pvFile,
		0600,
	)
	if err != nil {
		return err
	}

	// create containers & start signer nodes
	for _, s := range testSigners {
		s := s
		eg.Go(func() error {
			return s.CreateSingleSignerContainer()
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}

	for _, s := range testSigners {
		s := s
		s.tl.Logf("{%s} => starting container...", s.Name())
		eg.Go(func() error {
			return s.StartContainer()
		})
	}
	return eg.Wait()
}

// StartCosignerContainers will generate the necessary config files for the nodes in the signer cluster,
// shard the validator's priv_validator_key.json key, write the sharded key shards to the appropriate
// signer nodes directory and start the signer cluster.
// NOTE: Zero or negative values for sentriesPerSigner configures the nodes in the signer cluster to connect to the
// same sentry node.
func StartCosignerContainers(
	signers Signers,
	sentryMap map[string]Nodes,
	threshold uint8,
	sentriesPerSigner int,
) error {
	eg := new(errgroup.Group)
	ctx := context.Background()

	peers := make([]Nodes, len(signers))

	for _, sentries := range sentryMap {
		// init config files, for each node in the signer cluster, with the appropriate number of sentries in front of the node
		switch {
		// Each node in the signer cluster is connected to a unique sentry node
		case sentriesPerSigner == 1:
			singleSentryIndex := 0
			for i := range signers {
				if len(sentries) == 1 || len(signers) > len(sentries) {
					peers[i] = append(peers[i], sentries[singleSentryIndex:singleSentryIndex+1]...)
					singleSentryIndex++
					if singleSentryIndex >= len(sentries) {
						singleSentryIndex = 0
					}
				} else {
					peers[i] = append(peers[i], sentries[i:i+1]...)
				}
			}

		// Each node in the signer cluster is connected to the number of sentry nodes specified by sentriesPerSigner
		case sentriesPerSigner > 1:
			sentriesIndex := 0
			for i := range signers {
				// if we are indexing sentries up to the end of the slice
				switch {
				case sentriesIndex+sentriesPerSigner == len(sentries):
					peers[i] = append(peers[i], sentries[sentriesIndex:]...)
					sentriesIndex++

					// if there aren't enough sentries left in the slice use the sentries left in slice,
					// calculate how many more are needed, then start back at the beginning of
					// the slice to grab the rest. After, check if index into slice of sentries needs reset
				case sentriesIndex+sentriesPerSigner > len(sentries):
					remainingSentries := sentries[sentriesIndex:]
					peers[i] = append(peers[i], remainingSentries...)

					neededSentries := sentriesPerSigner - len(remainingSentries)
					peers[i] = append(peers[i], sentries[0:neededSentries]...)

					sentriesIndex++
					if sentriesIndex >= len(sentries) {
						sentriesIndex = 0
					}
				default:
					peers[i] = append(peers[i], sentries[sentriesIndex:sentriesIndex+sentriesPerSigner]...)
					sentriesIndex++
				}
			}

		// All nodes in the signer cluster are connected to all sentry nodes
		default:
			for i := range signers {
				peers[i] = append(peers[i], sentries...)
			}
		}
	}

	for i, s := range signers {
		i := i
		s := s
		eg.Go(func() error { return s.InitThresholdModeConfig(ctx, peers[i], signers, threshold) })
	}
	err := eg.Wait()
	if err != nil {
		return err
	}

	// create containers & start signer nodes
	for _, s := range signers {
		s := s
		eg.Go(func() error {
			return s.CreateCosignerContainer()
		})
	}
	err = eg.Wait()
	if err != nil {
		return err
	}

	for _, s := range signers {
		s := s
		s.tl.Logf("{%s} => starting container...", s.Name())
		eg.Go(func() error {
			return s.StartContainer()
		})
	}
	return eg.Wait()
}

// CosignerFlags returns a string slice representing Signers' connectable private peers
func (ts Signers) ConfigInitFlags() (out []string) {
	for _, s := range ts {
		out = append(out, "--cosigner", fmt.Sprintf("tcp://%s:%s", s.Name(), signerPort))
	}
	return out
}

// MakeSigners creates the Signer objects required for bootstrapping tests
func MakeSigners(
	validatorIndex int,
	count int,
	home string,
	pool *dockertest.Pool,
	networkID string,
	tl Logger,
) (out Signers) {
	for i := 0; i < count; i++ {
		ts := &Signer{
			Home:           home,
			Index:          i + 1, // +1 is to ensure all Cosigner IDs end up being >0 as required in cosigner.go
			ValidatorIndex: validatorIndex,
			Pool:           pool,
			networkID:      networkID,
			Container:      nil,
			tl:             tl,
		}
		out = append(out, ts)
	}
	return
}

func (ts *Signer) GetHosts() (out Hosts) {
	host := ContainerPort{
		Name:      ts.Name(),
		Container: ts.Container,
		Port:      docker.Port(signerPortDocker),
	}
	out = append(out, host)
	return
}

func (ts Signers) GetHosts() (out Hosts) {
	for _, s := range ts {
		out = append(out, s.GetHosts()...)
	}
	return
}

// MkDir creates the directory for the Signer files
func (ts *Signer) MkDir() {
	if err := os.MkdirAll(ts.Dir(), 0755); err != nil {
		panic(err)
	}
}

// Dir is the directory where the Signer files are stored
func (ts *Signer) Dir() string {
	return filepath.Join(ts.Home, ts.Name())
}

// GetConfigFile returns the direct path to the signers config file as a string
func (ts *Signer) GetConfigFile() string {
	return filepath.Join(ts.Dir(), "config.yaml")
}

// Name is the hostname of the Signer container
func (ts *Signer) Name() string {
	return fmt.Sprintf("val-%d-sgn-%d-%s", ts.ValidatorIndex, ts.Index, ts.tl.Name())
}

// GRPCAddress returns the TCP address of the GRPC server,
// reachable from within the docker network.
func (ts *Signer) GRPCAddress() string {
	return fmt.Sprintf("tcp://%s:%s", ts.Name(), signerPort)
}

// ExecHorcruxCmd executes a CLI subcommand for the horcrux binary for the specific cosigner.
// The config home directory will be appended as a flag.
func (ts *Signer) ExecHorcruxCmd(ctx context.Context, cmd ...string) error {
	cmd = ts.horcruxCmd(cmd)
	container := RandLowerCaseLetterString(10)
	ts.tl.Logf("{%s}[%s] -> '%s'", ts.Name(), container, strings.Join(cmd, " "))
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: container,
		Config: &docker.Config{
			User:     getDockerUserString(),
			Hostname: container,
			ExposedPorts: map[docker.Port]struct{}{
				docker.Port(signerPortDocker): {},
			},
			Image:  signerImage,
			Cmd:    cmd,
			Labels: map[string]string{"horcrux-test": ts.tl.Name()},
		},
		HostConfig: &docker.HostConfig{
			PublishAllPorts: true,
			AutoRemove:      false,
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
			EndpointsConfig: map[string]*docker.EndpointConfig{
				ts.networkID: {},
			},
		},
		Context: nil,
	})
	if err != nil {
		return err
	}
	if err := ts.Pool.Client.StartContainer(cont.ID, nil); err != nil {
		return err
	}
	exitCode, err := ts.Pool.Client.WaitContainerWithContext(cont.ID, ctx)
	outputStream := new(bytes.Buffer)
	errorStream := new(bytes.Buffer)
	_ = ts.Pool.Client.Logs(docker.LogsOptions{
		Context:      ctx,
		Container:    cont.ID,
		OutputStream: outputStream,
		ErrorStream:  errorStream,
		Stdout:       true,
		Stderr:       true,
		Tail:         "100",
		Follow:       false,
		Timestamps:   false,
	})
	_ = ts.Pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: cont.ID})
	stdout := outputStream.String()
	stderr := errorStream.String()
	return containerExitError(container, exitCode, stdout, stderr, err)
}

// InitSingleSignerConfig creates and runs a container to init a single signers config files
// blocks until the container exits
func (ts *Signer) InitSingleSignerConfig(ctx context.Context, listenNodes Nodes) error {
	cmd := []string{"config", "init", "--mode", "single"}
	cmd = append(cmd, listenNodes.ConfigInitFlags()...)
	return ts.ExecHorcruxCmd(ctx, cmd...)
}

// InitThresholdModeConfig creates and runs a container to init a signer nodes config files
// blocks until the container exits
func (ts *Signer) InitThresholdModeConfig(
	ctx context.Context, listenNodes Nodes, cosigners Signers, threshold uint8) error {
	cmd := []string{"config", "init"}
	cmd = append(cmd, listenNodes.ConfigInitFlags()...)
	cmd = append(cmd, cosigners.ConfigInitFlags()...)
	cmd = append(cmd, "--threshold", fmt.Sprint(threshold))
	return ts.ExecHorcruxCmd(ctx, cmd...)
}

// StartContainer starts a Signers container and assigns the new running container to replace the old one
func (ts *Signer) StartContainer() error {
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

// StopAndRemoveContainer stops and removes a Signers docker container.
// If force is true, error for stopping container will be ignored and container
// will be forcefully removed.
func (ts *Signer) StopAndRemoveContainer(force bool) error {
	if err := ts.Pool.Client.StopContainer(ts.Container.ID, 60); err != nil && !force {
		return err
	}
	return ts.Pool.Client.RemoveContainer(docker.RemoveContainerOptions{
		ID:    ts.Container.ID,
		Force: force,
	})
}

func (ts *Signer) PauseContainer() error {
	return ts.Pool.Client.PauseContainer(ts.Container.ID)
}

func (ts *Signer) UnpauseContainer() error {
	return ts.Pool.Client.UnpauseContainer(ts.Container.ID)
}

// CreateSingleSignerContainer creates a docker container to run a single signer
func (ts *Signer) CreateSingleSignerContainer() error {
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: ts.Name(),
		Config: &docker.Config{
			User:     getDockerUserString(),
			Cmd:      []string{binary, "signer", "start", "--accept-risk", fmt.Sprintf("--home=%s", ts.Dir())},
			Hostname: ts.Name(),
			ExposedPorts: map[docker.Port]struct{}{
				docker.Port(signerPortDocker): {},
			},
			DNS:    []string{},
			Image:  signerImage,
			Labels: map[string]string{"horcrux-test": ts.tl.Name()},
		},
		HostConfig: &docker.HostConfig{
			PublishAllPorts: true,
			AutoRemove:      false,
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
				ts.networkID: {},
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
func (ts *Signer) CreateCosignerContainer() error {
	cont, err := ts.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: ts.Name(),
		Config: &docker.Config{
			User:     getDockerUserString(),
			Cmd:      []string{binary, "cosigner", "start", fmt.Sprintf("--home=%s", ts.Dir())},
			Hostname: ts.Name(),
			ExposedPorts: map[docker.Port]struct{}{
				docker.Port(signerPortDocker): {},
			},
			DNS:    []string{},
			Image:  signerImage,
			Labels: map[string]string{"horcrux-test": ts.tl.Name()},
		},
		HostConfig: &docker.HostConfig{
			PublishAllPorts: true,
			AutoRemove:      false,
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
				ts.networkID: {},
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

// TransferLeadership elects a new raft leader.
func (ts *Signer) TransferLeadership(ctx context.Context, newLeaderID int) error {
	return ts.ExecHorcruxCmd(ctx,
		"elect", strconv.FormatInt(int64(newLeaderID), 10),
	)
}

// GetLeader returns the current raft leader.
func (ts *Signer) GetLeader(ctx context.Context) (string, error) {
	grpcAddress := GetHostPort(ts.Container, signerPortDocker)
	conn, err := grpc.Dial(grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return "", fmt.Errorf("dialing failed: %w", err)
	}
	defer conn.Close()

	ctx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()

	grpcClient := proto.NewCosignerGRPCClient(conn)

	res, err := grpcClient.GetLeader(ctx, &proto.CosignerGRPCGetLeaderRequest{})
	if err != nil {
		return "", err
	}
	return res.GetLeader(), nil
}

func (ts *Signer) PollForLeader(ctx context.Context, expectedLeader string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			leader, err := ts.GetLeader(ctx)
			ts.tl.Logf("{%s} => current leader: {%s}, expected leader: {%s}", ts.Name(), leader, expectedLeader)
			if err != nil {
				return fmt.Errorf("failed to get leader from signer: %s - %w", ts.Name(), err)
			}
			if leader == expectedLeader {
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("leader did not match before timeout for signer: %s - %w", ts.Name(), ctx.Err())
		}
	}
}

func (ts *Signer) horcruxCmd(cmd []string) (out []string) {
	out = append(out, binary)
	out = append(out, cmd...)
	out = append(out, fmt.Sprintf("--home=%s", ts.Dir()))
	return out
}
