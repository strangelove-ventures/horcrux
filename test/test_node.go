package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avast/retry-go"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/simapp"
	"github.com/cosmos/cosmos-sdk/simapp/params"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/strangelove-ventures/horcrux/signer"
	tmconfig "github.com/tendermint/tendermint/config"
	tmBytes "github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	rpcclient "github.com/tendermint/tendermint/rpc/client"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	libclient "github.com/tendermint/tendermint/rpc/jsonrpc/client"
	"golang.org/x/sync/errgroup"
)

const (
	valKey    = "validator"
	blockTime = 3 // seconds
)

var cosmosNodePorts = map[docker.Port]struct{}{
	"26656/tcp": {},
	"26657/tcp": {},
	"9090/tcp":  {},
	"1337/tcp":  {},
	"1234/tcp":  {},
}

func getGoModuleVersion(pkg string) string {
	cmd := exec.Command("go", "list", "-m", "-u", "-f", "{{.Version}}", pkg)
	out, err := cmd.Output()
	if err != nil {
		panic(fmt.Sprintf("failed to evaluate Go module version: %v", err))
	}
	return strings.TrimSpace(string(out))
}

func getHeighlinerChain(
	chain,
	version,
	binary,
	bech32Prefix string,
	pubKeyAsBech32 bool,
	preGenTx func(tn *TestNode) error,
) *ChainType {
	return &ChainType{
		Repository:     fmt.Sprintf("ghcr.io/strangelove-ventures/heighliner/%s", chain),
		Version:        version,
		Bin:            binary,
		Bech32Prefix:   bech32Prefix,
		PubKeyAsBech32: pubKeyAsBech32,
		Ports:          cosmosNodePorts,
		PreGenTx:       preGenTx,
	}
}

func getSimdChain() *ChainType {
	return getHeighlinerChain("sim", getGoModuleVersion("github.com/cosmos/cosmos-sdk"), "simd", "cosmos", false, nil)
}

func getSentinelChain(ctx context.Context, version string) *ChainType {
	// sets "approve_by" in the genesis.json
	// this is required for sentinel, genesis validation fails without it.
	sentinelGenesisJSONModification := func(tn *TestNode) error {
		genesisJSON := path.Join(tn.NodeHome(), "config", "genesis.json")
		address, err := tn.Bech32AddressForKey(valKey)
		if err != nil {
			return err
		}
		command := []string{"sed", "-i", fmt.Sprintf(`s/"approve_by": ""/"approve_by": "%s"/g`, address), genesisJSON}
		return handleNodeJobError(tn.NodeJob(ctx, command))
	}

	return getHeighlinerChain("sentinel", version, "sentinelhub", "sent", true, sentinelGenesisJSONModification)
}

// ChainType represents the type of chain to instantiate
type ChainType struct {
	Repository string
	Version    string
	Bin        string

	Bech32Prefix   string
	PubKeyAsBech32 bool // true - gentx uses bech32 consval address. false - gentx uses json pubkey

	Ports map[docker.Port]struct{}

	// some chains need additional steps, such as genesis.json modification, before executing gentx
	PreGenTx func(tn *TestNode) error
}

// TestNode represents a node in the test network that is being created
type TestNode struct {
	Home           string
	Index          int
	ValidatorIndex int
	ChainID        string
	Chain          *ChainType
	GenesisCoins   string
	Validator      bool
	Pool           *dockertest.Pool
	Client         rpcclient.Client
	Container      *docker.Container
	tl             TestLogger
	ec             params.EncodingConfig
}

type ContainerPort struct {
	Name      string
	Container *docker.Container
	Port      docker.Port
}

type Hosts []ContainerPort

// CliContext creates a new Cosmos SDK client context
func (tn *TestNode) CliContext() client.Context {
	return client.Context{
		Client:            tn.Client,
		ChainID:           tn.ChainID,
		InterfaceRegistry: tn.ec.InterfaceRegistry,
		Input:             os.Stdin,
		Output:            os.Stdout,
		OutputFormat:      "json",
		LegacyAmino:       tn.ec.Amino,
	}
}

// MakeTestNodes creates the test node objects required for bootstrapping tests
func MakeTestNodes(
	validatorIndex,
	count int,
	home,
	chainID string,
	chainType *ChainType,
	pool *dockertest.Pool,
	tl TestLogger,
) (out TestNodes) {
	err := pool.Client.PullImage(docker.PullImageOptions{
		Repository: chainType.Repository,
		Tag:        chainType.Version,
	}, docker.AuthConfiguration{})
	if err != nil {
		tl.Logf("Error pulling image: %v", err)
	}
	for i := 0; i < count; i++ {
		tn := &TestNode{Home: home, Index: i, ValidatorIndex: validatorIndex, Chain: chainType, ChainID: chainID,
			Pool: pool, tl: tl, ec: simapp.MakeTestEncodingConfig()}
		tn.MkDir()
		out = append(out, tn)
	}
	return
}

// Creates indexed validator test nodes
func GetValidators(
	startingValidatorIndex,
	count,
	sentriesPerValidator int,
	home,
	chainID string,
	chain *ChainType,
	pool *dockertest.Pool,
	t *testing.T,
) (out TestNodes) {
	for i := startingValidatorIndex; i < startingValidatorIndex+count; i++ {
		out = append(out, MakeTestNodes(i, sentriesPerValidator, home, chainID, chain, pool, t)...)
	}
	return
}

func GetAllNodes(nodes ...TestNodes) (out TestNodes) {
	for _, testNodes := range nodes {
		out = append(out, testNodes...)
	}
	return
}

// NewClient creates and assigns a new Tendermint RPC client to the TestNode
func (tn *TestNode) NewClient(addr string) error {
	httpClient, err := libclient.DefaultHTTPClient(addr)
	if err != nil {
		return err
	}

	httpClient.Timeout = 10 * time.Second
	rpcClient, err := rpchttp.NewWithClient(addr, "/websocket", httpClient)
	if err != nil {
		return err
	}

	tn.Client = rpcClient
	return nil

}

func (tn *TestNode) GetHosts() (out Hosts) {
	name := tn.Name()
	for k := range tn.Chain.Ports {
		host := ContainerPort{
			Name:      name,
			Container: tn.Container,
			Port:      k,
		}
		out = append(out, host)
	}
	return
}

func (tn TestNodes) GetHosts() (out Hosts) {
	for _, n := range tn {
		out = append(out, n.GetHosts()...)
	}
	return
}

func connectionAttempt(t *testing.T, host ContainerPort) bool {
	port := string(host.Port)
	hostname := GetHostPort(host.Container, port)

	t.Logf("Attempting to reach {%s} {%s} local hostname: %s", host.Name, port, hostname)

	conn, err := net.DialTimeout("tcp", hostname, time.Duration(1)*time.Second)

	if err != nil {
		t.Logf("Error: %s\n", err)
		return false
	}

	defer conn.Close()

	t.Logf("{%s} is reachable", hostname)
	return true
}

func isReachable(wg *sync.WaitGroup, t *testing.T, host ContainerPort, ch chan<- bool) {
	defer wg.Done()

	ch <- connectionAttempt(t, host)
}

func (hosts Hosts) WaitForAllToStart(t *testing.T, timeout int) error {
	if len(hosts) == 0 {
		return nil
	}
ReachableCheckLoop:
	for seconds := 1; seconds <= timeout; seconds++ {
		var wg sync.WaitGroup

		results := make(chan bool, len(hosts))
		wg.Add(len(hosts))
		for _, host := range hosts {
			go isReachable(&wg, t, host, results)
		}
		wg.Wait()

		close(results)

		for reachable := range results {
			if !reachable {
				t.Logf("A host is not reachable")
				continue ReachableCheckLoop
			}
		}

		t.Logf("All hosts are reachable after %d seconds", seconds)
		return nil
	}
	return fmt.Errorf("timed out after %d seconds waiting for hosts", timeout)
}

// Name is the hostname of the test node container
func (tn *TestNode) Name() string {
	return fmt.Sprintf("val-%d-node-%d-%s", tn.ValidatorIndex, tn.Index, tn.tl.Name())
}

// Dir is the directory where the test node files are stored
func (tn *TestNode) Dir() string {
	return fmt.Sprintf("%s/%s/", tn.Home, tn.Name())
}

// MkDir creates the directory for the testnode
func (tn *TestNode) MkDir() {
	if err := os.MkdirAll(tn.Dir(), 0755); err != nil {
		panic(err)
	}
}

// GentxPath returns the path to the gentx for a node
func (tn *TestNode) GentxPath() (string, error) {
	id, err := tn.NodeID()
	return path.Join(tn.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", id)), err
}

func (tn *TestNode) GenesisFilePath() string {
	return path.Join(tn.Dir(), "config", "genesis.json")
}

func (tn *TestNode) TMConfigPath() string {
	return path.Join(tn.Dir(), "config", "config.toml")
}

// Bind returns the home folder bind point for running the node
func (tn *TestNode) Bind() []string {
	return []string{fmt.Sprintf("%s:/home/.%s", tn.Dir(), tn.Chain.Bin)}
}

func (tn *TestNode) NodeHome() string {
	return fmt.Sprintf("/home/.%s", tn.Chain.Bin)
}

// Keybase returns the keyring for a given node
func (tn *TestNode) Keybase() keyring.Keyring {
	kr, err := keyring.New("", keyring.BackendTest, tn.Dir(), os.Stdin)
	if err != nil {
		panic(err)
	}
	return kr
}

// SetValidatorConfigAndPeers modifies the config for a validator node to start a chain
func (tn *TestNode) SetValidatorConfigAndPeers(peers string, enablePrivVal bool) {
	// Pull default config
	cfg := tmconfig.DefaultConfig()

	// change config to include everything needed
	stdconfigchanges(cfg, peers, enablePrivVal)

	// overwrite with the new config
	tmconfig.WriteConfigFile(tn.TMConfigPath(), cfg)
}

func (tn *TestNode) SetPrivValListen(peers string) {
	cfg := tmconfig.DefaultConfig()
	stdconfigchanges(cfg, peers, true) // Reapply the changes made to the config file in SetValidatorConfigAndPeers()
	tmconfig.WriteConfigFile(tn.TMConfigPath(), cfg)
}

func (tn *TestNode) getValSigningInfo(address tmBytes.HexBytes) (*slashingtypes.QuerySigningInfoResponse, error) {
	valConsPrefix := fmt.Sprintf("%svalcons", tn.Chain.Bech32Prefix)
	bech32ValConsAddress, err := bech32.ConvertAndEncode(valConsPrefix, address)
	if err != nil {
		return nil, err
	}
	return slashingtypes.NewQueryClient(
		tn.CliContext()).SigningInfo(context.Background(), &slashingtypes.QuerySigningInfoRequest{
		ConsAddress: bech32ValConsAddress,
	})
}

func (tn *TestNode) GetMostRecentConsecutiveSignedBlocks(
	max int64,
	address tmBytes.HexBytes,
) (count int64, latestHeight int64, err error) {
	var status *ctypes.ResultStatus
	status, err = tn.Client.Status(context.Background())
	if err != nil {
		return
	}

	latestHeight = status.SyncInfo.LatestBlockHeight

	for i := latestHeight; i > latestHeight-max && i > 0; i-- {
		var block *ctypes.ResultBlock
		block, err = tn.Client.Block(context.Background(), &i)
		if err != nil {
			return
		}
		for _, voter := range block.Block.LastCommit.Signatures {
			if reflect.DeepEqual(voter.ValidatorAddress, address) {
				count++
				break
			}
		}
	}
	return
}

func (tn *TestNode) getMissingBlocks(address tmBytes.HexBytes) (int64, error) {
	missedBlocks, err := tn.getValSigningInfo(address)
	if err != nil {
		return 0, err
	}
	return missedBlocks.ValSigningInfo.MissedBlocksCounter, nil
}

func (tn *TestNode) EnsureNotSlashed(address tmBytes.HexBytes) error {
	for i := 0; i < 50; i++ {
		time.Sleep(1 * time.Second)
		slashInfo, err := tn.getValSigningInfo(address)
		if err != nil {
			return err
		}

		if i == 0 {
			tn.tl.Logf("{EnsureNotSlashed} val-%d Initial Missed blocks: %d", tn.ValidatorIndex,
				slashInfo.ValSigningInfo.MissedBlocksCounter)
			continue
		}
		if i%2 == 0 {
			// require.Equal(tn.t, missed, slashInfo.ValSigningInfo.MissedBlocksCounter)
			stat, err := tn.Client.Status(context.Background())
			if err != nil {
				return err
			}

			tn.tl.Logf("{EnsureNotSlashed} val-%d Missed blocks: %d block: %d", tn.ValidatorIndex,
				slashInfo.ValSigningInfo.MissedBlocksCounter, stat.SyncInfo.LatestBlockHeight)
		}
		if slashInfo.ValSigningInfo.Tombstoned {
			return errors.New("validator is tombstoned")
		}
	}
	return nil
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// Wait until we have signed n blocks in a row
func (tn *TestNode) WaitForConsecutiveBlocks(blocks int64, address tmBytes.HexBytes) error {
	initialMissed, err := tn.getMissingBlocks(address)
	if err != nil {
		return err
	}
	tn.tl.Logf("{WaitForConsecutiveBlocks} val-%d Initial Missed blocks: %d", tn.ValidatorIndex, initialMissed)
	stat, err := tn.Client.Status(context.Background())
	if err != nil {
		return err
	}

	startingBlock := stat.SyncInfo.LatestBlockHeight
	// timeout after ~1 minute plus block time
	timeoutSeconds := blocks*(int64(blockTime)+1) + int64(60)
	for i := int64(0); i < timeoutSeconds; i++ {
		time.Sleep(1 * time.Second)

		recentSignedBlocksCount, checkingBlock, err := tn.GetMostRecentConsecutiveSignedBlocks(blocks, address)
		if err != nil {
			continue
		}
		deltaMissed := min(blocks, checkingBlock-1) - recentSignedBlocksCount
		deltaBlocks := checkingBlock - startingBlock

		tn.tl.Logf("{WaitForConsecutiveBlocks} val-%d Missed blocks: %d block: %d",
			tn.ValidatorIndex, deltaMissed, checkingBlock)
		if deltaMissed == 0 && deltaBlocks >= blocks {
			tn.tl.Logf("Time (sec) to sign %d consecutive blocks: %d", blocks, i+1)
			return nil // done waiting for consecutive signed blocks
		}
	}
	return errors.New("timed out waiting for cluster to recover signing blocks")
}

func stdconfigchanges(cfg *tmconfig.Config, peers string, enablePrivVal bool) {
	// turn down blocktimes to make the chain faster
	cfg.Consensus.TimeoutCommit = blockTime * time.Second
	cfg.Consensus.TimeoutPropose = blockTime * time.Second

	// Open up rpc address
	cfg.RPC.ListenAddress = "tcp://0.0.0.0:26657"

	if enablePrivVal {
		cfg.BaseConfig.PrivValidatorListenAddr = "tcp://0.0.0.0:1234"
	}

	// Allow for some p2p weirdness
	cfg.P2P.AllowDuplicateIP = true
	cfg.P2P.AddrBookStrict = false

	// Set log level to info
	cfg.BaseConfig.LogLevel = "info"

	// set persistent peer nodes
	cfg.P2P.PersistentPeers = peers
}

// NodeJob run a container for a specific job and block until the container exits
// NOTE: on job containers generate random name
func (tn *TestNode) NodeJob(ctx context.Context, cmd []string) (string, int, string, string, error) {
	container := RandLowerCaseLetterString(10)
	tn.tl.Logf("{%s}[%s] -> '%s'", tn.Name(), container, strings.Join(cmd, " "))
	cont, err := tn.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: container,
		Config: &docker.Config{
			User:         getDockerUserString(),
			Hostname:     container,
			ExposedPorts: tn.Chain.Ports,
			DNS:          []string{},
			Image:        fmt.Sprintf("%s:%s", tn.Chain.Repository, tn.Chain.Version),
			Cmd:          cmd,
			Labels:       map[string]string{"horcrux-test": tn.tl.Name()},
		},
		HostConfig: &docker.HostConfig{
			Binds:           tn.Bind(),
			PublishAllPorts: true,
			AutoRemove:      false,
		},
		NetworkingConfig: &docker.NetworkingConfig{
			EndpointsConfig: map[string]*docker.EndpointConfig{},
		},
		Context: nil,
	})
	if err != nil {
		return container, 1, "", "", err
	}
	if err := tn.Pool.Client.StartContainer(cont.ID, nil); err != nil {
		return container, 1, "", "", err
	}
	exitCode, err := tn.Pool.Client.WaitContainerWithContext(cont.ID, ctx)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	_ = tn.Pool.Client.Logs(docker.LogsOptions{
		Context:      ctx,
		Container:    cont.ID,
		OutputStream: stdout,
		ErrorStream:  stderr,
		Stdout:       true,
		Stderr:       true,
		Tail:         "100",
		Follow:       false,
		Timestamps:   false,
	})
	_ = tn.Pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: cont.ID})
	return container, exitCode, stdout.String(), stderr.String(), err
}

// InitHomeFolder initializes a home folder for the given node
func (tn *TestNode) InitHomeFolder(ctx context.Context) error {
	command := []string{tn.Chain.Bin, "init", tn.Name(),
		"--chain-id", tn.ChainID,
		"--home", tn.NodeHome(),
	}
	return handleNodeJobError(tn.NodeJob(ctx, command))
}

// CreateKey creates a key in the keyring backend test for the given node
func (tn *TestNode) CreateKey(ctx context.Context, name string) error {
	command := []string{tn.Chain.Bin, "keys", "add", name,
		"--keyring-backend", "test",
		"--output", "json",
		"--home", tn.NodeHome(),
	}
	return handleNodeJobError(tn.NodeJob(ctx, command))
}

// AddGenesisAccount adds a genesis account for each key
func (tn *TestNode) AddGenesisAccount(ctx context.Context, address string) error {
	command := []string{tn.Chain.Bin, "add-genesis-account", address, "1000000000000stake",
		"--home", tn.NodeHome(),
	}
	return handleNodeJobError(tn.NodeJob(ctx, command))
}

// Gentx generates the gentx for a given node
func (tn *TestNode) Gentx(ctx context.Context, name, pubKey string) error {
	command := []string{tn.Chain.Bin, "gentx", valKey, "100000000000stake",
		"--pubkey", pubKey,
		"--keyring-backend", "test",
		"--home", tn.NodeHome(),
		"--chain-id", tn.ChainID,
	}
	return handleNodeJobError(tn.NodeJob(ctx, command))
}

// CollectGentxs runs collect gentxs on the node's home folders
func (tn *TestNode) CollectGentxs(ctx context.Context) error {
	command := []string{tn.Chain.Bin, "collect-gentxs",
		"--home", tn.NodeHome(),
	}
	return handleNodeJobError(tn.NodeJob(ctx, command))
}

func (tn *TestNode) CreateNodeContainer(networkID string) error {
	cont, err := tn.Pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: tn.Name(),
		Config: &docker.Config{
			User:         getDockerUserString(),
			Cmd:          []string{tn.Chain.Bin, "start", "--home", tn.NodeHome()},
			Hostname:     tn.Name(),
			ExposedPorts: tn.Chain.Ports,
			DNS:          []string{},
			Image:        fmt.Sprintf("%s:%s", tn.Chain.Repository, tn.Chain.Version),
			Labels:       map[string]string{"horcrux-test": tn.tl.Name()},
		},
		HostConfig: &docker.HostConfig{
			Binds:           tn.Bind(),
			PublishAllPorts: true,
			AutoRemove:      false,
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
	tn.Container = cont
	return nil
}

func (tn *TestNode) StopContainer() error {
	return tn.Pool.Client.StopContainer(tn.Container.ID, uint(time.Second*30))
}

func (tn *TestNode) StopAndRemoveContainer(force bool) error {
	if err := tn.StopContainer(); err != nil && !force {
		return err
	}
	return tn.Pool.Client.RemoveContainer(docker.RemoveContainerOptions{
		ID:    tn.Container.ID,
		Force: force,
	})
}

func (tn *TestNode) StartContainer(ctx context.Context) error {
	if err := tn.Pool.Client.StartContainer(tn.Container.ID, nil); err != nil {
		return err
	}

	c, err := tn.Pool.Client.InspectContainer(tn.Container.ID)
	if err != nil {
		return err
	}
	tn.Container = c

	port := GetHostPort(c, "26657/tcp")
	tn.tl.Logf("{%s} RPC => %s", tn.Name(), port)

	err = tn.NewClient(fmt.Sprintf("tcp://%s", port))
	if err != nil {
		return err
	}

	time.Sleep(5 * time.Second)
	return retry.Do(func() error {
		stat, err := tn.Client.Status(ctx)
		if err != nil {
			// tn.t.Log(err)
			return err
		}
		// TODO: reenable this check, having trouble with it for some reason
		if stat != nil && stat.SyncInfo.CatchingUp {
			return fmt.Errorf("still catching up: height(%d) catching-up(%t)",
				stat.SyncInfo.LatestBlockHeight, stat.SyncInfo.CatchingUp)
		}
		return nil
	}, retry.DelayType(retry.BackOffDelay))
}

func (tn *TestNode) Bech32AddressForKey(keyName string) (string, error) {
	key, err := tn.GetKey(valKey)
	if err != nil {
		return "", err
	}
	bech32Address, err := types.Bech32ifyAddressBytes(tn.Chain.Bech32Prefix, key.GetAddress())
	if err != nil {
		return "", err
	}
	return bech32Address, nil
}

// InitValidatorFiles creates the node files and signs a genesis transaction
func (tn *TestNode) InitValidatorFiles(ctx context.Context, pubKey string) error {
	if err := tn.InitHomeFolder(ctx); err != nil {
		return err
	}
	if err := tn.CreateKey(ctx, valKey); err != nil {
		return err
	}
	bech32Address, err := tn.Bech32AddressForKey(valKey)
	if err != nil {
		return err
	}
	if err := tn.AddGenesisAccount(ctx, bech32Address); err != nil {
		return err
	}
	// if override pubkey is not provided, use the one from this TestNode
	if pubKey == "" {
		bech32Prefix := ""
		if tn.Chain.PubKeyAsBech32 {
			bech32Prefix = tn.Chain.Bech32Prefix
		}
		pv, err := tn.GetPrivVal()
		if err != nil {
			return err
		}
		pubKey, err = signer.PubKey(bech32Prefix, pv.PubKey)
		if err != nil {
			return err
		}
	}
	// some chains need additional steps, such as genesis.json modification, before executing gentx
	if tn.Chain.PreGenTx != nil {
		if err := tn.Chain.PreGenTx(tn); err != nil {
			return err
		}
	}
	return tn.Gentx(ctx, valKey, pubKey)
}

func (tn *TestNode) InitFullNodeFiles(ctx context.Context) error {
	return tn.InitHomeFolder(ctx)
}

func handleNodeJobError(container string, i int, stdout string, stderr string, err error) error {
	if err != nil {
		return fmt.Errorf("%v\n%s\n%s", err, stdout, stderr)
	}
	if i != 0 {
		return fmt.Errorf("container [%s] returned non-zero error code: %d\nstdout:\n%s\nstderr:\n%s",
			container, i, stdout, stderr)
	}
	return nil
}

// NodeID returns the node of a given node
func (tn *TestNode) NodeID() (string, error) {
	nodeKey, err := p2p.LoadNodeKey(path.Join(tn.Dir(), "config", "node_key.json"))
	if err != nil {
		return "", err
	}
	return string(nodeKey.ID()), nil
}

// GetKey gets a key, waiting until it is available
func (tn *TestNode) GetKey(name string) (info keyring.Info, err error) {
	return info, retry.Do(func() (err error) {
		info, err = tn.Keybase().Key(name)
		return err
	})
}

// RandLowerCaseLetterString returns a lowercase letter string of given length
func RandLowerCaseLetterString(length int) string {
	chars := []rune("abcdefghijklmnopqrstuvwxyz")
	var b strings.Builder
	for i := 0; i < length; i++ {
		i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b.WriteRune(chars[i.Int64()])
	}
	return b.String()
}

// TestNodes is a collection of TestNode
type TestNodes []*TestNode

// PeerString returns the string for connecting the nodes passed in
func (tn TestNodes) PeerString() string {
	bldr := new(strings.Builder)
	for _, n := range tn {
		id, err := n.NodeID()
		if err != nil {
			return bldr.String()
		}
		ps := fmt.Sprintf("%s@%s:26656,", id, n.Name())
		tn[0].tl.Logf("{%s} peering (%s)", n.Name(), strings.TrimSuffix(ps, ","))
		bldr.WriteString(ps)
	}
	return strings.TrimSuffix(bldr.String(), ",")
}

// Peers returns the peer nodes for a given node if it is included in a set of nodes
func (tn TestNodes) Peers(node *TestNode) (out TestNodes) {
	for _, n := range tn {
		if n.Index != node.Index {
			out = append(out, n)
		}
	}
	return
}

func (tn TestNodes) ListenAddrs() string {
	out := []string{}
	for _, n := range tn {
		out = append(out, fmt.Sprintf("%s:%s", n.Name(), "1234"))
	}
	return strings.Join(out, ",")
}

// LogGenesisHashes logs the genesis hashes for the various nodes
func (tn TestNodes) LogGenesisHashes() error {
	for _, n := range tn {
		gen, err := os.ReadFile(n.GenesisFilePath())
		if err != nil {
			return err
		}
		tn[0].tl.Log(fmt.Sprintf("{%s} genesis hash %x", n.Name(), sha256.Sum256(gen)))
	}
	return nil
}

func (tn TestNodes) WaitForHeight(height int64) error {
	var eg errgroup.Group
	tn[0].tl.Logf("Waiting For Nodes To Reach Block Height %d...", height)
	for _, n := range tn {
		n := n
		eg.Go(func() error {
			return retry.Do(func() error {
				stat, err := n.Client.Status(context.Background())
				if err != nil {
					return err
				}

				if stat.SyncInfo.CatchingUp || stat.SyncInfo.LatestBlockHeight < height {
					return fmt.Errorf("node still under block %d: %d", height, stat.SyncInfo.LatestBlockHeight)
				}
				n.tl.Logf("{%s} => reached block %d\n", n.Name(), height)
				return nil
				// TODO: setup backup delay here
			}, retry.DelayType(retry.BackOffDelay), retry.Attempts(15))
		})
	}
	return eg.Wait()
}

func (tn *TestNode) GetPrivVal() (privval.FilePVKey, error) {
	return signer.ReadPrivValidatorFile(tn.privValKeyPath())
}

func (tn *TestNode) privValKeyPath() string {
	return path.Join(tn.Dir(), "config", "priv_validator_key.json")
}

func (tn *TestNode) privValStatePath() string {
	return path.Join(tn.Dir(), "config", "priv_validator_state.json")
}

func (tn *TestNode) GenNewPrivVal() {
	_ = os.Remove(tn.privValKeyPath())
	_ = os.Remove(tn.privValStatePath())
	newFilePV := privval.GenFilePV(tn.privValKeyPath(), tn.privValStatePath())
	newFilePV.Save()
}

func getDockerUserString() string {
	uid := os.Getuid()
	var usr string
	userOS := runtime.GOOS
	if userOS == "darwin" {
		usr = ""
	} else {
		usr = fmt.Sprintf("%d:%d", uid, uid)
	}
	return usr
}
