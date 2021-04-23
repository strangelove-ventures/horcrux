package testing

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	tmconfig "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/p2p"
)

var (
	valKey = "validator"
)

// ChainType represents the type of chain to instantiate
type ChainType struct {
	Repository string
	Version    string
	Bin        string
	Ports      []string
}

// ChainType instance for simd
var simdChain = &ChainType{
	Repository: "jackzampolin/simd",
	Version:    "v0.42.3",
	Bin:        "simd",
	Ports:      []string{"26656", "26657", "9090", "1317"},
}

// TestNode represents a node in the test network that is being created
type TestNode struct {
	Home    string
	Index   int
	ChainID string
	Chain   *ChainType
	Pool    *dockertest.Pool
}

// MakeTestNodes create the test node objects required for bootstrapping tests
func MakeTestNodes(count int, home, chainid string, chainType *ChainType, pool *dockertest.Pool) (out []*TestNode) {
	for i := 0; i < count; i++ {
		tn := &TestNode{Home: home, Index: i, Chain: chainType, ChainID: chainid, Pool: pool}
		tn.MkDir()
		out = append(out, tn)
	}
	return
}

// Name is the hostname of the test node container
func (tn *TestNode) Name() string {
	return fmt.Sprintf("node-%d", tn.Index)
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
func (tn *TestNode) GentxPath() string {
	return path.Join(tn.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", tn.NodeID()))
}

func (tn *TestNode) GenesisFilePath() string {
	return path.Join(tn.Dir(), "config", "genesis.json")
}

func (tn *TestNode) TMConfigPath() string {
	return path.Join(tn.Dir(), "config", "config.toml")
}

// Bind returns the home folder bind point for running the node
func (tn *TestNode) Bind() []string {
	return []string{fmt.Sprintf("%s:/root/.%s/", tn.Dir(), tn.Chain.Bin)}
}

// Keybase returns the keyring for a given node
func (tn *TestNode) Keybase() keyring.Keyring {
	kr, err := keyring.New("", keyring.BackendTest, tn.Dir(), os.Stdin)
	if err != nil {
		panic(err)
	}
	return kr
}

// ModifyConfig modifies the config for a validator node to start a chain
func (tn *TestNode) ModifyConfig(peers TestNodes) error {
	// Pull current config
	cfg := tmconfig.DefaultConfig()
	// turn down blocktimes to make the chain faster
	cfg.Consensus.TimeoutCommit = 1 * time.Second
	cfg.Consensus.TimeoutPropose = 1 * time.Second

	// Open up rpc address
	cfg.RPC.ListenAddress = "tcp://0.0.0.0:26657"

	// Allow for some p2p weirdness
	cfg.P2P.AllowDuplicateIP = true
	cfg.P2P.AddrBookStrict = false

	// Set log level to info
	cfg.BaseConfig.LogLevel = "info"

	// set persistent peer nodes
	cfg.P2P.PersistentPeers = peers.PeerString()

	// overwrite with the new config
	tmconfig.WriteConfigFile(tn.TMConfigPath(), cfg)
	return nil
}

// InitHomeFolder initializes a home folder for the given node
func (tn *TestNode) InitHomeFolder() error {
	// NOTE: on job containers generate random name
	container := RandLowerCaseLetterString(10)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     container,
		Name:         container,
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "init", tn.Name(), "--chain-id", tn.ChainID, "--home", "/root/.simd"},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	}, func(hc *docker.HostConfig) { hc.AutoRemove = true })
	return err
}

// CreateKey creates a key in the keyring backend test for the given node
func (tn *TestNode) CreateKey(name string) error {
	// NOTE: on job containers generate random name
	container := RandLowerCaseLetterString(10)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     container,
		Name:         container,
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "keys", "add", name, "--keyring-backend", "test", "--home", "/root/.simd"},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	}, func(hc *docker.HostConfig) { hc.AutoRemove = true })
	return err
}

// AddGenesisAccount adds a genesis account for each key
func (tn *TestNode) AddGenesisAccount(address string) error {
	// NOTE: on job containers generate random name
	container := RandLowerCaseLetterString(10)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     container,
		Name:         container,
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "add-genesis-account", address, "1000000000000stake", "--home", "/root/.simd"},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	}, func(hc *docker.HostConfig) { hc.AutoRemove = true })
	return err
}

// Gentx generates the gentx for a given node
func (tn *TestNode) Gentx(name string) error {
	// NOTE: on job containers generate random name
	container := RandLowerCaseLetterString(10)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     container,
		Name:         container,
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "gentx", valKey, "100000000000stake", "--keyring-backend", "test", "--home", "/root/.simd", "--chain-id", tn.ChainID},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	}, func(hc *docker.HostConfig) { hc.AutoRemove = true })
	return err
}

func (tn *TestNode) StartNode() error {
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     tn.Name(),
		Name:         tn.Name(),
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "start", "--home", "/root/.simd"},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	})
	return err
}

func (tn *TestNode) CollectGentxs() error {
	// NOTE: on job containers generate random name
	container := RandLowerCaseLetterString(10)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     container,
		Name:         container,
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "collect-gentxs", "--home", "/root/.simd"},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	}, func(hc *docker.HostConfig) { hc.AutoRemove = true })
	return err
}

func (tn *TestNode) InitNodeFilesAndGentx() error {
	if err := tn.InitHomeFolder(); err != nil {
		return err
	}
	if err := tn.CreateKey(valKey); err != nil {
		return err
	}
	if err := tn.AddGenesisAccount(tn.GetKey(valKey).GetAddress().String()); err != nil {
		return err
	}
	if err := tn.Gentx(valKey); err != nil {
		return err
	}
	return tn.WaitForGentx()
}

// NodeID returns the node of a given node
func (tn *TestNode) NodeID() string {
	nodeKey, err := p2p.LoadNodeKey(path.Join(tn.Dir(), "config", "node_key.json"))
	if err != nil {
		panic(err)
	}
	return string(nodeKey.ID())
}

// KeysList lists the keys in a keychain
func (tn *TestNode) KeysList() []keyring.Info {
	out, err := tn.Keybase().List()
	if err != nil {
		panic(err)
	}
	return out
}

// WaitForGentx waits for the gentx to be be complete
func (tn *TestNode) WaitForGentx() error {
	return retry.Do(func() error {
		if _, err := os.Stat(path.Join(tn.Dir(), "config", "gentx")); os.IsNotExist(err) {
			return err
		}
		return nil
	})
}

// GetKey gets a key, waiting until it is available
func (tn *TestNode) GetKey(name string) keyring.Info {
	kb := tn.Keybase()
	var info keyring.Info
	var err error
	err = retry.Do(func() (err error) {
		info, err = kb.Key(name)
		return err
	})
	if err != nil {
		panic(err)
	}
	return info
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

// PeerString returns the peer identifiers for a given set of nodes
func (tn TestNodes) PeerString() string {
	out := []string{}
	for _, n := range tn {
		out = append(out, fmt.Sprintf("%s@%s:%s", n.NodeID(), n.Name(), "26656"))
	}
	return strings.Join(out, ",")
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
