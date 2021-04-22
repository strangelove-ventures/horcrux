package testing

import (
	"fmt"
	"os"
	"path"

	"github.com/avast/retry-go"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/tendermint/tendermint/p2p"
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

// InitHomeFolder initializes a home folder for the given node
func (tn *TestNode) InitHomeFolder() error {
	name := fmt.Sprintf("init-%d", tn.Index)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     name,
		Name:         name,
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
	container := fmt.Sprintf("key-add-%d", tn.Index)
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
func (tn *TestNode) AddGenesisAccount(name string) error {
	container := fmt.Sprintf("aga-%d", tn.Index)
	val := tn.GetKey(name)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     container,
		Name:         container,
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "add-genesis-account", val.GetAddress().String(), "1000000000000stake", "--home", "/root/.simd"},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	}, func(hc *docker.HostConfig) { hc.AutoRemove = true })
	return err
}

// Gentx generates the gentx for a given node
func (tn *TestNode) Gentx(name string) error {
	container := fmt.Sprintf("gentx-%d", tn.Index)
	_, err := tn.Pool.RunWithOptions(&dockertest.RunOptions{
		Hostname:     container,
		Name:         container,
		Repository:   tn.Chain.Repository,
		Tag:          tn.Chain.Version,
		Cmd:          []string{tn.Chain.Bin, "gentx", "validator", "100000000000stake", "--keyring-backend", "test", "--home", "/root/.simd"},
		Mounts:       tn.Bind(),
		ExposedPorts: tn.Chain.Ports,
	}, func(hc *docker.HostConfig) { hc.AutoRemove = true })
	return err
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
