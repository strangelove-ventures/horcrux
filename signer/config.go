package signer

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/legacy"
	"github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/strangelove-ventures/horcrux/client"
	"github.com/tendermint/tendermint/crypto"
	"gopkg.in/yaml.v2"
)

type NodeConfig struct {
	Address string
}

// Config maps to the on-disk JSON format
type Config struct {
	PrivValKeyFile *string         `json:"key-file,omitempty" yaml:"key-file,omitempty"`
	CosignerConfig *CosignerConfig `json:"cosigner,omitempty" yaml:"cosigner,omitempty"`
	ChainNodes     ChainNodes      `json:"chain-nodes,omitempty" yaml:"chain-nodes,omitempty"`
	DebugAddr      string          `json:"debug-addr,omitempty" yaml:"debug-addr,omitempty"`
}

func (c *Config) Nodes() (out []string) {
	for _, n := range c.ChainNodes {
		out = append(out, n.PrivValAddr)
	}
	return out
}

func (c *Config) MustMarshalYaml() []byte {
	out, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	return out
}

func (c *Config) ValidateSingleSignerConfig() error {
	if len(c.ChainNodes) == 0 {
		return fmt.Errorf("need to have chain-nodes configured for priv-val connection")
	}
	if err := c.ChainNodes.Validate(); err != nil {
		return err
	}
	return nil
}

func (c *Config) ValidateCosignerConfig() error {
	if err := c.ValidateSingleSignerConfig(); err != nil {
		return err
	}
	if c.CosignerConfig == nil {
		return fmt.Errorf("cosigner config can't be empty")
	}
	if c.CosignerConfig.Threshold <= c.CosignerConfig.Shares/2 {
		return fmt.Errorf("threshold (%d) must be greater than number of shares (%d) / 2",
			c.CosignerConfig.Threshold, c.CosignerConfig.Shares)
	}
	if c.CosignerConfig.Shares < c.CosignerConfig.Threshold {
		return fmt.Errorf("number of shares (%d) must be greater or equal to threshold (%d)",
			c.CosignerConfig.Shares, c.CosignerConfig.Threshold)
	}

	_, err := time.ParseDuration(c.CosignerConfig.Timeout)
	if err != nil {
		return fmt.Errorf("invalid --timeout: %w", err)
	}
	if _, err := url.Parse(c.CosignerConfig.P2PListen); err != nil {
		return fmt.Errorf("failed to parse p2p listen address: %w", err)
	}
	if err := c.CosignerConfig.Peers.Validate(c.CosignerConfig.Shares); err != nil {
		return err
	}
	return nil
}

type RuntimeConfig struct {
	HomeDir    string
	ConfigFile string
	StateDir   string
	PidFile    string
	Config     Config
}

func (c RuntimeConfig) cachedKeyFile() string {
	if c.Config.PrivValKeyFile != nil {
		return *c.Config.PrivValKeyFile
	}
	return ""
}

func (c RuntimeConfig) KeyFilePathSingleSigner() string {
	if kf := c.cachedKeyFile(); kf != "" {
		return kf
	}
	return filepath.Join(c.HomeDir, "priv_validator_key.json")
}

func (c RuntimeConfig) KeyFilePathCosigner() string {
	if kf := c.cachedKeyFile(); kf != "" {
		return kf
	}
	return filepath.Join(c.HomeDir, "share.json")
}

func (c RuntimeConfig) PrivValStateFile(chainID string) string {
	return filepath.Join(c.StateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))
}

func (c RuntimeConfig) ShareStateFile(chainID string) string {
	return filepath.Join(c.StateDir, fmt.Sprintf("%s_share_sign_state.json", chainID))
}

func (c RuntimeConfig) WriteConfigFile() error {
	return os.WriteFile(c.ConfigFile, c.Config.MustMarshalYaml(), 0600)
}

func fileExists(file string) error {
	stat, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file doesn't exist at path (%s): %w", file, err)
		}
		return fmt.Errorf("unexpected error checking file existence (%s): %w", file, err)
	}
	if stat.IsDir() {
		return fmt.Errorf("path is not a file (%s)", file)
	}

	return nil
}

func (c RuntimeConfig) KeyFileExistsSingleSigner() (string, error) {
	keyFile := c.KeyFilePathSingleSigner()
	return keyFile, fileExists(keyFile)
}

func (c RuntimeConfig) KeyFileExistsCosigner() (string, error) {
	keyFile := c.KeyFilePathCosigner()
	return keyFile, fileExists(keyFile)
}

type CosignerConfig struct {
	Threshold int                 `json:"threshold"   yaml:"threshold"`
	Shares    int                 `json:"shares" yaml:"shares"`
	P2PListen string              `json:"p2p-listen"  yaml:"p2p-listen"`
	Peers     CosignerPeersConfig `json:"peers"       yaml:"peers"`
	Timeout   string              `json:"rpc-timeout" yaml:"rpc-timeout"`
}

func (cfg *CosignerConfig) LeaderElectMultiAddress() (string, error) {
	addresses := make([]string, 1+len(cfg.Peers))
	addresses[0] = cfg.P2PListen
	for i, peer := range cfg.Peers {
		addresses[i+1] = peer.P2PAddr
	}
	return client.MultiAddress(addresses)
}

type CosignerPeerConfig struct {
	ShareID int    `json:"share-id" yaml:"share-id"`
	P2PAddr string `json:"p2p-addr" yaml:"p2p-addr"`
}

type CosignerPeersConfig []CosignerPeerConfig

func (peers CosignerPeersConfig) Validate(shares int) error {
	// Check IDs to make sure none are duplicated
	if dupl := duplicatePeers(peers); len(dupl) != 0 {
		return fmt.Errorf("found duplicate share IDs in args: %v", dupl)
	}

	// Make sure that the peers' IDs match the number of shares.
	for _, peer := range peers {
		if peer.ShareID < 1 || peer.ShareID > shares {
			return fmt.Errorf("peer ID %v in args is out of range, must be between 1 and %v, inclusive",
				peer.ShareID, shares)
		}
	}

	// Check that exactly {num-shares}-1 peers are in the peer list, assuming
	// the remaining peer ID is the ID the local node is configured with.
	if len(peers) != shares-1 {
		return fmt.Errorf("incorrect number of peers. expected (%d shares - local node = %d peers)",
			shares, shares-1)
	}
	return nil
}

func duplicatePeers(peers []CosignerPeerConfig) (duplicates map[int][]string) {
	idAddrs := make(map[int][]string)
	for _, peer := range peers {
		// Collect all addresses assigned to each share ID.
		idAddrs[peer.ShareID] = append(idAddrs[peer.ShareID], peer.P2PAddr)
	}

	for shareID, peers := range idAddrs {
		if len(peers) == 1 {
			// One address per ID is correct.
			delete(idAddrs, shareID)
		}
	}

	if len(idAddrs) == 0 {
		// No duplicates, return nil for simple check by caller.
		return nil
	}

	// Non-nil result: there were duplicates.
	return idAddrs
}

func PeersFromFlag(peers []string) (out []CosignerPeerConfig, err error) {
	for _, p := range peers {
		ps := strings.Split(p, "|")
		if len(ps) != 2 {
			return nil, fmt.Errorf("invalid peer string %s, expected format: tcp://{addr}:{port}|{share-id}", p)
		}
		shareid, err := strconv.ParseInt(ps[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse share ID: %w", err)
		}
		out = append(out, CosignerPeerConfig{ShareID: int(shareid), P2PAddr: ps[0]})
	}
	return out, nil
}

type ChainNode struct {
	PrivValAddr string `json:"priv-val-addr" yaml:"priv-val-addr"`
}

func (cn ChainNode) Validate() error {
	_, err := url.Parse(cn.PrivValAddr)
	return err
}

type ChainNodes []ChainNode

func (cns ChainNodes) Validate() error {
	for _, cn := range cns {
		if err := cn.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func ChainNodesFromArg(arg string) (out ChainNodes, err error) {
	for _, n := range strings.Split(arg, ",") {
		cn := ChainNode{PrivValAddr: n}
		out = append(out, cn)
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

func PubKey(bech32BasePrefix string, pubKey crypto.PubKey) (string, error) {
	if bech32BasePrefix != "" {
		pubkey, err := cryptocodec.FromTmPubKeyInterface(pubKey)
		if err != nil {
			return "", err
		}
		consPubPrefix := bech32BasePrefix + "valconspub"
		pubKeyBech32, err := bech32.ConvertAndEncode(consPubPrefix, legacy.Cdc.Amino.MustMarshalBinaryBare(pubkey))
		if err != nil {
			return "", err
		}
		return pubKeyBech32, nil
	}

	registry := types.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(registry)
	var pk *cryptotypes.PubKey
	registry.RegisterInterface("cosmos.crypto.PubKey", pk)
	registry.RegisterImplementations(pk, &ed25519.PubKey{})
	sdkPK, err := cryptocodec.FromTmPubKeyInterface(pubKey)
	if err != nil {
		return "", err
	}
	pubKeyJSON, err := marshaler.MarshalInterfaceJSON(sdkPK)
	if err != nil {
		return "", err
	}
	return string(pubKeyJSON), nil
}
