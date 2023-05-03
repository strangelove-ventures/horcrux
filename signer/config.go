package signer

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/legacy"
	"github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/strangelove-ventures/horcrux/client"
	"gopkg.in/yaml.v2"
)

type NodeConfig struct {
	Address string
}

// Config maps to the on-disk JSON format
type Config struct {
	PrivValKeyDir  *string         `json:"key-dir,omitempty" yaml:"key-dir,omitempty"`
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
	var errs []error
	if len(c.ChainNodes) == 0 {
		errs = append(errs, fmt.Errorf("need to have chain-nodes configured for priv-val connection"))
	}
	if err := c.ChainNodes.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (c *Config) ValidateCosignerConfig() error {
	var errs []error
	if err := c.ValidateSingleSignerConfig(); err != nil {
		errs = append(errs, err)
	}
	if c.CosignerConfig == nil {
		errs = append(errs, fmt.Errorf("cosigner config can't be empty"))
		// the rest of the checks depend on non-nil c.CosignerConfig
		return errors.Join(errs...)
	}
	shares := len(c.CosignerConfig.Peers)
	if c.CosignerConfig.Threshold <= shares/2 {
		errs = append(errs, fmt.Errorf("threshold (%d) must be greater than number of shares (%d) / 2",
			c.CosignerConfig.Threshold, shares))
	}
	if shares < c.CosignerConfig.Threshold {
		errs = append(errs, fmt.Errorf("number of shares (%d) must be greater or equal to threshold (%d)",
			shares, c.CosignerConfig.Threshold))
	}

	_, err := time.ParseDuration(c.CosignerConfig.Timeout)
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid --timeout: %w", err))
	}
	if err := c.CosignerConfig.Peers.Validate(shares); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type RuntimeConfig struct {
	HomeDir    string
	ConfigFile string
	StateDir   string
	PidFile    string
	Config     Config
}

func (c RuntimeConfig) cachedKeyDirectory() string {
	if c.Config.PrivValKeyDir != nil {
		return *c.Config.PrivValKeyDir
	}
	return ""
}

func (c RuntimeConfig) KeyFilePathSingleSigner(chainID string) string {
	keyDir := c.HomeDir
	if kd := c.cachedKeyDirectory(); kd != "" {
		keyDir = kd
	}
	return filepath.Join(keyDir, fmt.Sprintf("%s_priv_validator_key.json", chainID))
}

func (c RuntimeConfig) KeyFilePathCosigner(chainID string) string {
	keyDir := c.HomeDir
	if kd := c.cachedKeyDirectory(); kd != "" {
		keyDir = kd
	}
	return filepath.Join(keyDir, fmt.Sprintf("%s_share.json", chainID))
}

func (c RuntimeConfig) KeyFilePathCosignerRSA() string {
	keyDir := c.HomeDir
	if kd := c.cachedKeyDirectory(); kd != "" {
		keyDir = kd
	}
	return filepath.Join(keyDir, "rsa_keys.json")
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

func (c RuntimeConfig) KeyFileExistsSingleSigner(chainID string) (string, error) {
	keyFile := c.KeyFilePathSingleSigner(chainID)
	return keyFile, fileExists(keyFile)
}

func (c RuntimeConfig) KeyFileExistsCosigner(chainID string) (string, error) {
	keyFile := c.KeyFilePathCosigner(chainID)
	return keyFile, fileExists(keyFile)
}

func (c RuntimeConfig) KeyFileExistsCosignerRSA() (string, error) {
	keyFile := c.KeyFilePathCosignerRSA()
	return keyFile, fileExists(keyFile)
}

type CosignerConfig struct {
	Threshold int                 `json:"threshold"   yaml:"threshold"`
	Peers     CosignerPeersConfig `json:"peers"       yaml:"peers"`
	Timeout   string              `json:"rpc-timeout" yaml:"rpc-timeout"`
}

func (cfg *CosignerConfig) LeaderElectMultiAddress() (string, error) {
	addresses := make([]string, len(cfg.Peers))
	for i, peer := range cfg.Peers {
		addresses[i] = peer.P2PAddr
	}
	return client.MultiAddress(addresses)
}

type CosignerPeerConfig struct {
	ShareID int    `json:"share-id" yaml:"share-id"`
	P2PAddr string `json:"p2p-addr" yaml:"p2p-addr"`
}

type CosignerPeersConfig []CosignerPeerConfig

func (peers CosignerPeersConfig) Validate(shares int) error {
	var errs []error
	// Check IDs to make sure none are duplicated
	if dupl := duplicatePeers(peers); len(dupl) != 0 {
		errs = append(errs, fmt.Errorf("found duplicate share IDs in args: %v", dupl))
	}

	// Make sure that the peers' IDs match the number of shares.
	for _, peer := range peers {
		if peer.ShareID < 1 || peer.ShareID > shares {
			errs = append(errs, fmt.Errorf("peer ID %d in args is out of range, must be between 1 and %d, inclusive",
				peer.ShareID, shares))
		}

		url, err := url.Parse(peer.P2PAddr)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse peer %d p2p address: %w", peer.ShareID, err))
			continue
		}

		host, _, err := net.SplitHostPort(url.Host)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse peer %d host port: %w", peer.ShareID, err))
			continue
		}
		if host == "0.0.0.0" {
			errs = append(errs, fmt.Errorf("host cannot be 0.0.0.0, must be reachable from other peers"))
		}
	}

	// Check that exactly {num-shares}-1 peers are in the peer list, assuming
	// the remaining peer ID is the ID the local node is configured with.
	if len(peers) != shares {
		errs = append(errs, fmt.Errorf("incorrect number of peers. expected (%d shares = %d peers)",
			shares, shares))
	}

	return errors.Join(errs...)
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
	var errs []error
	for _, p := range peers {
		ps := strings.Split(p, "|")
		if len(ps) != 2 {
			errs = append(errs, fmt.Errorf("invalid peer string %s, expected format: tcp://{addr}:{port}|{share-id}", p))
			continue
		}
		shareid, err := strconv.ParseInt(ps[1], 10, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse share ID: %w", err))
			continue
		}
		out = append(out, CosignerPeerConfig{ShareID: int(shareid), P2PAddr: ps[0]})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
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
	var errs []error
	for _, cn := range cns {
		if err := cn.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
