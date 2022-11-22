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
type DiskConfig struct {
	PrivValKeyFile *string         `json:"key-file,omitempty" yaml:"key-file,omitempty"`
	CosignerConfig *CosignerConfig `json:"cosigner,omitempty" yaml:"cosigner,omitempty"`
	ChainNodes     ChainNodes      `json:"chain-nodes,omitempty" yaml:"chain-nodes,omitempty"`
	DebugAddr      string          `json:"debug-addr,omitempty" yaml:"debug-addr,omitempty"`
}

func (c *DiskConfig) Nodes() (out []string) {
	for _, n := range c.ChainNodes {
		out = append(out, n.PrivValAddr)
	}
	return out
}

func (c *DiskConfig) MustMarshalYaml() []byte {
	out, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	return out
}

func (c *DiskConfig) CosignerPeers() (out []CosignerParams) {
	for _, p := range c.CosignerConfig.Peers {
		out = append(out, CosignerParams{ID: p.ShareID, Address: p.P2PAddr})
	}
	return
}

func (c *DiskConfig) ValidateSingleSignerConfig() error {
	if len(c.ChainNodes) == 0 {
		return fmt.Errorf("need to have a node configured to sign for")
	}
	if err := c.ChainNodes.Validate(); err != nil {
		return err
	}
	return nil
}

func (c *DiskConfig) ValidateCosignerConfig() error {
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
		return fmt.Errorf("%s is not a valid duration string for --timeout ", c.CosignerConfig.Timeout)
	}
	if _, err := url.Parse(c.CosignerConfig.P2PListen); err != nil {
		return fmt.Errorf("failed to parse p2p listen address")
	}
	if err := ValidateCosignerPeers(c.CosignerConfig.Peers, c.CosignerConfig.Shares); err != nil {
		return err
	}
	if err := c.ChainNodes.Validate(); err != nil {
		return err
	}
	return nil
}

type RuntimeConfig struct {
	HomeDir    string
	ConfigFile string
	StateDir   string
	PidFile    string
	Config     DiskConfig
}

func (c RuntimeConfig) KeyFilePath(cosigner bool) string {
	if c.Config.PrivValKeyFile != nil && *c.Config.PrivValKeyFile != "" {
		return *c.Config.PrivValKeyFile
	}
	if cosigner {
		return filepath.Join(c.HomeDir, "share.json")
	}
	return filepath.Join(c.HomeDir, "priv_validator_key.json")
}

func (c RuntimeConfig) PrivValStateFile(chainID string) string {
	return filepath.Join(c.StateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))
}

func (c RuntimeConfig) ShareStateFile(chainID string) string {
	return filepath.Join(c.StateDir, fmt.Sprintf("%s_share_sign_state.json", chainID))
}

func (c RuntimeConfig) WriteConfigFile() error {
	return os.WriteFile(c.ConfigFile, c.Config.MustMarshalYaml(), 0644) //nolint
}

func (c RuntimeConfig) KeyFileExists(cosigner bool) error {
	keyFile := c.KeyFilePath(cosigner)
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return fmt.Errorf("private key share doesn't exist at path(%s)", keyFile)
	}
	return nil
}

type CosignerConfig struct {
	Threshold int                  `json:"threshold"   yaml:"threshold"`
	Shares    int                  `json:"shares" yaml:"shares"`
	P2PListen string               `json:"p2p-listen"  yaml:"p2p-listen"`
	Peers     []CosignerPeerConfig `json:"peers"       yaml:"peers"`
	Timeout   string               `json:"rpc-timeout" yaml:"rpc-timeout"`
}

type CosignerParams struct {
	ID      int
	Address string
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

func ValidateCosignerPeers(peers []CosignerPeerConfig, shares int) error {
	// Check IDs to make sure none are duplicated
	if dupl := duplicatePeers(peers); len(dupl) != 0 {
		return fmt.Errorf("found duplicate share IDs in args: %v", dupl)
	}

	// Make sure that the peers' IDs match the number of shares.
	for _, peer := range peers {
		if peer.ShareID < 1 || peer.ShareID > shares {
			return fmt.Errorf("peer ID %v in args is out of range, must be between 1 and %v",
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

func duplicatePeers(peers []CosignerPeerConfig) (duplicates []CosignerPeerConfig) {
	encountered := make(map[int]string)
	for _, peer := range peers {
		if _, found := encountered[peer.ShareID]; !found {
			encountered[peer.ShareID] = peer.P2PAddr
		} else {
			duplicates = append(duplicates, CosignerPeerConfig{peer.ShareID, peer.P2PAddr})
		}
	}
	return
}

func PeersFromFlag(peers string) (out []CosignerPeerConfig, err error) {
	for _, p := range strings.Split(peers, ",") {
		ps := strings.Split(p, "|")
		if len(ps) != 2 {
			return nil, fmt.Errorf("invalid peer string %s", p)
		}
		shareid, err := strconv.ParseInt(ps[1], 10, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, CosignerPeerConfig{ShareID: int(shareid), P2PAddr: ps[0]})
	}
	return
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

func ChainNodesFromArg(arg string) (out []ChainNode, err error) {
	for _, n := range strings.Split(arg, ",") {
		cn := ChainNode{PrivValAddr: n}
		if err := cn.Validate(); err != nil {
			return nil, err
		}
		out = append(out, cn)
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
