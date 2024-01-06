package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
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

type SignMode string

const (
	SignModeThreshold SignMode = "threshold"
	SignModeSingle    SignMode = "single"

	/*
		Default values for the nouncecahce
	*/
	// TODO: Is this the best way to do this?
	DefaultGetNoncesInterval = 3 * time.Second
	DefaultGetNoncesTimeout  = 4 * time.Second
	DefaultNonceExpiration   = 10 * time.Second // half of the local cosigner cache expiration

)

// Config maps to the on-disk yaml format
type Config struct {
	PrivValKeyDir       *string              `yaml:"keyDir,omitempty"`
	SignMode            SignMode             `yaml:"signMode"`
	ThresholdModeConfig *ThresholdModeConfig `yaml:"thresholdMode,omitempty"`
	ChainNodes          ChainNodes           `yaml:"chainNodes"`
	DebugAddr           string               `yaml:"debugAddr"`
	GRPCAddr            string               `yaml:"grpcAddr"`
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
	return c.ChainNodes.Validate()
}

func (c *Config) ValidateThresholdModeConfig() error {
	if err := c.ValidateSingleSignerConfig(); err != nil {
		return err
	}

	if c.ThresholdModeConfig == nil {
		return fmt.Errorf("cosigner config can't be empty")
		// the rest of the checks depend on non-nil c.ThresholdModeConfig
	}

	numShards := len(c.ThresholdModeConfig.Cosigners)

	if c.ThresholdModeConfig.Threshold <= numShards/2 {
		return fmt.Errorf("threshold (%d) must be greater than number of shards (%d) / 2",
			c.ThresholdModeConfig.Threshold, numShards)
	}

	if numShards < c.ThresholdModeConfig.Threshold {
		return fmt.Errorf("number of shards (%d) must be greater or equal to threshold (%d)",
			numShards, c.ThresholdModeConfig.Threshold)
	}

	if _, err := time.ParseDuration(c.ThresholdModeConfig.RaftTimeout); err != nil {
		return fmt.Errorf("invalid raftTimeout: %w", err)
	}

	if _, err := time.ParseDuration(c.ThresholdModeConfig.GRPCTimeout); err != nil {
		return fmt.Errorf("invalid grpcTimeout: %w", err)
	}

	if err := c.ThresholdModeConfig.Cosigners.Validate(); err != nil {
		return err
	}

	return c.ThresholdModeConfig.Cosigners.Validate()
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
	return filepath.Join(keyDir, fmt.Sprintf("%s_shard.json", chainID))
}

func (c RuntimeConfig) KeyFilePathCosignerRSA() string {
	keyDir := c.HomeDir
	if kd := c.cachedKeyDirectory(); kd != "" {
		keyDir = kd
	}
	return filepath.Join(keyDir, "rsa_keys.json")
}

func (c RuntimeConfig) KeyFilePathCosignerECIES() string {
	keyDir := c.HomeDir
	if kd := c.cachedKeyDirectory(); kd != "" {
		keyDir = kd
	}
	return filepath.Join(keyDir, "ecies_keys.json")
}

func (c RuntimeConfig) PrivValStateFile(chainID string) string {
	return filepath.Join(c.StateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))
}

func (c RuntimeConfig) CosignerStateFile(chainID string) string {
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

func (c RuntimeConfig) KeyFileExistsCosignerECIES() (string, error) {
	keyFile := c.KeyFilePathCosignerECIES()
	return keyFile, fileExists(keyFile)
}

// ThresholdModeConfig is the on disk config format for threshold sign mode.
type ThresholdModeConfig struct {
	Threshold   int             `yaml:"threshold"`
	Cosigners   CosignersConfig `yaml:"cosigners"`
	GRPCTimeout string          `yaml:"grpcTimeout"`
	RaftTimeout string          `yaml:"raftTimeout"`
}

func (cfg *ThresholdModeConfig) LeaderElectMultiAddress() (string, error) {
	addresses := make([]string, len(cfg.Cosigners))
	for i, c := range cfg.Cosigners {
		addresses[i] = c.P2PAddr
	}
	return client.MultiAddress(addresses)
}

// CosignerConfig is the on disk format representing a cosigner for threshold sign mode.
type CosignerConfig struct {
	ShardID int    `yaml:"shardID"`
	P2PAddr string `yaml:"p2pAddr"`
}

type CosignersConfig []CosignerConfig

func (cosigners CosignersConfig) Validate() error {
	// Check IDs to make sure none are duplicated
	if dupl := duplicateCosigners(cosigners); len(dupl) != 0 {
		return fmt.Errorf("found duplicate cosigner shard Index(s) in args: %v", dupl)
	}

	shards := len(cosigners)

	// Make sure that the cosigner IDs match the number of cosigners.
	for _, cosigner := range cosigners {
		if cosigner.ShardID < 1 || cosigner.ShardID > shards {
			return fmt.Errorf("cosigner shard Index %d in args is out of range, must be between 1 and %d, inclusive",
				cosigner.ShardID, shards)
		}

		url, err := url.Parse(cosigner.P2PAddr)
		if err != nil {
			return fmt.Errorf("failed to parse cosigner (shard Index: %d) p2p address: %w", cosigner.ShardID, err)
		}

		host, _, err := net.SplitHostPort(url.Host)
		if err != nil {
			return fmt.Errorf("failed to parse cosigner (shard Index: %d) host port: %w", cosigner.ShardID, err)
		}

		if host == "0.0.0.0" {
			return fmt.Errorf("host cannot be 0.0.0.0, must be reachable from other cosigners")
		}
	}

	// Check that exactly {num-shards} cosigners are in the list
	if len(cosigners) != shards {
		return fmt.Errorf("incorrect number of cosigners. expected (%d shards = %d cosigners)",
			shards, shards)
	}

	return nil
}

func duplicateCosigners(cosigners []CosignerConfig) (duplicates map[int][]string) {
	idAddrs := make(map[int][]string)
	for _, cosigner := range cosigners {
		// Collect all addresses assigned to each cosigner.
		idAddrs[cosigner.ShardID] = append(idAddrs[cosigner.ShardID], cosigner.P2PAddr)
	}

	for shardID, cosigners := range idAddrs {
		if len(cosigners) == 1 {
			// One address per Index is correct.
			delete(idAddrs, shardID)
		}
	}

	if len(idAddrs) == 0 {
		// No duplicates, return nil for simple check by caller.
		return nil
	}

	// Non-nil result: there were duplicates.
	return idAddrs
}

func CosignersFromFlag(cosigners []string) (out []CosignerConfig, err error) {
	var errs []error
	for i, c := range cosigners {
		out = append(out, CosignerConfig{ShardID: i + 1, P2PAddr: c})
	}
	if len(errs) > 0 {
		return nil, nil
	}
	return out, nil
}

type ChainNode struct {
	PrivValAddr string `json:"privValAddr" yaml:"privValAddr"`
}

func (cn ChainNode) Validate() error {
	_, err := url.Parse(cn.PrivValAddr)
	return err
}

type ChainNodes []ChainNode

func (cns ChainNodes) Validate() error {
	if cns == nil {
		return nil
	}
	for _, cn := range cns {
		if err := cn.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func ChainNodesFromFlag(nodes []string) (ChainNodes, error) {
	out := make(ChainNodes, len(nodes))
	for i, n := range nodes {
		cn := ChainNode{PrivValAddr: n}
		out[i] = cn
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

func PubKey(bech32BasePrefix string, pubKey crypto.PubKey) (string, error) {
	if bech32BasePrefix != "" {
		pubkey, err := cryptocodec.FromCmtPubKeyInterface(pubKey)
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
	sdkPK, err := cryptocodec.FromCmtPubKeyInterface(pubKey)
	if err != nil {
		return "", err
	}
	pubKeyJSON, err := marshaler.MarshalInterfaceJSON(sdkPK)
	if err != nil {
		return "", err
	}
	return string(pubKeyJSON), nil
}
