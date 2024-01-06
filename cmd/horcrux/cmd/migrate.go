package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cconfig "github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"
	"github.com/strangelove-ventures/horcrux/src/tss"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/spf13/cobra"
	amino "github.com/tendermint/go-amino"
	"gopkg.in/yaml.v2"
)

func legacyConfig() (*v2Config, error) {
	configFile, err := os.ReadFile(config.ConfigFile)
	if err != nil {
		return nil, err
	}

	legacyConfig := new(v2Config)

	if err := yaml.Unmarshal(configFile, &legacyConfig); err != nil {
		return nil, fmt.Errorf("failed to read config file as legacy: %w", err)
	}

	if err := legacyConfig.validate(); err != nil {
		return nil, err
	}

	return legacyConfig, nil
}

type (
	v2Config struct {
		ChainID        string              `json:"chain-id" yaml:"chain-id"`
		PrivValKeyFile *string             `json:"key-file,omitempty" yaml:"key-file,omitempty"`
		Cosigner       *v2CosignerConfig   `json:"cosigner"  yaml:"cosigner"`
		ChainNodes     []v2ChainNodeConfig `json:"chain-cosigner,omitempty" yaml:"chain-cosigner,omitempty"`
		DebugAddr      string              `json:"debug-addr,omitempty" yaml:"debug-addr,omitempty"`
	}

	v2CosignerConfig struct {
		Threshold int    `json:"threshold"   yaml:"threshold"`
		Shares    int    `json:"shares" yaml:"shares"`
		P2PListen string `json:"p2p-listen"  yaml:"p2p-listen"`
		Peers     []struct {
			ShareID int    `json:"share-id" yaml:"share-id"`
			P2PAddr string `json:"p2p-addr" yaml:"p2p-addr"`
		} `json:"peers"       yaml:"peers"`
		Timeout string `json:"rpc-timeout" yaml:"rpc-timeout"`
	}

	v2ChainNodeConfig struct {
		PrivValAddr string `json:"priv-val-addr" yaml:"priv-val-addr"`
	}

	v2CosignerKey struct {
		PubKey   cometcrypto.PubKey `json:"pub_key"`
		ShareKey []byte             `json:"secret_share"`
		RSAKey   rsa.PrivateKey     `json:"rsa_key"`
		ID       int                `json:"id"`
		RSAPubs  []*rsa.PublicKey   `json:"rsa_pubs"`
	}
)

func (c *v2Config) validate() error {
	if c.ChainID == "" {
		return fmt.Errorf("chain-id is empty")
	}

	return nil
}

func (key *v2CosignerKey) UnmarshalJSON(data []byte) error {
	type Alias v2CosignerKey

	aux := &struct {
		RSAKey      []byte   `json:"rsa_key"`
		PubkeyBytes []byte   `json:"pub_key"`
		RSAPubs     [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Alias: (*Alias)(key),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(aux.RSAKey)
	if err != nil {
		return err
	}

	var pubkey cometcrypto.PubKey
	var protoPubkey cometprotocrypto.PublicKey
	err = protoPubkey.Unmarshal(aux.PubkeyBytes)

	// Prior to the tendermint protobuf migration, the public key bytes in key files
	// were encoded using the go-amino libraries via
	// cdc.MarshalBinaryBare(Ed25519Key.PubKey)
	//
	// To support reading the public key bytes from these key files, we fallback to
	// amino unmarshalling if the protobuf unmarshalling fails
	if err != nil {
		var pub cometcryptoed25519.PubKey
		codec := amino.NewCodec()
		codec.RegisterInterface((*cometcrypto.PubKey)(nil), nil)
		codec.RegisterConcrete(cometcryptoed25519.PubKey{}, "tendermint/PubKeyEd25519", nil)
		errInner := codec.UnmarshalBinaryBare(aux.PubkeyBytes, &pub)
		if errInner != nil {
			return err
		}
		pubkey = pub
	} else {
		pubkey, err = cometcryptoencoding.PubKeyFromProto(protoPubkey)
		if err != nil {
			return err
		}
	}

	// unmarshal the public key bytes for each cosigner
	key.RSAPubs = make([]*rsa.PublicKey, 0)
	for _, bytes := range aux.RSAPubs {
		cosignerRsaPubkey, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return err
		}
		key.RSAPubs = append(key.RSAPubs, cosignerRsaPubkey)
	}

	key.RSAKey = *privateKey
	key.PubKey = pubkey
	return nil
}

func (key *v2CosignerKey) validate() error {
	if key.PubKey == nil || len(key.PubKey.Bytes()) == 0 {
		return fmt.Errorf("pub_key cannot be empty")
	}
	if len(key.ShareKey) == 0 {
		return fmt.Errorf("secret_share cannot be empty")
	}
	if err := key.RSAKey.Validate(); err != nil {
		return fmt.Errorf("rsa_key is invalid: %w", err)
	}
	if key.ID == 0 {
		return fmt.Errorf("id cannot be zero")
	}
	if len(key.RSAPubs) == 0 {
		return fmt.Errorf("cosigner keys cannot be empty")
	}

	return nil
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "migrate [chain-id]",
		Short:        "Migrate config and key files from v2 to v3",
		SilenceUsage: true,
		Args:         cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			legacyCfg, legacyCfgErr := legacyConfig()
			if legacyCfgErr != nil {
				fmt.Fprintf(
					cmd.OutOrStderr(),
					"failed to load legacy config: %v, proceeding to attempt key migration",
					legacyCfgErr,
				)
			}

			var chainID string

			if len(args) == 1 {
				chainID = args[0]
			} else {
				if legacyCfgErr != nil {
					return fmt.Errorf("unable to migrate v2 config without chain-id. please provide [chain-id] argument")
				}

				chainID = legacyCfg.ChainID
			}

			var legacyCosignerKeyFile string

			if legacyCfgErr == nil && legacyCfg.PrivValKeyFile != nil && *legacyCfg.PrivValKeyFile != "" {
				legacyCosignerKeyFile = *legacyCfg.PrivValKeyFile
				dir := filepath.Dir(legacyCosignerKeyFile)
				config.Config.PrivValKeyDir = &dir
			} else {
				legacyCosignerKeyFile = filepath.Join(config.HomeDir, "share.json")
			}

			if _, err := os.Stat(legacyCosignerKeyFile); err != nil {
				return fmt.Errorf("error loading v2 key file: %w", err)
			}

			keyFile, err := os.ReadFile(legacyCosignerKeyFile)
			if err != nil {
				return err
			}

			legacyCosignerKey := new(v2CosignerKey)

			if err := legacyCosignerKey.UnmarshalJSON(keyFile); err != nil {
				return fmt.Errorf("failed to read key file as legacy: %w", err)
			}

			if err := legacyCosignerKey.validate(); err != nil {
				return err
			}

			newEd25519Key := tss.Ed25519Key{
				PubKey:       legacyCosignerKey.PubKey,
				PrivateShard: legacyCosignerKey.ShareKey,
				ID:           legacyCosignerKey.ID,
			}

			newEd25519KeyBz, err := newEd25519Key.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal new Ed25519 key to json: %w", err)
			}

			newEd25519Path := config.KeyFilePathCosigner(chainID)
			if err := os.WriteFile(newEd25519Path, newEd25519KeyBz, 0600); err != nil {
				return fmt.Errorf("failed to write new Ed25519 key to %s: %w", newEd25519Path, err)
			}

			newRSAKey := nodesecurity.CosignerRSAKey{
				RSAKey:  legacyCosignerKey.RSAKey,
				ID:      legacyCosignerKey.ID,
				RSAPubs: legacyCosignerKey.RSAPubs,
			}

			newRSAKeyBz, err := newRSAKey.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal new RSA key to json: %w", err)
			}

			newRSAPath := config.KeyFilePathCosignerRSA()
			if err := os.WriteFile(newRSAPath, newRSAKeyBz, 0600); err != nil {
				return fmt.Errorf("failed to write new RSA key to %s: %w", newRSAPath, err)
			}

			// only attempt config migration if legacy config exists
			if legacyCfgErr == nil {
				var migratedNodes cconfig.ChainNodes

				for _, n := range legacyCfg.ChainNodes {
					migratedNodes = append(migratedNodes, cconfig.ChainNode{
						PrivValAddr: n.PrivValAddr,
					})
				}

				config.Config.ChainNodes = migratedNodes
				config.Config.DebugAddr = legacyCfg.DebugAddr

				signMode := cconfig.SignModeSingle

				if legacyCfg.Cosigner != nil {
					signMode = cconfig.SignModeThreshold

					var migratedCosigners cconfig.CosignersConfig

					if legacyCfg.Cosigner.P2PListen != "" {
						migratedCosigners = append(
							migratedCosigners,
							cconfig.CosignerConfig{
								ShardID: legacyCosignerKey.ID,
								P2PAddr: legacyCfg.Cosigner.P2PListen,
							},
						)
					}

					for _, c := range legacyCfg.Cosigner.Peers {
						migratedCosigners = append(migratedCosigners, cconfig.CosignerConfig{
							ShardID: c.ShareID,
							P2PAddr: c.P2PAddr,
						})
					}

					config.Config.ThresholdModeConfig = &cconfig.ThresholdModeConfig{
						Threshold:   legacyCfg.Cosigner.Threshold,
						Cosigners:   migratedCosigners,
						GRPCTimeout: legacyCfg.Cosigner.Timeout,
						RaftTimeout: legacyCfg.Cosigner.Timeout,
					}
				}

				config.Config.SignMode = signMode

				if err := config.WriteConfigFile(); err != nil {
					return err
				}
			}

			if err := os.Remove(legacyCosignerKeyFile); err != nil {
				return fmt.Errorf("failed to remove legacy key file (%s): %w", legacyCosignerKeyFile, err)
			}

			return nil
		},
	}
}
