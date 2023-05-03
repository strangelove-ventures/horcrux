package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	amino "github.com/tendermint/go-amino"
	"gopkg.in/yaml.v2"
)

type (
	v2Config struct {
		ChainID        string  `json:"chain-id" yaml:"chain-id"`
		PrivValKeyFile *string `json:"key-file,omitempty" yaml:"key-file,omitempty"`
		Cosigner       struct {
			P2PListen string `json:"p2p-listen"  yaml:"p2p-listen"`
		} `json:"cosigner"  yaml:"cosigner"`
	}

	v2CosignerKey struct {
		PubKey       cometcrypto.PubKey `json:"pub_key"`
		ShareKey     []byte             `json:"secret_share"`
		RSAKey       rsa.PrivateKey     `json:"rsa_key"`
		ID           int                `json:"id"`
		CosignerKeys []*rsa.PublicKey   `json:"rsa_pubs"`
	}
)

func (cosignerKey *v2CosignerKey) UnmarshalJSON(data []byte) error {
	type Alias v2CosignerKey

	aux := &struct {
		RSAKey       []byte   `json:"rsa_key"`
		PubkeyBytes  []byte   `json:"pub_key"`
		CosignerKeys [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Alias: (*Alias)(cosignerKey),
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
	// cdc.MarshalBinaryBare(cosignerKey.PubKey)
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
	cosignerKey.CosignerKeys = make([]*rsa.PublicKey, 0)
	for _, bytes := range aux.CosignerKeys {
		cosignerRsaPubkey, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return err
		}
		cosignerKey.CosignerKeys = append(cosignerKey.CosignerKeys, cosignerRsaPubkey)
	}

	cosignerKey.RSAKey = *privateKey
	cosignerKey.PubKey = pubkey
	return nil
}

func (cosignerKey *v2CosignerKey) validate() error {
	var errs []error
	if cosignerKey.PubKey == nil || len(cosignerKey.PubKey.Bytes()) == 0 {
		errs = append(errs, fmt.Errorf("pub_key cannot be empty"))
	}
	if len(cosignerKey.ShareKey) == 0 {
		errs = append(errs, fmt.Errorf("secret_share cannot be empty"))
	}
	if err := cosignerKey.RSAKey.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("rsa_key is invalid: %w", err))
	}
	if cosignerKey.ID == 0 {
		errs = append(errs, fmt.Errorf("id cannot be zero"))
	}
	if len(cosignerKey.CosignerKeys) == 0 {
		errs = append(errs, fmt.Errorf("cosigner keys cannot be empty"))
	}

	return errors.Join(errs...)
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "migrate [chain-id]",
		Short:        "Migrate config and key files from v2 to v3",
		SilenceUsage: true,
		Args:         cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			configFile, err := os.ReadFile(config.ConfigFile)
			if err != nil {
				return err
			}

			var chainID string

			var legacyConfig v2Config

			if err := yaml.Unmarshal(configFile, &legacyConfig); err != nil {
				return fmt.Errorf("failed to read config file as legacy: %w", err)
			}

			if len(args) == 1 {
				chainID = args[0]
			} else {
				if legacyConfig.ChainID == "" {
					return fmt.Errorf("unable to migrate v2 config without chain-id. please provide [chain-id] argument")
				}

				chainID = legacyConfig.ChainID
			}

			var legacyCosignerKeyFile string

			if legacyConfig.PrivValKeyFile != nil && *legacyConfig.PrivValKeyFile != "" {
				legacyCosignerKeyFile = *legacyConfig.PrivValKeyFile
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

			newEd25519Key := signer.CosignerKey{
				PubKey:   legacyCosignerKey.PubKey,
				ShareKey: legacyCosignerKey.ShareKey,
				ID:       legacyCosignerKey.ID,
			}

			newEd25519KeyBz, err := newEd25519Key.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal new Ed25519 key to json: %w", err)
			}

			newEd25519Path := config.KeyFilePathCosigner(chainID)
			if err := os.WriteFile(newEd25519Path, newEd25519KeyBz, 0600); err != nil {
				return fmt.Errorf("failed to write new Ed25519 key to %s: %w", newEd25519Path, err)
			}

			newRSAKey := signer.CosignerKeyRSA{
				RSAKey:       legacyCosignerKey.RSAKey,
				ID:           legacyCosignerKey.ID,
				CosignerKeys: legacyCosignerKey.CosignerKeys,
			}

			newRSAKeyBz, err := newRSAKey.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal new RSA key to json: %w", err)
			}

			newRSAPath := config.KeyFilePathCosignerRSA()
			if err := os.WriteFile(newRSAPath, newRSAKeyBz, 0600); err != nil {
				return fmt.Errorf("failed to write new RSA key to %s: %w", newRSAPath, err)
			}

			if legacyConfig.Cosigner.P2PListen != "" {
				config.Config.CosignerConfig.Peers = append(config.Config.CosignerConfig.Peers, signer.CosignerPeerConfig{
					ShareID: legacyCosignerKey.ID,
					P2PAddr: legacyConfig.Cosigner.P2PListen,
				})
			}

			if err := config.WriteConfigFile(); err != nil {
				return err
			}

			if err := os.Remove(legacyCosignerKeyFile); err != nil {
				return fmt.Errorf("failed to remove legacy key file (%s): %w", legacyCosignerKeyFile, err)
			}

			return nil
		},
	}
}
