package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/spf13/cobra"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/privval"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func CreateCosignerSharesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-shares [priv_validator.json] [shares] [threshold]",
		Aliases: []string{"shard", "shares"},
		Args:    validateCreateCosignerShares,
		Short:   "create  cosigner shares",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			threshold, _ := strconv.ParseInt(args[1], 10, 64)
			numShares, _ := strconv.ParseInt(args[2], 10, 64)
			csKeys, err := CreateCosignerSharesFromFile(args[0], threshold, numShares)
			if err != nil {
				return err
			}
			for _, c := range csKeys {
				if err = WriteCosignerShareFile(c, fmt.Sprintf("private_share_%d.json", c.ID)); err != nil {
					return err
				}
				fmt.Printf("Created Share %d\n", c.ID)
			}
			return nil
		},
	}
	return cmd
}

// CreateCosignerSharesFromFile creates cosigner key objects from a priv_validator_key.json file
func CreateCosignerSharesFromFile(priv string, threshold, shares int64) ([]CosignerKey, error) {
	pv, err := ReadPrivValidatorFile(priv)
	if err != nil {
		return nil, err
	}
	return CreateCosignerShares(pv, threshold, shares)
}

// CreateCosignerShares creates cosigner key objects from a privval.FilePVKey
func CreateCosignerShares(pv privval.FilePVKey, threshold, shares int64) (out []CosignerKey, err error) {
	privshares := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Bytes()[:32]), uint8(threshold), uint8(shares))
	rsaKeys, pubKeys, err := makeRSAKeys(len(privshares))
	if err != nil {
		return nil, err
	}
	for idx, share := range privshares {
		out = append(out, CosignerKey{
			PubKey:       pv.PubKey,
			ShareKey:     share,
			ID:           idx + 1,
			RSAKey:       *rsaKeys[idx],
			CosignerKeys: pubKeys,
		})
	}
	return
}

// ReadPrivValidatorFile reads in a privval.FilePVKey from a given file
func ReadPrivValidatorFile(priv string) (out privval.FilePVKey, err error) {
	bz := []byte{}
	if bz, err = ioutil.ReadFile(priv); err != nil {
		return
	}
	if err = tmjson.Unmarshal(bz, &out); err != nil {
		return
	}
	return
}

// WriteCosignerShareFile writes a cosigner key to a given file name
func WriteCosignerShareFile(cosigner CosignerKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, jsonBytes, 0644)
}

func makeRSAKeys(num int) (rsaKeys []*rsa.PrivateKey, pubKeys []*rsa.PublicKey, err error) {
	rsaKeys = make([]*rsa.PrivateKey, num)
	pubKeys = make([]*rsa.PublicKey, num)
	for i := 0; i < num; i++ {
		bitSize := 4096
		rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			return rsaKeys, pubKeys, err
		}
		rsaKeys[i] = rsaKey
		pubKeys[i] = &rsaKey.PublicKey
	}
	return
}

func validateCreateCosignerShares(cmd *cobra.Command, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("wrong num args exp(3) got(%d)", len(args))
	}
	if !os.FileExists(args[0]) {
		return fmt.Errorf("priv_validator.json file(%s) doesn't exist", args[0])
	}
	if _, err := strconv.ParseInt(args[1], 10, 64); err != nil {
		return fmt.Errorf("shards must be an integer got(%s)", args[1])
	}
	if _, err := strconv.ParseInt(args[2], 10, 64); err != nil {
		return fmt.Errorf("threshold must be an integer got(%s)", args[2])
	}
	return nil
}
