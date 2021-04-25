package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"

	"tendermint-signer/internal/signer"

	"github.com/spf13/cobra"
	"github.com/tendermint/tendermint/crypto/ed25519"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/libs/os"
	tmOS "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/privval"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

func shardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "shard [priv_validator.json] [shards] [threshold]",
		Aliases: []string{},
		Args:    validateShardCmd,
		Short:   "shard a private validator key",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			threshold, _ := strconv.ParseInt(args[1], 10, 64)
			numShards, _ := strconv.ParseInt(args[2], 10, 64)
			csKeys, err := CosignerKeysFromFile(args[0], threshold, numShards)
			if err != nil {
				return err
			}
			for _, c := range csKeys {
				if err = WriteKeyShardFile(c, fmt.Sprintf("private_share_%d.json", c.ID)); err != nil {
					return err
				}
				fmt.Printf("Created Share %d\n", c.ID)
			}
			return nil
		},
	}
	return cmd
}

// CosignerKeysFromFile creates cosigner key objects from a priv_validator_key.json file
func CosignerKeysFromFile(priv string, threshold, shards int64) ([]signer.CosignerKey, error) {
	pv, err := ReadPrivKeyFile(priv)
	if err != nil {
		return nil, err
	}
	return CreateCosignerKeys(pv, threshold, shards)
}

// CreateCosignerKeys creates cosigner key objects from a privval.FilePVKey
func CreateCosignerKeys(pv privval.FilePVKey, threshold, shards int64) (out []signer.CosignerKey, err error) {
	shares := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Bytes()[:32]), uint8(threshold), uint8(shards))
	rsaKeys, pubKeys, err := makeRSAKeys(len(shares))
	if err != nil {
		return nil, err
	}
	for idx, share := range shares {
		out = append(out, signer.CosignerKey{
			PubKey:       pv.PubKey,
			ShareKey:     share,
			ID:           idx + 1,
			RSAKey:       *rsaKeys[idx],
			CosignerKeys: pubKeys,
		})
	}
	return
}

// ReadPrivKeyFile reads in a privval.FilePVKey from a given file
func ReadPrivKeyFile(priv string) (out privval.FilePVKey, err error) {
	bz := []byte{}
	if bz, err = ioutil.ReadFile(priv); err != nil {
		return
	}
	if err = tmjson.Unmarshal(bz, &out); err != nil {
		return
	}
	return
}

// WriteKeyShardFile writes a cosigner key to a given file name
func WriteKeyShardFile(cosigner signer.CosignerKey, file string) error {
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

func validateShardCmd(cmd *cobra.Command, args []string) error {
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

func main() {
	var threshold = flag.Int("threshold", 2, "the number of shares required to produce a valid signature")
	var total = flag.Int("total", 2, "the total number of shareholders")
	flag.Parse()

	if len(flag.Args()) != 1 {
		log.Fatal("positional argument priv_validator_key.json is required")
	}

	keyFilePath := flag.Args()[0]
	keyJSONBytes, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		tmOS.Exit(err.Error())
	}
	pvKey := privval.FilePVKey{}
	err = tmjson.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		tmOS.Exit(fmt.Sprintf("Error reading PrivValidator key from %v: %v\n", keyFilePath, err))
	}

	privKeyBytes := [64]byte{}

	// extract the raw private key bytes from the loaded key
	// we need this to compute the expanded secret
	switch ed25519Key := pvKey.PrivKey.(type) {
	case ed25519.PrivKey:
		if len(ed25519Key) != len(privKeyBytes) {
			panic("Key length inconsistency")
		}
		copy(privKeyBytes[:], ed25519Key[:])
		break
	default:
		panic("Not an ed25519 private key")
	}

	fmt.Printf("key bytes %X\n", privKeyBytes)
	fmt.Printf("bytes from key %X\n", pvKey.PrivKey.Bytes())

	// generate shares from secret
	shares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), uint8(*threshold), uint8(*total))

	// generate all rsa keys
	rsaKeys := make([]*rsa.PrivateKey, len(shares))
	pubkeys := make([]*rsa.PublicKey, len(shares))
	for idx := range shares {
		bitSize := 4096
		rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			panic(err)
		}
		rsaKeys[idx] = rsaKey
		pubkeys[idx] = &rsaKey.PublicKey
	}

	// write shares and keys to private share files
	for idx, share := range shares {
		shareID := idx + 1

		privateFilename := fmt.Sprintf("private_share_%d.json", shareID)

		cosignerKey := signer.CosignerKey{
			PubKey:       pvKey.PubKey,
			ShareKey:     share,
			ID:           shareID,
			RSAKey:       *rsaKeys[idx],
			CosignerKeys: pubkeys,
		}

		jsonBytes, err := json.MarshalIndent(&cosignerKey, "", "  ")
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(privateFilename, jsonBytes, 0644)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Created Share %d\n", shareID)
	}
}
