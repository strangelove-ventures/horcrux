package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"tendermint-signer/internal/signer"

	"github.com/tendermint/tendermint/crypto/ed25519"
	tmjson "github.com/tendermint/tendermint/libs/json"
	tmOS "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/privval"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

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
