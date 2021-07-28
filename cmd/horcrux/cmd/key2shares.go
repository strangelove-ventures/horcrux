/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/jackzampolin/horcrux/internal/signer"
	"github.com/spf13/cobra"
	"github.com/tendermint/tendermint/crypto/ed25519"
	tmjson "github.com/tendermint/tendermint/libs/json"
	tmOS "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/privval"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

// key2sharesCmd represents the key2shares command
var key2sharesCmd = &cobra.Command{
	Use:   "key2shares [/path/to/priv_validator_key.json] [threshold] [total]",
	Short: "break a priv_validator.json into (total) shares with (threshold) required",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		threshold, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return err
		}

		total, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return err
		}

		keyJSONBytes, err := ioutil.ReadFile(args[0])
		if err != nil {
			return err
		}

		pvKey := privval.FilePVKey{}
		if err = tmjson.Unmarshal(keyJSONBytes, &pvKey); err != nil {
			tmOS.Exit(fmt.Sprintf("Error reading PrivValidator key from %v: %v\n", args[0], err))
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
		shares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), uint8(threshold), uint8(total))

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

			if err = ioutil.WriteFile(privateFilename, jsonBytes, 0644); err != nil {
				panic(err)
			}
			fmt.Printf("Created Share %d\n", shareID)
		}
		fmt.Println("key2shares called")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(key2sharesCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// key2sharesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// key2sharesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
