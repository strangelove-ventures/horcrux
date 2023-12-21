package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	cometprivval "github.com/cometbft/cometbft/privval"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/v3/signer"
)

type AddressCmdOutput struct {
	HexAddress        string
	PubKey            string
	ValConsAddress    string
	ValConsPubAddress string
}

func addressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "address chain-id [bech32]",
		Short:        "Get public key hex address and valcons address",
		Example:      `horcrux cosigner address cosmos`,
		SilenceUsage: true,
		Args:         cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {

			var pubKey []byte

			chainID := args[0]

			switch config.Config.SignMode {
			case signer.SignModeThreshold:
				err := config.Config.ValidateThresholdModeConfig()
				if err != nil {
					return err
				}

				keyFile, err := config.KeyFileExistsCosigner(chainID)
				if err != nil {
					return err
				}

				key, err := signer.LoadCosignerKey(keyFile)
				if err != nil {
					return fmt.Errorf("error reading cosigner key: %w, check that key is present for chain ID: %s", err, chainID)
				}

				pubKey = key.PubKey
			case signer.SignModeSingle:
				err := config.Config.ValidateSingleSignerConfig()
				if err != nil {
					return err
				}
				keyFile, err := config.KeyFileExistsSingleSigner(chainID)
				if err != nil {
					return fmt.Errorf("error reading priv-validator key: %w, check that key is present for chain ID: %s", err, chainID)
				}

				filePV := cometprivval.LoadFilePVEmptyState(keyFile, "")
				pubKey = filePV.Key.PubKey.Bytes()
			default:
				panic(fmt.Errorf("unexpected sign mode: %s", config.Config.SignMode))
			}

			address := sha256.New().Sum(pubKey)[:20]

			pubKeyJSON, err := signer.PubKey("", pubKey)
			if err != nil {
				return err
			}

			output := AddressCmdOutput{
				HexAddress: strings.ToUpper(hex.EncodeToString(address)),
				PubKey:     pubKeyJSON,
			}

			if len(args) == 2 {
				bech32ValConsAddress, err := bech32.ConvertAndEncode(args[1]+"valcons", address)
				if err != nil {
					return err
				}
				output.ValConsAddress = bech32ValConsAddress
				pubKeyBech32, err := signer.PubKey(args[1], pubKey)
				if err != nil {
					return err
				}
				output.ValConsPubAddress = pubKeyBech32
			} else {
				bech32Hint := "Pass bech32 base prefix as argument to generate (e.g. cosmos)"
				output.ValConsAddress = bech32Hint
				output.ValConsPubAddress = bech32Hint
			}

			jsonOut, err := json.Marshal(output)
			if err != nil {
				return err
			}

			fmt.Println(string(jsonOut))

			return nil
		},
	}

	return cmd
}
