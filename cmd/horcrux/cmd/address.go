package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cometbft/cometbft/crypto"
	cometprivval "github.com/cometbft/cometbft/privval"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/spf13/cobra"
	cconfig "github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/tss"
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

			var pubKey tss.PubKey

			chainID := args[0]

			switch config.Config.SignMode {
			case cconfig.SignModeThreshold:
				err := config.Config.ValidateThresholdModeConfig()
				if err != nil {
					return err
				}

				keyFile, err := config.KeyFileExistsCosigner(chainID)
				if err != nil {
					return err
				}

				key, err := tss.LoadVaultKeyFromFile(keyFile)
				if err != nil {
					return fmt.Errorf("error reading threshold key: %w, check that key is present for chain id: %s", err, chainID)
				}

				pubKey = key.PubKey.(crypto.PubKey)
			case cconfig.SignModeSingle:
				err := config.Config.ValidateSingleSignerConfig()
				if err != nil {
					return err
				}
				keyFile, err := config.KeyFileExistsSingleSigner(chainID)
				if err != nil {
					return fmt.Errorf(
						"error reading priv-validator key: %w, check that key is present for chain Index: %s", err, chainID)
				}

				filePV := cometprivval.LoadFilePVEmptyState(keyFile, "")
				pubKey = filePV.Key.PubKey
			default:
				panic(fmt.Errorf("unexpected sign mode: %s", config.Config.SignMode))
			}
			pubKeyComet := pubKey.(crypto.PubKey)
			pubKeyAddress := pubKeyComet.Address()

			pubKeyJSON, err := cconfig.PubKey("", pubKeyComet)
			if err != nil {
				return err
			}

			output := AddressCmdOutput{
				HexAddress: strings.ToUpper(hex.EncodeToString(pubKeyAddress)),
				PubKey:     pubKeyJSON,
			}

			if len(args) == 2 {
				bech32ValConsAddress, err := bech32.ConvertAndEncode(args[1]+"valcons", pubKeyAddress)
				if err != nil {
					return err
				}
				output.ValConsAddress = bech32ValConsAddress
				pubKeyBech32, err := cconfig.PubKey(args[1], pubKeyComet)
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
