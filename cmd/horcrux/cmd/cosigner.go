package cmd

import (
	"github.com/jackzampolin/horcrux/internal/signer"
	"github.com/spf13/cobra"
)

func init() {
	cosignerCmd.AddCommand(signer.CreateCosignerSharesCmd())
	rootCmd.AddCommand(cosignerCmd)
}

var cosignerCmd = &cobra.Command{
	Use:   "cosigner",
	Short: "A brief description of your command",
}
