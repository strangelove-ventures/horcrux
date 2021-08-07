package version

import (
	"encoding/json"

	"github.com/spf13/cobra"
)

const flagLong = "long"

// NewVersionCommand returns a CLI command to interactively print the application binary version information.
func NewVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the application binary version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			verInfo := NewInfo()

			var (
				bz  []byte
				err error
			)

			bz, err = json.MarshalIndent(verInfo, "", "  ")
			if err != nil {
				return err
			}
			cmd.Println(string(bz))
			return nil
		},
	}
	return cmd
}
