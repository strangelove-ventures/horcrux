package cmd

import (
	"fmt"
	"io"

	"github.com/strangelove-ventures/horcrux/src/node"
)

const (
	flagAcceptRisk = "accept-risk"

	singleSignerWarning = `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@ WARNING: SINGLE-SIGNER MODE SHOULD NOT BE USED FOR MAINNET! @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Horcrux single-signer mode does not give the level of improved 
key security and fault tolerance that Horcrux MPC/cosigner mode
provides. While it is a simpler deployment configuration, 
single-signer should only be used for experimentation
as it is not officially supported by Strangelove.`
)

func NewSingleSignerValidator(
	out io.Writer,
	acceptRisk bool,
) (*node.SingleSignerValidator, error) {
	fmt.Fprintln(out, singleSignerWarning)

	if !acceptRisk {
		panic(fmt.Errorf("risk not accepted. --accept-risk flag required to run single signer mode"))
	}

	if err := config.Config.ValidateSingleSignerConfig(); err != nil {
		return nil, err
	}

	return node.NewSingleSignerValidator(&config), nil
}
