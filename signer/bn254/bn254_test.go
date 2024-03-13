package bn254_test

import (
	"fmt"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/signer/bn254"
	"github.com/strangelove-ventures/horcrux/v3/types"
	"github.com/stretchr/testify/require"
)

func TestXxx(t *testing.T) {
	bz, err := bn254.VoteSignBytesPre("test", types.Block{
		Step:   types.StepPrecommit,
		Height: 200,
		Round:  100,
	})
	require.NoError(t, err)

	fmt.Printf("%x\n", bz)
}
