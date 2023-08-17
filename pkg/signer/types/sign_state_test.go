package types

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/strangelove-ventures/horcrux/pkg/signer/cond"
	"github.com/stretchr/testify/require"
)

func TestCreateLoadSignState(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")

	// Make an empty sign state and save it.
	state := &SignState{
		FilePath: path,
		cache:    make(map[HRSKey]SignStateConsensus),
	}
	state.cond = cond.New(&state.mu)

	// Set state Height to one so we can test if reading and writing is correct.
	state.Height = 1

	jsonBytes, err := cometjson.MarshalIndent(state, "", "  ")
	if err != nil {
		fmt.Printf("cometjson.MarshalIndent: %s", err)
		panic(err)
	}
	state.save(jsonBytes)

	stateJSONBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	newstate := new(SignState)
	err = cometjson.Unmarshal(stateJSONBytes, &newstate)
	require.NoError(t, err)

	// Check cond is not equal
	require.NotEqual(t, state.cond, newstate.cond)

	// Check height is equal
	require.Equal(t, state.Height, newstate.Height)

	// Why this would ever happen I dont know.
	newstate.cond = cond.New(&newstate.mu)
	require.NotEqual(t, state.cond, newstate.cond)
}
