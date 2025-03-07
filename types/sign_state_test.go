package types_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/types"
	"github.com/stretchr/testify/require"
)

func TestLegacySignState(t *testing.T) {
	//nolint: lll
	const signState = `{
	"height": "120802",
	"round": "0",
	"step": 3,
	"nonce_public": null,
	"signature": "AXiV7BDzYDuIlgf4adJ3zAu7lzprXfB5gvEP2JHmEzWo2zpNs8yfrEovl4ktZE3wa1tI4Hm+7vNuZwOOTbW5Ag==",
	"signbytes": "72080211E2D701000000000022480A204F4BF00C4AE3E71106CE705A20C07009A4DC39FE2D7DA80CA9D509C87E9E263912240801122012BE46D23277FDD30F4DED498A5E52A34B5A1CD2F38E9A0EC994A42A2CEBC9962A0C08FFEADAB006109F8CB59103320D7373632D746573746E65742D32",
	"vote_ext_signature": "wOFUBF+R3r+OKVDfOmd4BLgij/DEJl88v5CgCf07UA6MNqJRRzqFJZfiLraRgMyt+n9amkJ+ZrjiGzA2jCorAQ=="
}
`

	signStateFilePath := filepath.Join(t.TempDir(), "signstate.json")

	err := os.WriteFile(signStateFilePath, []byte(signState), 0600)
	require.NoError(t, err)

	signStateOld, err := types.LoadSignState(signStateFilePath)
	require.NoError(t, err)

	require.Equal(t, int64(120802), signStateOld.Height)
	require.Equal(t, int64(0), signStateOld.Round)
	require.Equal(t, int8(3), signStateOld.Step)

	//nolint: lll
	signbytesBz, err := hex.DecodeString("72080211E2D701000000000022480A204F4BF00C4AE3E71106CE705A20C07009A4DC39FE2D7DA80CA9D509C87E9E263912240801122012BE46D23277FDD30F4DED498A5E52A34B5A1CD2F38E9A0EC994A42A2CEBC9962A0C08FFEADAB006109F8CB59103320D7373632D746573746E65742D32")
	require.NoError(t, err)

	require.Equal(t, signbytesBz, signStateOld.SignBytes)

	//nolint: lll
	signatureBz, err := base64.StdEncoding.DecodeString("AXiV7BDzYDuIlgf4adJ3zAu7lzprXfB5gvEP2JHmEzWo2zpNs8yfrEovl4ktZE3wa1tI4Hm+7vNuZwOOTbW5Ag==")
	require.NoError(t, err)

	require.Equal(t, signatureBz, signStateOld.Signature)

	//nolint: lll
	voteExtSignatureBz, err := base64.StdEncoding.DecodeString("wOFUBF+R3r+OKVDfOmd4BLgij/DEJl88v5CgCf07UA6MNqJRRzqFJZfiLraRgMyt+n9amkJ+ZrjiGzA2jCorAQ==")
	require.NoError(t, err)

	require.Equal(t, voteExtSignatureBz, signStateOld.VoteExtensionSignature)
}

func TestSignState(t *testing.T) {
	signStateFilePath := filepath.Join(t.TempDir(), "signstate.json")

	signState, err := types.LoadOrCreateSignState(signStateFilePath)
	require.NoError(t, err)

	err = signState.Save(types.SignStateConsensus{
		Height: 20,
		Round:  5,
		Step:   3,
		BlockID: &types.BlockID{
			Hash: []byte("block_id_hash"),
			PartSetHeader: types.PartSetHeader{
				Total: 100,
				Hash:  []byte("part_set_header_hash"),
			},
		},
		POLRound:               123,
		Timestamp:              98908123,
		SignBytes:              []byte("signbytes"),
		Signature:              []byte("signature"),
		VoteExtensionSignature: []byte("vote_ext_signature"),
	}, nil)

	require.NoError(t, err)

	ssbz, err := os.ReadFile(signStateFilePath)
	require.NoError(t, err)

	fmt.Println(string(ssbz))

	signStateNew, err := types.LoadSignState(signStateFilePath)
	require.NoError(t, err)

	require.Equal(t, int64(20), signStateNew.Height)
	require.Equal(t, int64(5), signStateNew.Round)
	require.Equal(t, int8(3), signStateNew.Step)
	require.Equal(t, int64(123), signStateNew.POLRound)
	require.Equal(t, int64(98908123), signStateNew.Timestamp)
	require.Equal(t, []byte("signbytes"), signStateNew.SignBytes)
	require.Equal(t, []byte("signature"), signStateNew.Signature)
	require.Equal(t, []byte("vote_ext_signature"), signStateNew.VoteExtensionSignature)
	require.Equal(t, []byte("block_id_hash"), signStateNew.BlockID.Hash)
	require.Equal(t, uint32(100), signStateNew.BlockID.PartSetHeader.Total)
	require.Equal(t, []byte("part_set_header_hash"), signStateNew.BlockID.PartSetHeader.Hash)

}

func TestNewSignState(t *testing.T) {

	const signState = `{
	"height": 20,
	"round": 5,
	"step": 3,
	"block_id": {
		"hash": "YmxvY2tfaWRfaGFzaA==",
		"part_set_header": {
		"total": 100,
		"hash": "cGFydF9zZXRfaGVhZGVyX2hhc2g="
		}
	},
	"pol_round": 123,
	"timestamp": 98908123,
	"sign_bytes": "c2lnbmJ5dGVz",
	"signature": "c2lnbmF0dXJl",
	"vote_ext_signature": "dm90ZV9leHRfc2lnbmF0dXJl"
}
`

	signStateFilePath := filepath.Join(t.TempDir(), "signstate.json")

	err := os.WriteFile(signStateFilePath, []byte(signState), 0600)
	require.NoError(t, err)

	signStateNew, err := types.LoadSignState(signStateFilePath)
	require.NoError(t, err)

	require.Equal(t, int64(20), signStateNew.Height)
	require.Equal(t, int64(5), signStateNew.Round)
	require.Equal(t, int8(3), signStateNew.Step)
	require.Equal(t, int64(123), signStateNew.POLRound)
	require.Equal(t, int64(98908123), signStateNew.Timestamp)
	require.Equal(t, []byte("signbytes"), signStateNew.SignBytes)
	require.Equal(t, []byte("signature"), signStateNew.Signature)
	require.Equal(t, []byte("vote_ext_signature"), signStateNew.VoteExtensionSignature)
	require.Equal(t, []byte("block_id_hash"), signStateNew.BlockID.Hash)
	require.Equal(t, uint32(100), signStateNew.BlockID.PartSetHeader.Total)
	require.Equal(t, []byte("part_set_header_hash"), signStateNew.BlockID.PartSetHeader.Hash)

}

func TestSignStateCheck(t *testing.T) {
	filepath := t.TempDir() + "/sign_state.json"
	ss, err := types.LoadOrCreateSignState(filepath)
	require.NoError(t, err)
	require.NotNil(t, ss)

	for i := 1; i < 100; i++ {
		const jMax = 100
		startedCh := make(chan struct{}, jMax)
		workNowCh := make(chan struct{})

		numErr, numSuccess := 0, 0
		var mu sync.Mutex
		i := i
		var wg sync.WaitGroup
		wg.Add(100)
		for j := 0; j < jMax; j++ {
			go func() {
				startedCh <- struct{}{} // Notify reader that goroutine is ready to run.
				<-workNowCh             // Coordinator closes this channel so all goroutines can start working.

				defer wg.Done()
				err := ss.Save(types.SignStateConsensus{
					Height: int64(i),
				}, nil)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					numErr++
				} else {
					numSuccess++
				}
			}()
		}

		for j := 0; j < jMax; j++ {
			<-startedCh // Make sure all goroutines are ready to run.
		}

		close(workNowCh) // Give them the start signal.
		wg.Wait()
		require.Equal(t, numSuccess, 1)
		require.Equal(t, numErr, 99)
	}
}

func TestSignStateCheckDiskWG(t *testing.T) {
	filepath := t.TempDir() + "/sign_state.json"
	ss, err := types.LoadOrCreateSignState(filepath)
	require.NoError(t, err)
	require.NotNil(t, ss)

	var pendingDiskWG sync.WaitGroup

	for i := 1; i < 100; i++ {
		const jMax = 100
		startedCh := make(chan struct{}, jMax)
		workNowCh := make(chan struct{})

		numErr, numSuccess := 0, 0
		var mu sync.Mutex
		i := i
		var wg sync.WaitGroup
		wg.Add(100)
		for j := 0; j < jMax; j++ {
			go func() {
				startedCh <- struct{}{} // Notify reader that goroutine is ready to run.
				<-workNowCh             // Coordinator closes this channel so all goroutines can start working.

				defer wg.Done()
				err := ss.Save(types.SignStateConsensus{
					Height: int64(i),
				}, &pendingDiskWG)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					numErr++
				} else {
					numSuccess++
				}
			}()
		}

		for j := 0; j < jMax; j++ {
			<-startedCh // Make sure all goroutines are ready to run.
		}

		close(workNowCh) // Give them the start signal.
		wg.Wait()
		pendingDiskWG.Wait()

		require.Equal(t, numSuccess, 1)
		require.Equal(t, numErr, 99)
	}
}
