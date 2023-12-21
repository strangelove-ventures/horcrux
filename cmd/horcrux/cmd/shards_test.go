package cmd

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/strangelove-ventures/horcrux/cmd/horcrux/cmd/testdata"
	"github.com/strangelove-ventures/horcrux/v3/signer"
	"github.com/stretchr/testify/require"
)

const testChainID = "test"

func TestEd25519Shards(t *testing.T) {
	tmp := t.TempDir()

	privValidatorKeyFile := filepath.Join(tmp, "priv_validator_key.json")
	privValidatorStateFile := filepath.Join(tmp, "priv_validator_state.json")
	pv := privval.NewFilePV(ed25519.GenPrivKey(), privValidatorKeyFile, privValidatorStateFile)
	pv.Save()

	tcs := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			name: "valid threshold and shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "2",
				"--shards", "3",
			},
			expectErr: false,
		},
		{
			name: "valid threshold and shards 2",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "3",
				"--shards", "5",
			},
			expectErr: false,
		},
		{
			name: "threshold exactly half of shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "2",
				"--shards", "4",
			},
			expectErr: true,
		},
		{
			name: "threshold less than half of shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "1",
				"--shards", "3",
			},
			expectErr: true,
		},
		{
			name: "threshold exceeds shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "4",
				"--shards", "3",
			},
			expectErr: true,
		},
		{
			name: "non-numeric threshold and shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "two",
				"--shards", "three",
			},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-ed25519-shards", "--home", tmp, "--out", tmp}, tc.args...)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRSAShards(t *testing.T) {
	tmp := t.TempDir()

	tcs := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			name:      "valid shards",
			args:      []string{"--shards", "3"},
			expectErr: false,
		},
		{
			name:      "invalid shards",
			args:      []string{"--shards", "0"},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-rsa-shards", "--home", tmp, "--out", tmp}, tc.args...)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPrivValidatorBn254(t *testing.T) {
	bz := testdata.PrivValidatorKeyBn254
	var privvalKey privval.FilePVKey
	err := cometjson.Unmarshal(bz, &privvalKey)
	require.NoError(t, err)

	msg := []byte("hello")

	sig, err := privvalKey.PrivKey.Sign(msg)
	require.NoError(t, err)

	valid := privvalKey.PrivKey.PubKey().VerifySignature(msg, sig)
	require.True(t, valid)

	valid = privvalKey.PubKey.VerifySignature(msg, sig)
	require.True(t, valid)

	shards, err := signer.CreateCosignerShards(&privvalKey, 2, 3)
	require.NoError(t, err)

	var signers = make([]*signer.ThresholdSignerSoftBn254, len(shards))
	var sigs = make([][]byte, len(shards))

	for i, shard := range shards {
		shard := shard
		signers[i], err = signer.NewThresholdSignerSoftBn254(&shard, 2, 3)
		require.NoError(t, err)

		sig, err = signers[i].Sign(nil, msg)
		require.NoError(t, err)

		sigs[i] = sig
	}

	var partialSigs = make([]signer.PartialSignature, 0, 2)
	for i, sig := range sigs {
		if i == 0 {
			continue
		}
		partialSigs = append(partialSigs, signer.PartialSignature{
			ID:        i + 1,
			Signature: sig,
		})
	}

	combinedSig, err := signers[0].CombineSignatures(partialSigs)
	require.NoError(t, err)

	valid = privvalKey.PrivKey.PubKey().VerifySignature(msg, combinedSig)
	require.True(t, valid)

	valid = privvalKey.PubKey.VerifySignature(msg, combinedSig)
	require.True(t, valid)
}
