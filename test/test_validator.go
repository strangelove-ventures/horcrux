package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
	crypto "github.com/tendermint/tendermint/crypto"
	ed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/privval"
)

type TestValidator struct {
	Index         int
	Sentries      TestNodes
	Signers       TestSigners
	t             *testing.T
	Home          string
	PubKey        crypto.PubKey
	PrivKeyShares []signer.CosignerKey
	Threshold     int
}

func NewHorcruxValidator(
	t *testing.T,
	pool *dockertest.Pool,
	home string,
	chainID string,
	index int,
	numSentries int,
	numSigners int,
	threshold int,
	chainType *ChainType,
) *TestValidator {
	testValidator := &TestValidator{
		Index:     index,
		Sentries:  MakeTestNodes(index, numSentries, home, chainID, chainType, pool, t),
		Signers:   MakeTestSigners(index, numSigners, home, pool, t),
		t:         t,
		Home:      home,
		Threshold: threshold,
	}

	testValidator.genPrivKeyAndShares()

	return testValidator
}

func NewHorcruxValidatorWithPrivValKey(
	t *testing.T,
	pool *dockertest.Pool,
	home string,
	chainID string,
	index int,
	numSentries int,
	numSigners int,
	threshold int,
	chainType *ChainType,
	privValKey privval.FilePVKey,
) *TestValidator {
	testValidator := &TestValidator{
		Index:     index,
		Sentries:  MakeTestNodes(index, numSentries, home, chainID, chainType, pool, t),
		Signers:   MakeTestSigners(index, numSigners, home, pool, t),
		t:         t,
		Home:      home,
		Threshold: threshold,
	}

	testValidator.generateShares(privValKey)

	return testValidator
}

// Name is the name of the test validator
func (tv *TestValidator) Name() string {
	return fmt.Sprintf("validator-%d-%s", tv.Index, tv.t.Name())
}

// Dir is the directory where the test validator files are stored
func (tv *TestValidator) Dir() string {
	return filepath.Join(tv.Home, tv.Name())
}

// Generate Ed25519 Private Key
func (tv *TestValidator) genPrivKeyAndShares() {
	privKey := ed25519.GenPrivKey()
	pubKey := privKey.PubKey()
	filePVKey := privval.FilePVKey{
		Address: pubKey.Address(),
		PubKey:  pubKey,
		PrivKey: privKey,
	}
	tv.generateShares(filePVKey)
}

func (tv *TestValidator) generateShares(filePVKey privval.FilePVKey) {
	tv.PubKey = filePVKey.PubKey
	shares, err := signer.CreateCosignerShares(filePVKey, int64(tv.Threshold), int64(len(tv.Signers)))
	require.NoError(tv.t, err)
	tv.PrivKeyShares = shares
	for i, s := range tv.Signers {
		tv.t.Logf("{%s} -> Writing Key Share To File... ", s.Name())
		require.NoError(tv.t, os.MkdirAll(s.Dir(), 0700))
		privateFilename := filepath.Join(s.Dir(), "share.json")
		require.NoError(tv.t, signer.WriteCosignerShareFile(shares[i], privateFilename))
	}
}

func (tv *TestValidator) StartHorcruxCluster(
	ctx context.Context,
	network *docker.Network,
	sentriesPerSigner int,
) error {
	return StartCosignerContainers(tv.t, tv.Signers, tv.Sentries,
		tv.Threshold, len(tv.Signers), sentriesPerSigner, network)
}

func (tv *TestValidator) WaitForConsecutiveBlocks(blocks int64) error {
	return tv.Sentries[0].WaitForConsecutiveBlocks(blocks, tv.PubKey.Address())
}

func (tv *TestValidator) EnsureNotSlashed() error {
	return tv.Sentries[0].EnsureNotSlashed(tv.PubKey.Address())
}
