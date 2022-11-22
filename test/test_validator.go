package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ory/dockertest"
	"github.com/strangelove-ventures/horcrux/signer"
	crypto "github.com/tendermint/tendermint/crypto"
	ed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/privval"
)

type TestValidator struct {
	Index         int
	Sentries      TestNodes
	Signers       TestSigners
	tl            TestLogger
	Home          string
	PubKey        crypto.PubKey
	PrivKeyShares []signer.CosignerKey
	Threshold     int
}

func NewHorcruxValidator(
	tl TestLogger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	index int,
	numSigners int,
	threshold int,
	chains ...*ChainType,
) (*TestValidator, error) {
	var sentries TestNodes
	for _, chain := range chains {
		sentries = append(sentries,
			MakeTestNodes(
				index,
				chain.NumSentries,
				home,
				chain.ChainID,
				chain,
				pool,
				networkID,
				tl,
			)...,
		)
	}
	testValidator := &TestValidator{
		Index:     index,
		Sentries:  sentries,
		Signers:   MakeTestSigners(index, numSigners, home, pool, networkID, tl),
		tl:        tl,
		Home:      home,
		Threshold: threshold,
	}
	if err := testValidator.genPrivKeyAndShares(); err != nil {
		return nil, err
	}
	return testValidator, nil
}

func NewHorcruxValidatorWithPrivValKey(
	tl TestLogger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	chainID string,
	index int,
	numSentries int,
	numSigners int,
	threshold int,
	chainType *ChainType,
	privValKey privval.FilePVKey,
) (*TestValidator, error) {
	testValidator := &TestValidator{
		Index:     index,
		Sentries:  MakeTestNodes(index, numSentries, home, chainID, chainType, pool, networkID, tl),
		Signers:   MakeTestSigners(index, numSigners, home, pool, networkID, tl),
		tl:        tl,
		Home:      home,
		Threshold: threshold,
	}
	if err := testValidator.generateShares(privValKey); err != nil {
		return nil, err
	}
	return testValidator, nil
}

// Name is the name of the test validator
func (tv *TestValidator) Name() string {
	return fmt.Sprintf("validator-%d-%s", tv.Index, tv.tl.Name())
}

// Dir is the directory where the test validator files are stored
func (tv *TestValidator) Dir() string {
	return filepath.Join(tv.Home, tv.Name())
}

// Generate Ed25519 Private Key
func (tv *TestValidator) genPrivKeyAndShares() error {
	privKey := ed25519.GenPrivKey()
	pubKey := privKey.PubKey()
	filePVKey := privval.FilePVKey{
		Address: pubKey.Address(),
		PubKey:  pubKey,
		PrivKey: privKey,
	}
	return tv.generateShares(filePVKey)
}

func (tv *TestValidator) generateShares(filePVKey privval.FilePVKey) error {
	tv.PubKey = filePVKey.PubKey
	shares, err := signer.CreateCosignerShares(filePVKey, int64(tv.Threshold), int64(len(tv.Signers)))
	if err != nil {
		return err
	}
	tv.PrivKeyShares = shares
	for i, s := range tv.Signers {
		tv.tl.Logf("{%s} -> Writing Key Share To File... ", s.Name())
		if err := os.MkdirAll(s.Dir(), 0700); err != nil {
			return err
		}
		privateFilename := filepath.Join(s.Dir(), "share.json")
		if err := signer.WriteCosignerShareFile(shares[i], privateFilename); err != nil {
			return err
		}
	}
	return nil
}

func (tv *TestValidator) StartHorcruxCluster(
	ctx context.Context,
	sentriesPerSigner int,
) error {
	return StartCosignerContainers(tv.Signers, tv.Sentries,
		tv.Threshold, len(tv.Signers), sentriesPerSigner)
}

func (tv *TestValidator) WaitForConsecutiveBlocks(chainID string, blocks int64) error {
	for _, n := range tv.Sentries {
		if n.ChainID == chainID {
			return n.WaitForConsecutiveBlocks(blocks, tv.PubKey.Address())
		}
	}
	return fmt.Errorf("no sentry found with chain id: %s", chainID)
}

func (tv *TestValidator) EnsureNotSlashed(chainID string) error {
	for _, n := range tv.Sentries {
		if n.ChainID == chainID {
			return n.EnsureNotSlashed(tv.PubKey.Address())
		}
	}
	return fmt.Errorf("no sentry found with chain id: %s", chainID)
}
