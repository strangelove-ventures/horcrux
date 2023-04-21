package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ory/dockertest"
	"github.com/strangelove-ventures/horcrux/signer"
	tmcrypto "github.com/tendermint/tendermint/crypto"
	tmcryptoed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/privval"
)

type Validator struct {
	Index         int
	Sentries      Nodes
	Signers       Signers
	tl            Logger
	Home          string
	PubKey        tmcrypto.PubKey
	PrivKeyShares []signer.CosignerKey
	Threshold     int
}

func NewHorcruxValidator(
	tl Logger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	chainID string,
	index int,
	numSentries int,
	numSigners int,
	threshold int,
	chainType *ChainType,
) (*Validator, error) {
	testValidator := &Validator{
		Index:     index,
		Sentries:  MakeNodes(index, numSentries, home, chainID, chainType, pool, networkID, tl),
		Signers:   MakeSigners(index, numSigners, home, pool, networkID, tl),
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
	tl Logger,
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
) (*Validator, error) {
	testValidator := &Validator{
		Index:     index,
		Sentries:  MakeNodes(index, numSentries, home, chainID, chainType, pool, networkID, tl),
		Signers:   MakeSigners(index, numSigners, home, pool, networkID, tl),
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
func (tv *Validator) Name() string {
	return fmt.Sprintf("validator-%d-%s", tv.Index, tv.tl.Name())
}

// Dir is the directory where the test validator files are stored
func (tv *Validator) Dir() string {
	return filepath.Join(tv.Home, tv.Name())
}

// Generate Ed25519 Private Key
func (tv *Validator) genPrivKeyAndShares() error {
	privKey := tmcryptoed25519.GenPrivKey()
	pubKey := privKey.PubKey()
	filePVKey := privval.FilePVKey{
		Address: pubKey.Address(),
		PubKey:  pubKey,
		PrivKey: privKey,
	}
	return tv.generateShares(filePVKey)
}

func (tv *Validator) generateShares(filePVKey privval.FilePVKey) error {
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

func (tv *Validator) StartHorcruxCluster(
	ctx context.Context,
	sentriesPerSigner int,
) error {
	return StartCosignerContainers(tv.Signers, tv.Sentries,
		tv.Threshold, len(tv.Signers), sentriesPerSigner)
}

func (tv *Validator) WaitForConsecutiveBlocks(blocks int64) error {
	return tv.Sentries[0].WaitForConsecutiveBlocks(blocks, tv.PubKey.Address())
}

func (tv *Validator) EnsureNotSlashed() error {
	return tv.Sentries[0].EnsureNotSlashed(tv.PubKey.Address())
}
