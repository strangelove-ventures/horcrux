package test

import (
	"fmt"
	"os"
	"path/filepath"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	"github.com/ory/dockertest"
	"github.com/strangelove-ventures/horcrux/signer"
)

type Validator struct {
	Index     int
	Sentries  Nodes
	Signers   Signers
	tl        Logger
	Home      string
	PubKeys   map[string]cometcrypto.PubKey
	Threshold uint8
}

func NewHorcruxValidator(
	tl Logger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	index int,
	numSigners int,
	threshold uint8,
	chains ...*ChainType,
) (*Validator, error) {
	var sentries Nodes
	chainIDs := make([]string, 0, len(chains))
	for _, chain := range chains {
		sentries = append(sentries,
			MakeNodes(
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
		chainIDs = append(chainIDs, chain.ChainID)
	}
	testValidator := &Validator{
		Index:     index,
		Sentries:  sentries,
		Signers:   MakeSigners(index, numSigners, home, pool, networkID, tl),
		tl:        tl,
		Home:      home,
		Threshold: threshold,
		PubKeys:   make(map[string]cometcrypto.PubKey),
	}
	if err := testValidator.genPrivKeyAndShares(nil, chainIDs...); err != nil {
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
	threshold uint8,
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
		PubKeys:   make(map[string]cometcrypto.PubKey),
	}
	if err := testValidator.genPrivKeyAndShares(&privValKey, chainID); err != nil {
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

func (tv *Validator) genRSAShares() error {
	rsaShares, err := signer.CreateCosignerSharesRSA(len(tv.Signers))
	if err != nil {
		return err
	}

	for i, s := range tv.Signers {
		tv.tl.Logf("{%s} -> Writing RSA Key Share To File... ", s.Name())
		if err := os.MkdirAll(s.Dir(), 0700); err != nil {
			return err
		}

		cosignerFilename := filepath.Join(s.Dir(), "rsa_keys.json")
		if err := signer.WriteCosignerShareRSAFile(rsaShares[i], cosignerFilename); err != nil {
			return err
		}
	}

	return nil
}

// genPrivKeyAndShares generates cosigner RSA shares.
// If existingKey is nil, generates Ed25519 key shares, otherwise shards existing key.
func (tv *Validator) genPrivKeyAndShares(existingKey *privval.FilePVKey, chainIDs ...string) error {
	if err := tv.genRSAShares(); err != nil {
		return err
	}

	for _, chainID := range chainIDs {
		if err := tv.genEd25519Shares(existingKey, chainID); err != nil {
			return err
		}
	}

	return nil
}

func (tv *Validator) genEd25519Shares(
	existingKey *privval.FilePVKey,
	chainID string,
) error {
	var key privval.FilePVKey
	if existingKey != nil {
		key = *existingKey
	} else {
		privKey := cometcryptoed25519.GenPrivKey()
		pubKey := privKey.PubKey()
		key = privval.FilePVKey{
			Address: pubKey.Address(),
			PubKey:  pubKey,
			PrivKey: privKey,
		}
	}

	tv.PubKeys[chainID] = key.PubKey

	shares, err := signer.CreateCosignerShares(key, tv.Threshold, uint8(len(tv.Signers)))
	if err != nil {
		return err
	}

	for i, s := range tv.Signers {
		tv.tl.Logf("{%s} -> Writing Ed25519 Key Share To File... ", s.Name())

		privateFilename := filepath.Join(s.Dir(), fmt.Sprintf("%s_share.json", chainID))
		if err := signer.WriteCosignerShareFile(shares[i], privateFilename); err != nil {
			return err
		}
	}
	return nil
}

func (tv *Validator) StartHorcruxCluster(
	sentriesPerSigner int,
) error {
	return StartCosignerContainers(tv.Signers, tv.Sentries,
		tv.Threshold, sentriesPerSigner)
}

func (tv *Validator) WaitForConsecutiveBlocks(chainID string, blocks int64) error {
	for _, n := range tv.Sentries {
		if n.ChainID == chainID {
			return n.WaitForConsecutiveBlocks(blocks, tv.PubKeys[chainID].Address())
		}
	}
	return fmt.Errorf("no sentry found with chain id: %s", chainID)
}

func (tv *Validator) EnsureNotSlashed(chainID string) error {
	for _, n := range tv.Sentries {
		if n.ChainID == chainID {
			return n.EnsureNotSlashed(tv.PubKeys[chainID].Address())
		}
	}
	return fmt.Errorf("no sentry found with chain id: %s", chainID)
}
