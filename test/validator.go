package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	"github.com/ory/dockertest"
	"github.com/strangelove-ventures/horcrux/signer"
	"golang.org/x/sync/errgroup"
)

type Validator struct {
	Index     int
	Sentries  map[string]Nodes
	Signers   Signers
	tl        Logger
	Home      string
	PubKeys   map[string]cometcrypto.PubKey
	Threshold uint8
}

func NewHorcruxValidator(
	ctx context.Context,
	tl Logger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	index int,
	numSigners int,
	threshold uint8,
	dkg bool,
	chains ...*ChainType,
) (*Validator, error) {
	chainIDs := make([]string, 0, len(chains))
	sentries := make(map[string]Nodes)
	for _, chain := range chains {
		sentries[chain.ChainID] = MakeNodes(
			index,
			chain.NumSentries,
			home,
			chain.ChainID,
			chain,
			pool,
			networkID,
			tl,
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
	if err := testValidator.genPrivKeyAndShards(ctx, nil, dkg, chainIDs...); err != nil {
		return nil, err
	}
	return testValidator, nil
}

func NewHorcruxValidatorWithPrivValKey(
	ctx context.Context,
	tl Logger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	index int,
	numSentries int,
	numSigners int,
	threshold uint8,
	chainType *ChainType,
	privValKey privval.FilePVKey,
) (*Validator, error) {
	chainID := chainType.ChainID
	sentries := make(map[string]Nodes)
	sentries[chainID] = MakeNodes(index, numSentries, home, chainID, chainType, pool, networkID, tl)
	testValidator := &Validator{
		Index:     index,
		Sentries:  sentries,
		Signers:   MakeSigners(index, numSigners, home, pool, networkID, tl),
		tl:        tl,
		Home:      home,
		Threshold: threshold,
		PubKeys:   make(map[string]cometcrypto.PubKey),
	}
	if err := testValidator.genPrivKeyAndShards(ctx, &privValKey, false, chainID); err != nil {
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
	rsaShards, err := signer.CreateCosignerRSAShards(len(tv.Signers))
	if err != nil {
		return err
	}

	for i, s := range tv.Signers {
		tv.tl.Logf("{%s} -> Writing RSA Key Shard To File... ", s.Name())
		if err := os.MkdirAll(s.Dir(), 0700); err != nil {
			return err
		}

		cosignerFilename := filepath.Join(s.Dir(), "rsa_keys.json")
		if err := signer.WriteCosignerRSAShardFile(rsaShards[i], cosignerFilename); err != nil {
			return err
		}
	}

	return nil
}

// performDKG runs the DKG keygen process via libp2p.
func (tv *Validator) performDKG(ctx context.Context, chainID string) error {
	var eg errgroup.Group
	for _, s := range tv.Signers {
		s := s
		eg.Go(func() error { return s.InitThresholdModeConfig(ctx, tv.Sentries[chainID], tv.Signers, tv.Threshold) })
	}
	if err := eg.Wait(); err != nil {
		return err
	}

	for i, s := range tv.Signers {
		s := s
		i := i
		eg.Go(func() error {
			return s.ExecHorcruxCmd(ctx, s.Name(), "dkg", "--chain-id", chainID, "--id", fmt.Sprint(i+1))
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}

	pubKey, err := tv.Signers[0].PubKey(chainID)
	if err != nil {
		return err
	}

	tv.PubKeys[chainID] = pubKey

	return nil
}

// genPrivKeyAndShards generates cosigner RSA shards.
// If existingKey is nil, generates Ed25519 key shards, otherwise shards existing key.
func (tv *Validator) genPrivKeyAndShards(
	ctx context.Context,
	existingKey *privval.FilePVKey,
	dkg bool,
	chainIDs ...string,
) error {
	if err := tv.genRSAShares(); err != nil {
		return err
	}

	for _, chainID := range chainIDs {
		if dkg {
			if err := tv.performDKG(ctx, chainID); err != nil {
				return err
			}
			continue
		}

		if err := tv.genEd25519Shards(existingKey, chainID); err != nil {
			return err
		}
	}

	return nil
}

func (tv *Validator) genEd25519Shards(
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

	shards, err := signer.CreateCosignerEd25519Shards(key, tv.Threshold, uint8(len(tv.Signers)))
	if err != nil {
		return err
	}

	for i, s := range tv.Signers {
		tv.tl.Logf("{%s} -> Writing Ed25519 Key Shard To File... ", s.Name())

		privateFilename := filepath.Join(s.Dir(), fmt.Sprintf("%s_shard.json", chainID))
		if err := signer.WriteCosignerEd25519ShardFile(shards[i], privateFilename); err != nil {
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
	for sentryChainID, n := range tv.Sentries {
		if sentryChainID == chainID {
			return n[0].WaitForConsecutiveBlocks(blocks, tv.PubKeys[chainID].Address())
		}
	}
	return fmt.Errorf("no sentry found with chain id: %s", chainID)
}

func (tv *Validator) EnsureNotSlashed(chainID string) error {
	for sentryChainID, n := range tv.Sentries {
		if sentryChainID == chainID {
			return n[0].EnsureNotSlashed(tv.PubKeys[chainID].Address())
		}
	}
	return fmt.Errorf("no sentry found with chain id: %s", chainID)
}
