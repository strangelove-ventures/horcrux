package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"os"
	"testing"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"golang.org/x/sync/errgroup"
)

func TestThresholdValidator2of2Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 2, 2)
}

func TestThresholdValidator2of2Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 2, 2)
}

func TestThresholdValidator3of3Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 3, 3)
}

func TestThresholdValidator3of3Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 3, 3)
}

func TestThresholdValidator2of3Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 2, 3)
}

func TestThresholdValidator2of3Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 2, 3)
}

func TestThresholdValidator3of5Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 3, 5)
}

func TestThresholdValidator3of5Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 3, 5)
}

func loadKeyForLocalCosigner(
	cosigner *LocalCosigner,
	keyType string,
	pubKey []byte,
	chainID string,
	privateShard []byte,
) error {
	key := &CosignerKey{
		KeyType:      keyType,
		PubKey:       pubKey,
		PrivateShard: privateShard,
		ID:           cosigner.GetID(),
	}

	keyBz, err := json.Marshal(key)
	if err != nil {
		return err
	}

	return os.WriteFile(cosigner.config.KeyFilePathCosigner(chainID), keyBz, 0600)
}

func testThresholdValidator(t *testing.T, keyType string, threshold, total uint8) {
	cosigners := getTestLocalCosigners(t, keyType, threshold, total)

	thresholdCosigners := make([]Cosigner, 0, threshold-1)

	for i, cosigner := range cosigners {
		require.Equal(t, i+1, cosigner.GetID())

		if i != 0 && len(thresholdCosigners) != int(threshold)-1 {
			thresholdCosigners = append(thresholdCosigners, cosigner)
		}
	}

	leader := &MockLeader{id: 1}

	validator := NewThresholdValidator(
		cometlog.NewNopLogger(),
		cosigners[0].config,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer validator.Stop()

	leader.leader = validator

	ctx := context.Background()

	err := validator.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cometproto.ProposalType,
	}

	block := ProposalToBlock(testChainID, &proposal)

	signature, _, err := validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	require.True(t, validator.myCosigner.VerifySignature(testChainID, block.SignBytes, signature))

	firstSignature := signature

	require.Len(t, firstSignature, 64)

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     20,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	block = ProposalToBlock(testChainID, &proposal)

	validator.nonceCache.LoadN(ctx, 1)

	// should be able to sign same proposal with only differing timestamp
	_, _, err = validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	// construct different block ID for proposal at same height as highest signed
	randHash := cometrand.Bytes(tmhash.Size)
	blockID := cometproto.BlockID{Hash: randHash,
		PartSetHeader: cometproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = cometproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    cometproto.ProposalType,
		BlockID: blockID,
	}

	validator.nonceCache.LoadN(ctx, 1)

	// different than single-signer mode, threshold mode will be successful for this,
	// but it will return the same signature as before.
	signature, _, err = validator.Sign(ctx, testChainID, ProposalToBlock(testChainID, &proposal))
	require.NoError(t, err)

	require.True(t, bytes.Equal(firstSignature, signature))

	proposal.Round = 19

	validator.nonceCache.LoadN(ctx, 1)

	// should not be able to sign lower than highest signed
	_, _, err = validator.Sign(ctx, testChainID, ProposalToBlock(testChainID, &proposal))
	require.Error(t, err, "double sign!")

	validator.nonceCache.LoadN(ctx, 1)

	// lower LSS should sign for different chain ID
	_, _, err = validator.Sign(ctx, testChainID2, ProposalToBlock(testChainID2, &proposal))
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	newValidator := NewThresholdValidator(
		cometlog.NewNopLogger(),
		cosigners[0].config,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer newValidator.Stop()

	newValidator.nonceCache.LoadN(ctx, 1)

	_, _, err = newValidator.Sign(ctx, testChainID, ProposalToBlock(testChainID, &proposal))
	require.Error(t, err, "double sign!")

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     21,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	proposalClone := proposal
	proposalClone.Timestamp = proposal.Timestamp.Add(2 * time.Millisecond)

	proposalClone2 := proposal
	proposalClone2.Timestamp = proposal.Timestamp.Add(4 * time.Millisecond)

	var eg errgroup.Group

	newValidator.nonceCache.LoadN(ctx, 3)

	eg.Go(func() error {
		_, _, err := newValidator.Sign(ctx, testChainID, ProposalToBlock(testChainID, &proposal))
		return err
	})
	eg.Go(func() error {
		_, _, err := newValidator.Sign(ctx, testChainID, ProposalToBlock(testChainID, &proposalClone))
		return err
	})
	eg.Go(func() error {
		_, _, err := newValidator.Sign(ctx, testChainID, ProposalToBlock(testChainID, &proposalClone2))
		return err
	})
	// signing higher block now should succeed
	err = eg.Wait()
	require.NoError(t, err)

	// Sign some votes from multiple sentries
	for i := 2; i < 50; i++ {
		newValidator.nonceCache.LoadN(ctx, 3)

		prevote := cometproto.Vote{
			Height:    int64(i),
			Round:     0,
			Type:      cometproto.PrevoteType,
			Timestamp: time.Now(),
		}

		prevoteClone := prevote
		prevoteClone.Timestamp = prevote.Timestamp.Add(2 * time.Millisecond)

		prevoteClone2 := prevote
		prevoteClone2.Timestamp = prevote.Timestamp.Add(4 * time.Millisecond)

		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, VoteToBlock(testChainID, &prevote))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, VoteToBlock(testChainID, &prevoteClone))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, VoteToBlock(testChainID, &prevoteClone2))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})

		err = eg.Wait()
		require.NoError(t, err)

		precommit := cometproto.Vote{
			Height:    int64(i),
			Round:     0,
			Type:      cometproto.PrecommitType,
			Timestamp: time.Now(),
		}

		precommitClone := precommit
		precommitClone.Timestamp = precommit.Timestamp.Add(2 * time.Millisecond)

		precommitClone2 := precommit
		precommitClone2.Timestamp = precommit.Timestamp.Add(4 * time.Millisecond)

		newValidator.nonceCache.LoadN(ctx, 3)

		eg.Go(func() error {
			start := time.Now()
			t.Log("Sign time", "duration", time.Since(start))
			_, _, err := newValidator.Sign(ctx, testChainID, VoteToBlock(testChainID, &precommit))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			t.Log("Sign time", "duration", time.Since(start))
			_, _, err := newValidator.Sign(ctx, testChainID, VoteToBlock(testChainID, &precommitClone))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, VoteToBlock(testChainID, &precommitClone2))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})

		err = eg.Wait()
		require.NoError(t, err)
	}
}

func getTestLocalCosigners(t *testing.T, keyType string, threshold, total uint8) []*LocalCosigner {
	eciesKeys := make([]*ecies.PrivateKey, total)
	pubKeys := make([]*ecies.PublicKey, total)
	cosigners := make([]*LocalCosigner, total)

	for i := uint8(0); i < total; i++ {
		eciesKey, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		eciesKeys[i] = eciesKey

		pubKeys[i] = &eciesKey.PublicKey
	}

	var (
		pubKey     []byte
		privShards = make([][]byte, total)
	)

	switch keyType {
	case CosignerKeyTypeEd25519:
		privateKey := cometcryptoed25519.GenPrivKey()
		privKeyBytes := privateKey[:]
		privShardsEd25519 := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

		for i := range privShardsEd25519 {
			privShards[i] = privShardsEd25519[i][:]
		}
		pubKey = privateKey.PubKey().Bytes()
	case CosignerKeyTypeBn254:
		suite := bn256.NewSuite()
		secret := suite.G1().Scalar().Pick(suite.RandomStream())
		priPoly := share.NewPriPoly(suite.G2(), int(threshold), secret, suite.RandomStream())
		pubPoly := priPoly.Commit(suite.G2().Point().Base())
		var err error
		pk := pubPoly.Commit()
		pubKey, err = pk.MarshalBinary()
		require.NoError(t, err)

		for i, x := range priPoly.Shares(int(total)) {
			privShards[i], err = x.V.MarshalBinary()
			require.NoError(t, err)
		}
	}

	tmpDir := t.TempDir()

	cosignersConfig := make(CosignersConfig, total)

	for i := range pubKeys {
		cosignersConfig[i] = CosignerConfig{
			ShardID: i + 1,
		}
	}

	for i := range pubKeys {
		cosignerDir := filepath.Join(tmpDir, fmt.Sprintf("cosigner_%d", i+1))
		err := os.MkdirAll(cosignerDir, 0777)
		require.NoError(t, err)

		cosignerConfig := &RuntimeConfig{
			HomeDir:  cosignerDir,
			StateDir: cosignerDir,
			Config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold: int(threshold),
					Cosigners: cosignersConfig,
				},
			},
		}

		cosigner := NewLocalCosigner(
			cometlog.NewNopLogger(),
			cosignerConfig,
			NewCosignerSecurityECIES(
				CosignerECIESKey{
					ID:        i + 1,
					ECIESKey:  eciesKeys[i],
					ECIESPubs: pubKeys,
				},
			),
			"",
		)
		require.NoError(t, err)

		cosigners[i] = cosigner

		err = loadKeyForLocalCosigner(cosigner, keyType, pubKey, testChainID, privShards[i])
		require.NoError(t, err)

		err = loadKeyForLocalCosigner(cosigner, keyType, pubKey, testChainID2, privShards[i])
		require.NoError(t, err)
	}

	return cosigners
}

func testThresholdValidatorLeaderElection(t *testing.T, threshold, total uint8) {
	cosigners := getTestLocalCosigners(t, CosignerKeyTypeEd25519, threshold, total)

	thresholdValidators := make([]*ThresholdValidator, 0, total)
	var leader *ThresholdValidator
	leaders := make([]*MockLeader, total)

	ctx := context.Background()

	for i, cosigner := range cosigners {
		peers := make([]Cosigner, 0, len(cosigners)-1)
		for j, otherCosigner := range cosigners {
			if i != j {
				peers = append(peers, otherCosigner)
			}
		}
		leaders[i] = &MockLeader{id: cosigner.GetID(), leader: leader}
		tv := NewThresholdValidator(
			cometlog.NewNopLogger(),
			cosigner.config,
			int(threshold),
			time.Second,
			1,
			cosigner,
			peers,
			leaders[i],
		)
		if i == 0 {
			leader = tv
			leaders[i].leader = tv
		}

		thresholdValidators = append(thresholdValidators, tv)
		defer tv.Stop()

		err := tv.LoadSignStateIfNecessary(testChainID)
		require.NoError(t, err)

		require.NoError(t, tv.Start(ctx))
	}

	quit := make(chan bool)
	done := make(chan bool)

	go func() {
		for i := 0; true; i++ {
			select {
			case <-quit:
				done <- true
				return
			default:
			}
			// simulate leader election
			for _, l := range leaders {
				l.SetLeader(nil)
			}
			t.Log("No leader")

			// time without a leader
			time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

			newLeader := thresholdValidators[i%len(thresholdValidators)]
			for _, l := range leaders {
				l.SetLeader(newLeader)
			}
			t.Logf("New leader: %d", newLeader.myCosigner.GetID())

			// time with new leader
			time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec
		}
	}()

	// sign 20 blocks (proposal, prevote, precommit)
	for i := 0; i < 20; i++ {
		var wg sync.WaitGroup
		wg.Add(len(thresholdValidators))
		var mu sync.Mutex
		success := false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				proposal := cometproto.Proposal{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.ProposalType,
				}

				signature, _, err := tv.Sign(ctx, testChainID, ProposalToBlock(testChainID, &proposal))
				if err != nil {
					t.Log("Proposal sign failed", "error", err)
					return
				}

				signBytes := comet.ProposalSignBytes(testChainID, &proposal)

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !tv.myCosigner.VerifySignature(testChainID, signBytes, sig) {
					t.Log("Proposal signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()
		require.True(t, success) // at least one should succeed so that the block is not missed.
		wg.Add(len(thresholdValidators))
		success = false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				preVote := cometproto.Vote{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.PrevoteType,
				}

				signature, _, err := tv.Sign(ctx, testChainID, VoteToBlock(testChainID, &preVote))
				if err != nil {
					t.Log("PreVote sign failed", "error", err)
					return
				}

				signBytes := comet.VoteSignBytes(testChainID, &preVote)

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !tv.myCosigner.VerifySignature(testChainID, signBytes, sig) {
					t.Log("PreVote signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()
		require.True(t, success) // at least one should succeed so that the block is not missed.
		wg.Add(len(thresholdValidators))
		success = false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				preCommit := cometproto.Vote{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.PrecommitType,
				}

				signature, _, err := tv.Sign(ctx, testChainID, VoteToBlock(testChainID, &preCommit))
				if err != nil {
					t.Log("PreCommit sign failed", "error", err)
					return
				}

				signBytes := comet.VoteSignBytes(testChainID, &preCommit)

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !tv.myCosigner.VerifySignature(testChainID, signBytes, sig) {
					t.Log("PreCommit signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()

		require.True(t, success) // at least one should succeed so that the block is not missed.
	}

	quit <- true
	<-done
}

func TestThresholdValidatorLeaderElection2of3(t *testing.T) {
	testThresholdValidatorLeaderElection(t, 2, 3)
}
