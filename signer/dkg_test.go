package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"golang.org/x/sync/errgroup"
)

func TestNetworkDKG(t *testing.T) {
	ctx := context.Background()

	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey3, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	cosigners := []CosignerConfig{
		{
			ShardID: 1,
			P2PAddr: "tcp://127.0.0.1:8062",
		},
		{
			ShardID: 2,
			P2PAddr: "tcp://127.0.0.1:8063",
		},
		{
			ShardID: 3,
			P2PAddr: "tcp://127.0.0.1:8064",
		},
	}

	rsaPubs := []*rsa.PublicKey{
		&rsaKey1.PublicKey,
		&rsaKey2.PublicKey,
		&rsaKey3.PublicKey,
	}

	rsaKeys := []CosignerRSAKey{
		{
			ID:      1,
			RSAKey:  *rsaKey1,
			RSAPubs: rsaPubs,
		},
		{
			ID:      2,
			RSAKey:  *rsaKey2,
			RSAPubs: rsaPubs,
		},
		{
			ID:      3,
			RSAKey:  *rsaKey3,
			RSAPubs: rsaPubs,
		},
	}

	const threshold = 2

	var eg errgroup.Group

	shards := make([]*CosignerEd25519Key, len(cosigners))

	for i, c := range cosigners {
		id := c.ShardID
		i := i
		eg.Go(func() (err error) {
			shards[i], err = NetworkDKG(ctx, cosigners, id, rsaKeys[i], threshold)
			return err
		})
	}

	require.NoError(t, eg.Wait())

	pubKey := shards[0].PubKey

	privShards := make([]tsed25519.Scalar, len(cosigners))

	for i, shard := range shards {
		privShards[i] = shard.PrivateShard
	}

	testThresholdValidatorWithShards(t, threshold, uint8(len(cosigners)), pubKey, privShards)
}

func TestKeygenCosigner(t *testing.T) {
	const (
		threshold = 2
		total     = 3
	)

	cosigners, err := LocalDKG(threshold, total)
	require.NoError(t, err)

	var pubCmp *eddsa.Public
	secrets := make(map[party.ID]*eddsa.SecretShare)

	for _, c := range cosigners {
		p := c.Public()
		secrets[c.ID] = c.Secret()
		if pubCmp == nil {
			pubCmp = p
			continue
		}
		err := CompareOutput(pubCmp, p)
		require.NoError(t, err)
	}

	err = ValidateSecrets(secrets, pubCmp)
	require.NoError(t, err)
}

func CompareOutput(public1, public2 *eddsa.Public) error {
	if !public1.Equal(public2) {
		return errors.New("shares not equal")
	}
	partyIDs1 := public1.PartyIDs
	partyIDs2 := public2.PartyIDs
	if len(partyIDs1) != len(partyIDs2) {
		return errors.New("partyIDs are not the same length")
	}

	for i, id1 := range partyIDs1 {
		if id1 != partyIDs2[i] {
			return errors.New("partyIDs are not the same")
		}

		publicShare1 := public1.Shares[partyIDs1[i]]
		publicShare2 := public2.Shares[partyIDs2[i]]
		if publicShare1.Equal(publicShare2) != 1 {
			return errors.New("different public keys")
		}
	}

	if !public1.GroupKey.Equal(public2.GroupKey) {
		return errors.New("groupKeys not computed the same way")
	}

	return nil
}

func ValidateSecrets(secrets map[party.ID]*eddsa.SecretShare, public *eddsa.Public) error {
	fullSecret := ristretto.NewScalar()

	for id, secret := range secrets {
		pk1 := &secret.Public
		pk2, ok := public.Shares[id]
		if !ok {
			return errors.New("party %d has no share")
		}

		if pk1.Equal(pk2) != 1 {
			return errors.New("pk not the same")
		}

		lagrange, err := id.Lagrange(public.PartyIDs)
		if err != nil {
			return err
		}
		fullSecret.MultiplyAdd(lagrange, &secret.Secret, fullSecret)
	}

	fullPk := eddsa.NewPublicKeyFromPoint(new(ristretto.Element).ScalarBaseMult(fullSecret))
	if !public.GroupKey.Equal(fullPk) {
		return errors.New("computed groupKey does not match")
	}

	return nil
}
