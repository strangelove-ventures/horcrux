package signer_test

import (
	"errors"
	"testing"

	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestKeygenCosigner(t *testing.T) {
	const (
		threshold = 2
		total     = 3
	)

	cosigners, err := signer.LocalDKG(threshold, total)
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
