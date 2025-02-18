package signer_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/signer"
	"github.com/stretchr/testify/require"
)

func TestPubKeyEncodingEd25519(t *testing.T) {
	const shard = `{
	"pubKey":"CiCIu0WMSHxz/vavkpyuYC3FTo6/nqvF8wCUKMxwqG7YsQ==",
	"privateShard":"MqnT3qkD93YdbPkibp3rFtc2IUTtqn97Kgo5xlHblwE=",
	"id":1
}`

	key := new(signer.CosignerKey)

	err := json.Unmarshal([]byte(shard), key)
	require.NoError(t, err)

	require.Equal(t, "ed25519", key.KeyType)
	require.Equal(t, 1, key.ID)

	pubz, err := base64.StdEncoding.DecodeString("iLtFjEh8c/72r5KcrmAtxU6Ov56rxfMAlCjMcKhu2LE=")
	require.NoError(t, err)

	require.Equal(t, pubz, key.PubKey)

	privbz, err := base64.StdEncoding.DecodeString("MqnT3qkD93YdbPkibp3rFtc2IUTtqn97Kgo5xlHblwE=")
	require.NoError(t, err)

	require.Equal(t, privbz, key.PrivateShard)
}

func TestPubKeyEncodingEd25519New(t *testing.T) {
	const shard = `{
	"pubKey":"CiCIu0WMSHxz/vavkpyuYC3FTo6/nqvF8wCUKMxwqG7YsQ==",
	"keyType":"ed25519",
	"privateShard":"MqnT3qkD93YdbPkibp3rFtc2IUTtqn97Kgo5xlHblwE=",
	"id":1
}`

	key := new(signer.CosignerKey)

	err := json.Unmarshal([]byte(shard), key)
	require.NoError(t, err)

	require.Equal(t, "ed25519", key.KeyType)
	require.Equal(t, 1, key.ID)

	pubz, err := base64.StdEncoding.DecodeString("iLtFjEh8c/72r5KcrmAtxU6Ov56rxfMAlCjMcKhu2LE=")
	require.NoError(t, err)

	require.Equal(t, pubz, key.PubKey)

	privbz, err := base64.StdEncoding.DecodeString("MqnT3qkD93YdbPkibp3rFtc2IUTtqn97Kgo5xlHblwE=")
	require.NoError(t, err)

	require.Equal(t, privbz, key.PrivateShard)
}

func TestPubKeyEncodingBn254(t *testing.T) {
	const shard = `{
	"pubKey":"mgYg3BYpPKAOYQUV9UPDLONDvIlhigtB1+Z3Vi7DXGZ6hFk=",
	"keyType":"bn254",
	"privateShard":"EfFU3vqRIlB/epaNyPbx9cvaclfFGK5g/l+hDEN1u1w=",
	"id":1
}`

	key := new(signer.CosignerKey)

	err := json.Unmarshal([]byte(shard), key)
	require.NoError(t, err)

	require.Equal(t, "bn254", key.KeyType)
	require.Equal(t, 1, key.ID)

	pubz, err := base64.StdEncoding.DecodeString("3BYpPKAOYQUV9UPDLONDvIlhigtB1+Z3Vi7DXGZ6hFk=")
	require.NoError(t, err)

	require.Equal(t, pubz, key.PubKey)

	privbz, err := base64.StdEncoding.DecodeString("EfFU3vqRIlB/epaNyPbx9cvaclfFGK5g/l+hDEN1u1w=")
	require.NoError(t, err)

	require.Equal(t, privbz, key.PrivateShard)
}
