package signer_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/signer"
	"github.com/stretchr/testify/require"
)

func TestPubKeyEncodingEd25519(t *testing.T) {
	const shard = `{"pubKey":"CiCIu0WMSHxz/vavkpyuYC3FTo6/nqvF8wCUKMxwqG7YsQ==","privateShard":"MqnT3qkD93YdbPkibp3rFtc2IUTtqn97Kgo5xlHblwE=","id":1}`

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
	const shard = `{"pubKey":"CiCIu0WMSHxz/vavkpyuYC3FTo6/nqvF8wCUKMxwqG7YsQ==","keyType":"ed25519","privateShard":"MqnT3qkD93YdbPkibp3rFtc2IUTtqn97Kgo5xlHblwE=","id":1}`

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
	const shard = `{"pubKey":"GiDdw489mIOeveo0DtEo92+I20JoPopwpxkYsfYiCCsFHw==","keyType":"bn254","privateShard":"FRPM7QlT/UJunPz5DgMAQ7H0RTZiEc9ZXQz16somPw0=","id":1}`

	key := new(signer.CosignerKey)

	err := json.Unmarshal([]byte(shard), key)
	require.NoError(t, err)

	require.Equal(t, "bn254", key.KeyType)
	require.Equal(t, 1, key.ID)

	pubz, err := base64.StdEncoding.DecodeString("3cOPPZiDnr3qNA7RKPdviNtCaD6KcKcZGLH2IggrBR8=")
	require.NoError(t, err)

	require.Equal(t, pubz, key.PubKey)

	privbz, err := base64.StdEncoding.DecodeString("FRPM7QlT/UJunPz5DgMAQ7H0RTZiEc9ZXQz16somPw0=")
	require.NoError(t, err)

	require.Equal(t, privbz, key.PrivateShard)
}
