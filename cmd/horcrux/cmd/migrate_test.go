package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrateV2toV3(t *testing.T) {
	v2ConfigBz, err := os.ReadFile("./fixtures/config-v2.yaml")
	require.NoError(t, err)

	v2ShareBz, err := os.ReadFile("./fixtures/cosigner-key-v2.json")
	require.NoError(t, err)

	tmp := t.TempDir()

	configFile := filepath.Join(tmp, "config.yaml")

	err = os.WriteFile(configFile, v2ConfigBz, 0600)
	require.NoError(t, err)

	keyShareFile := filepath.Join(tmp, "share.json")

	err = os.WriteFile(keyShareFile, v2ShareBz, 0600)
	require.NoError(t, err)

	cmd := rootCmd()
	cmd.SetOutput(io.Discard)
	args := []string{"--home", tmp, "config", "migrate"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	require.NoFileExists(t, keyShareFile)

	newKeyShareFile := filepath.Join(tmp, "test_share.json")
	require.FileExists(t, newKeyShareFile)

	newRSAKeyFile := filepath.Join(tmp, "rsa_keys.json")
	require.FileExists(t, newRSAKeyFile)

	newKeyShareFileBz, err := os.ReadFile(newKeyShareFile)
	require.NoError(t, err)

	v3ShareBz, err := os.ReadFile("./fixtures/cosigner-key-migrated-ed25519.json")
	require.NoError(t, err)

	require.Equal(t, string(v3ShareBz), string(newKeyShareFileBz))

	newRSAKeyFileBz, err := os.ReadFile(newRSAKeyFile)
	require.NoError(t, err)

	v3RSABz, err := os.ReadFile("./fixtures/cosigner-key-migrated-rsa.json")
	require.NoError(t, err)

	require.Equal(t, string(v3RSABz), string(newRSAKeyFileBz))

	newConfigFileBz, err := os.ReadFile(configFile)
	require.NoError(t, err)

	v3ConfigBz, err := os.ReadFile("./fixtures/config-migrated.yaml")
	require.NoError(t, err)

	require.Equal(t, string(v3ConfigBz), string(newConfigFileBz))
}

func appendToFile(file, append string) error {
	f, err := os.OpenFile(file,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(append)
	return err
}

func TestMigrateV2toV3DifferentKeyFilePath(t *testing.T) {
	v2ConfigBz, err := os.ReadFile("./fixtures/config-v2.yaml")
	require.NoError(t, err)

	v2ShareBz, err := os.ReadFile("./fixtures/cosigner-key-v2.json")
	require.NoError(t, err)

	tmp := t.TempDir()

	keyDir := filepath.Join(tmp, "keys")
	err = os.Mkdir(keyDir, 0700)
	require.NoError(t, err)

	configFile := filepath.Join(tmp, "config.yaml")

	err = os.WriteFile(configFile, v2ConfigBz, 0600)
	require.NoError(t, err)

	keyShareFile := filepath.Join(keyDir, "share.json")

	err = appendToFile(configFile, fmt.Sprintf("key-file: %s", keyShareFile))
	require.NoError(t, err)

	err = os.WriteFile(keyShareFile, v2ShareBz, 0600)
	require.NoError(t, err)

	cmd := rootCmd()
	cmd.SetOutput(io.Discard)
	args := []string{"--home", tmp, "config", "migrate"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	require.NoFileExists(t, keyShareFile)

	newKeyShareFile := filepath.Join(keyDir, "test_share.json")
	require.FileExists(t, newKeyShareFile)

	newRSAKeyFile := filepath.Join(keyDir, "rsa_keys.json")
	require.FileExists(t, newRSAKeyFile)

	newKeyShareFileBz, err := os.ReadFile(newKeyShareFile)
	require.NoError(t, err)

	v3ShareBz, err := os.ReadFile("./fixtures/cosigner-key-migrated-ed25519.json")
	require.NoError(t, err)

	require.Equal(t, string(v3ShareBz), string(newKeyShareFileBz))

	newRSAKeyFileBz, err := os.ReadFile(newRSAKeyFile)
	require.NoError(t, err)

	v3RSABz, err := os.ReadFile("./fixtures/cosigner-key-migrated-rsa.json")
	require.NoError(t, err)

	require.Equal(t, string(v3RSABz), string(newRSAKeyFileBz))

	newConfigFileBz, err := os.ReadFile(configFile)
	require.NoError(t, err)

	v3ConfigBz, err := os.ReadFile("./fixtures/config-migrated.yaml")
	require.NoError(t, err)

	require.Equal(t, fmt.Sprintf("key-dir: %s\n", keyDir)+string(v3ConfigBz), string(newConfigFileBz))
}
