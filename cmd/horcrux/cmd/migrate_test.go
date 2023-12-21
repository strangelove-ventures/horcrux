package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/strangelove-ventures/horcrux/v3/cmd/horcrux/cmd/testdata"
	"github.com/stretchr/testify/require"
)

func TestMigrateV2toV3(t *testing.T) {
	tmp := t.TempDir()

	configFile := filepath.Join(tmp, "config.yaml")

	err := os.WriteFile(configFile, testdata.ConfigV2, 0600)
	require.NoError(t, err)

	keyShareFile := filepath.Join(tmp, "share.json")

	err = os.WriteFile(keyShareFile, testdata.CosignerKeyV2, 0600)
	require.NoError(t, err)

	cmd := rootCmd()
	cmd.SetOutput(io.Discard)
	args := []string{"--home", tmp, "config", "migrate"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	require.NoFileExists(t, keyShareFile)

	newKeyShardFile := filepath.Join(tmp, "test_shard.json")
	require.FileExists(t, newKeyShardFile)

	newRSAKeyFile := filepath.Join(tmp, "rsa_keys.json")
	require.FileExists(t, newRSAKeyFile)

	newKeyShardFileBz, err := os.ReadFile(newKeyShardFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerEd25519KeyMigrated, string(newKeyShardFileBz))

	newRSAKeyFileBz, err := os.ReadFile(newRSAKeyFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerRSAKeyMigrated, string(newRSAKeyFileBz))

	newConfigFileBz, err := os.ReadFile(configFile)
	require.NoError(t, err)

	require.Equal(t, testdata.ConfigMigrated, string(newConfigFileBz))
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
	tmp := t.TempDir()

	keyDir := filepath.Join(tmp, "keys")
	err := os.Mkdir(keyDir, 0700)
	require.NoError(t, err)

	configFile := filepath.Join(tmp, "config.yaml")

	err = os.WriteFile(configFile, testdata.ConfigV2, 0600)
	require.NoError(t, err)

	keyShareFile := filepath.Join(keyDir, "share.json")

	err = appendToFile(configFile, fmt.Sprintf("key-file: %s", keyShareFile))
	require.NoError(t, err)

	err = os.WriteFile(keyShareFile, testdata.CosignerKeyV2, 0600)
	require.NoError(t, err)

	cmd := rootCmd()
	cmd.SetOutput(io.Discard)
	args := []string{"--home", tmp, "config", "migrate"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	require.NoFileExists(t, keyShareFile)

	newKeyShardFile := filepath.Join(keyDir, "test_shard.json")
	require.FileExists(t, newKeyShardFile)

	newRSAKeyFile := filepath.Join(keyDir, "rsa_keys.json")
	require.FileExists(t, newRSAKeyFile)

	newKeyShardFileBz, err := os.ReadFile(newKeyShardFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerEd25519KeyMigrated, string(newKeyShardFileBz))

	newRSAKeyFileBz, err := os.ReadFile(newRSAKeyFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerRSAKeyMigrated, string(newRSAKeyFileBz))

	newConfigFileBz, err := os.ReadFile(configFile)
	require.NoError(t, err)

	require.Equal(t, fmt.Sprintf("keyDir: %s\n", keyDir)+testdata.ConfigMigrated, string(newConfigFileBz))
}

// Should migrate keys only if config has already been migrated
func TestMigrateV2toV3KeysOnly(t *testing.T) {
	tmp := t.TempDir()

	keyShareFile := filepath.Join(tmp, "share.json")

	err := os.WriteFile(keyShareFile, testdata.CosignerKeyV2, 0600)
	require.NoError(t, err)

	cmd := rootCmd()
	cmd.SetOutput(io.Discard)
	args := []string{"--home", tmp, "config", "migrate", "test"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	require.NoFileExists(t, keyShareFile)

	newKeyShardFile := filepath.Join(tmp, "test_shard.json")
	require.FileExists(t, newKeyShardFile)

	newRSAKeyFile := filepath.Join(tmp, "rsa_keys.json")
	require.FileExists(t, newRSAKeyFile)

	newKeyShardFileBz, err := os.ReadFile(newKeyShardFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerEd25519KeyMigrated, string(newKeyShardFileBz))

	newRSAKeyFileBz, err := os.ReadFile(newRSAKeyFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerRSAKeyMigrated, string(newRSAKeyFileBz))
}

// Should not modify config that is already in v3 format
func TestMigrateV2toV3ConfigAlreadyMigrated(t *testing.T) {
	tmp := t.TempDir()

	configFile := filepath.Join(tmp, "config.yaml")

	err := os.WriteFile(configFile, []byte(testdata.ConfigMigrated), 0600)
	require.NoError(t, err)

	keyShareFile := filepath.Join(tmp, "share.json")

	err = os.WriteFile(keyShareFile, testdata.CosignerKeyV2, 0600)
	require.NoError(t, err)

	cmd := rootCmd()
	cmd.SetOutput(io.Discard)
	args := []string{"--home", tmp, "config", "migrate", "test"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	require.NoFileExists(t, keyShareFile)

	newKeyShardFile := filepath.Join(tmp, "test_shard.json")
	require.FileExists(t, newKeyShardFile)

	newRSAKeyFile := filepath.Join(tmp, "rsa_keys.json")
	require.FileExists(t, newRSAKeyFile)

	newKeyShardFileBz, err := os.ReadFile(newKeyShardFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerEd25519KeyMigrated, string(newKeyShardFileBz))

	newRSAKeyFileBz, err := os.ReadFile(newRSAKeyFile)
	require.NoError(t, err)

	require.Equal(t, testdata.CosignerRSAKeyMigrated, string(newRSAKeyFileBz))

	newConfigFileBz, err := os.ReadFile(configFile)
	require.NoError(t, err)

	require.Equal(t, testdata.ConfigMigrated, string(newConfigFileBz))
}

// Should not modify config or keys that are already in v3 format
func TestMigrateV2toV3AlreadyMigrated(t *testing.T) {
	tmp := t.TempDir()

	configFile := filepath.Join(tmp, "config.yaml")

	err := os.WriteFile(configFile, []byte(testdata.ConfigMigrated), 0600)
	require.NoError(t, err)

	ed25519KeyShardFile := filepath.Join(tmp, "test_shard.json")

	err = os.WriteFile(ed25519KeyShardFile, []byte(testdata.CosignerEd25519KeyMigrated), 0600)
	require.NoError(t, err)

	rsaKeyShardFile := filepath.Join(tmp, "rsa_keys.json")

	err = os.WriteFile(rsaKeyShardFile, []byte(testdata.CosignerRSAKeyMigrated), 0600)
	require.NoError(t, err)

	cmd := rootCmd()
	cmd.SetOutput(io.Discard)
	args := []string{"--home", tmp, "config", "migrate", "test"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.Error(t, err)
	require.EqualError(
		t, err,
		fmt.Sprintf(
			"error loading v2 key file: stat %s: no such file or directory",
			filepath.Join(tmp, "share.json"),
		),
	)
}
