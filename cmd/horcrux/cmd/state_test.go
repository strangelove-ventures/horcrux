package cmd

import (
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
)

func TestStateSetCmd(t *testing.T) {
	tmpHome := "/tmp/TestStateSetCmd"
	tmpConfig := path.Join(tmpHome, ".horcrux")
	chainid := "horcrux-1"

	err := os.Setenv("HOME", tmpHome)
	require.NoError(t, err)
	err = os.MkdirAll(tmpHome, 0777)
	require.NoError(t, err)

	cmd := initCmd()
	cmd.SetOutput(ioutil.Discard)
	cmd.SetArgs([]string{
		chainid,
		"tcp://10.168.0.1:1234",
		"-c",
		"-p", "tcp://10.168.1.2:2222|2,tcp://10.168.1.3:2222|3",
		"-l", "tcp://10.168.1.1:2222",
		"--timeout", "1500ms",
	})
	err = cmd.Execute()
	require.NoError(t, err)

	tcs := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			name:      "valid height",
			args:      []string{"123456789"},
			expectErr: false,
		},
		{
			name:      "invalid height",
			args:      []string{"-123456789"},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := setStateCmd()
			cmd.SetOutput(ioutil.Discard)
			cmd.SetArgs(tc.args)
			err = cmd.Execute()

			time.Sleep(1 * time.Second)

			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				height, err := strconv.ParseInt(tc.args[0], 10, 64)
				require.NoError(t, err)

				ss, err := signer.LoadSignState(path.Join(tmpConfig, "state", chainid+"_priv_validator_state.json"))
				require.NoError(t, err)
				require.Equal(t, height, ss.Height)
				require.Equal(t, int64(0), ss.Round)
				require.Equal(t, int8(0), ss.Step)
				require.Nil(t, ss.EphemeralPublic)
				require.Nil(t, ss.Signature)
				require.Nil(t, ss.SignBytes)

				ss, err = signer.LoadSignState(path.Join(tmpConfig, "state", chainid+"_share_sign_state.json"))
				require.NoError(t, err)
				require.Equal(t, height, ss.Height)
				require.Equal(t, int64(0), ss.Round)
				require.Equal(t, int8(0), ss.Step)
				require.Nil(t, ss.EphemeralPublic)
				require.Nil(t, ss.Signature)
				require.Nil(t, ss.SignBytes)
			}
		})
	}

	t.Cleanup(func() {
		os.RemoveAll(tmpHome)
	})
}
