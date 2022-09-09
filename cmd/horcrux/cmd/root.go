package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var (
	homeDir string
	config  RuntimeConfig
)

var rootCmd = &cobra.Command{
	Use:   "horcrux",
	Short: "A tendermint remote signer with both single signer and threshold signer modes",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Cobra will print the error
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&homeDir, "home", "", "Directory for config and data (default is $HOME/.horcrux)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	var home string
	if homeDir == "" {
		userHome, err := homedir.Dir()
		handleInitError(err)
		home = filepath.Join(userHome, ".horcrux")
	} else {
		home = homeDir
	}
	config = RuntimeConfig{
		HomeDir:    home,
		ConfigFile: filepath.Join(home, "config.yaml"),
		StateDir:   filepath.Join(home, "state"),
		PidFile:    filepath.Join(home, "horcrux.pid"),
	}
	viper.SetConfigFile(config.ConfigFile)
	viper.SetEnvPrefix("horcrux")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("no config exists at default location", err)
		return
	}
	handleInitError(viper.Unmarshal(&config.Config))
	bz, err := os.ReadFile(viper.ConfigFileUsed())
	handleInitError(err)
	handleInitError(yaml.Unmarshal(bz, &config.Config))
}

func handleInitError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
