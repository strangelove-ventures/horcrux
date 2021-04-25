package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	config  *Config
)

var rootCmd = &cobra.Command{
	Use:   "horcrux",
	Short: "A tendermint remote signer with both single signer and threshold signer modes",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	handleInitError(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.horcrux/config.yaml)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		handleInitError(err)
		viper.AddConfigPath(path.Join(home, ".horcrux"))
		viper.SetConfigName("config")
	}
	viper.AutomaticEnv()
	handleInitError(viper.ReadInConfig())
	handleInitError(viper.Unmarshal(config))
}

func handleInitError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
