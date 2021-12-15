package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var (
	homeDir string
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
	rootCmd.PersistentFlags().StringVar(&homeDir, "home", "", "Directory for config and data (default is $HOME/.horcrux)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	cfg := Config{}
	if homeDir != "" {
		cfgFile := path.Join(homeDir, "config.yaml")
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		handleInitError(err)
		viper.AddConfigPath(path.Join(home, ".horcrux"))
		viper.SetConfigName("config")
	}
	viper.SetEnvPrefix("horcrux")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("no config exists at default location", err)
		return
	}
	handleInitError(viper.Unmarshal(&cfg))
	bz, err := ioutil.ReadFile(viper.ConfigFileUsed())
	handleInitError(err)
	handleInitError(yaml.Unmarshal(bz, &cfg))
	config = &cfg
}

func handleInitError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
