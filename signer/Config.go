package signer

import (
	"os"

	"github.com/BurntSushi/toml"
)

type NodeConfig struct {
	Address string `toml:"address"`
}

type CosignerConfig struct {
	ID      int    `toml:"id"`
	Address string `toml:"remote_address"`
}

type Config struct {
	Mode              string           `toml:"mode"`
	PrivValKeyFile    string           `toml:"key_file"`
	PrivValStateDir   string           `toml:"state_dir"`
	ChainID           string           `toml:"chain_id"`
	CosignerThreshold int              `toml:"cosigner_threshold"`
	ListenAddress     string           `toml:"cosigner_listen_address"`
	Nodes             []NodeConfig     `toml:"node"`
	Cosigners         []CosignerConfig `toml:"cosigner"`
}

func LoadConfigFromFile(file string) (Config, error) {
	var config Config

	// default mode is mpc
	config.Mode = "mpc"

	reader, err := os.Open(file)
	if err != nil {
		return config, err
	}
	_, err = toml.DecodeReader(reader, &config)
	return config, err
}
