package signer

import (
	"fmt"
	"os"
)

type NodeConfig struct {
	Address string
}

type CosignerConfig struct {
	ID          int
	Address     string
	RaftAddress string
}

type Config struct {
	Mode              string
	PrivValKeyFile    string
	PrivValStateDir   string
	ChainID           string
	CosignerThreshold int
	ListenAddress     string
	RaftListenAddress string
	Nodes             []NodeConfig
	Cosigners         []CosignerConfig
}

func (cfg *Config) KeyFileExists() error {
	if _, err := os.Stat(cfg.PrivValKeyFile); os.IsNotExist(err) {
		return fmt.Errorf("private key share doesn't exist at path(%s)", cfg.PrivValKeyFile)
	}
	return nil
}
