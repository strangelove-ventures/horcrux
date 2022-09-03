package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	"gopkg.in/yaml.v2"
)

func init() {
	nodesCmd.AddCommand(addNodesCmd())
	nodesCmd.AddCommand(removeNodesCmd())
	configCmd.AddCommand(nodesCmd)

	peersCmd.AddCommand(addPeersCmd())
	peersCmd.AddCommand(removePeersCmd())
	peersCmd.AddCommand(setSharesCmd())
	configCmd.AddCommand(peersCmd)

	chainIDCmd.AddCommand(setChainIDCmd())
	configCmd.AddCommand(chainIDCmd)

	configCmd.AddCommand(initCmd())
	rootCmd.AddCommand(configCmd)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Commands to configure the horcrux signer",
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "init [chain-id] [chain-nodes]",
		Aliases: []string{"i"},
		Short:   "initialize configuration file and home directory if one doesn't already exist",
		Long: "initialize configuration file, use flags for cosigner configuration.\n\n" +
			"[chain-id] is the chain id of the chain to validate\n" +
			"[chain-nodes] is a comma separated array of chain node addresses i.e.\n" +
			"tcp://chain-node-1:1234,tcp://chain-node-2:1234",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			cid := args[0]
			var cn []ChainNode
			if len(args) == 2 {
				cn, err = chainNodesFromArg(args[1])
				if err != nil {
					return err
				}
			}

			cmdFlags := cmd.Flags()
			overwrite, _ := cmdFlags.GetBool("overwrite")

			if _, err := os.Stat(config.ConfigFile); !os.IsNotExist(err) && !overwrite {
				return fmt.Errorf("%s already exists. Provide the -o flag to overwrite the existing config",
					config.ConfigFile)
			}

			var cfg DiskConfig

			cs, _ := cmdFlags.GetBool("cosigner")
			keyFileFlag, _ := cmdFlags.GetString("keyfile")
			var keyFile *string
			if keyFileFlag != "" {
				keyFile = &keyFileFlag
			}
			if cs {
				p, _ := cmdFlags.GetString("peers")
				threshold, _ := cmdFlags.GetInt("threshold")
				timeout, _ := cmdFlags.GetString("timeout")
				peers, err := peersFromFlag(p)
				if err != nil {
					return err
				}

				listen, _ := cmdFlags.GetString("listen")
				if listen == "" {
					return errors.New("must input at least one node")
				}
				url, err := url.Parse(listen)
				if err != nil {
					return fmt.Errorf("error parsing listen address: %s, %v", listen, err)
				}
				host, _, err := net.SplitHostPort(url.Host)
				if err != nil {
					return err
				}
				if host == "0.0.0.0" {
					return errors.New("host cannot be 0.0.0.0, must be reachable from other peers")
				}

				cfg = DiskConfig{
					PrivValKeyFile: keyFile,
					ChainID:        cid,
					CosignerConfig: &CosignerConfig{
						Threshold: threshold,
						Shares:    len(peers) + 1,
						P2PListen: listen,
						Peers:     peers,
						Timeout:   timeout,
					},
					ChainNodes: cn,
				}
				if err = validateCosignerConfig(cfg); err != nil {
					return err
				}
			} else {
				if len(cn) == 0 {
					return fmt.Errorf("must input at least one node")
				}
				cfg = DiskConfig{
					PrivValKeyFile: keyFile,
					ChainID:        cid,
					ChainNodes:     cn,
				}
				if err = validateSingleSignerConfig(cfg); err != nil {
					return err
				}
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			// create all directories up to the state directory
			if err = os.MkdirAll(config.StateDir, 0755); err != nil {
				return err
			}
			// create the config file
			config.Config = cfg
			if err = config.writeConfigFile(); err != nil {
				return err
			}

			// initialize state/{chainid}_priv_validator_state.json file
			if _, err = signer.LoadOrCreateSignState(config.privValStateFile(cid)); err != nil {
				return err
			}

			// if node is a cosigner initialize state/{chainid}_priv_validator_state.json file
			if cs {
				if _, err = signer.LoadOrCreateSignState(config.shareStateFile(cid)); err != nil {
					return err
				}
			}

			fmt.Printf("Successfully initialized configuration: %s\n", config.ConfigFile)
			return nil
		},
	}
	cmd.Flags().BoolP("cosigner", "c", false, "set to initialize a cosigner node, requires --peers and --threshold")
	cmd.Flags().StringP("peers", "p", "", "cosigner peer addresses in format tcp://{addr}:{port}|{share-id} \n"+
		"(i.e. \"tcp://node-1:2222|2,tcp://node-2:2222|3\")")
	cmd.Flags().IntP("threshold", "t", 0, "indicate number of signatures required for threshold signature")
	cmd.Flags().StringP("listen", "l", "", "listen address of the signer")
	cmd.Flags().StringP("keyfile", "k", "",
		"priv val key file path (full key for single signer, or key share for cosigner)")
	cmd.Flags().String("timeout", "1500ms", "configure cosigner rpc server timeout value, \n"+
		"accepts valid duration strings for Go's time.ParseDuration() e.g. 1s, 1000ms, 1.5m")
	cmd.Flags().BoolP("overwrite", "o", false, "set to overwrite an existing config.yaml")
	return cmd
}

func validateSingleSignerConfig(cfg DiskConfig) error {
	if cfg.ChainID == "" {
		return fmt.Errorf("chain-id cannot be empty")
	}
	if len(cfg.ChainNodes) == 0 {
		return fmt.Errorf("need to have a node configured to sign for")
	}
	if err := validateChainNodes(cfg.ChainNodes); err != nil {
		return err
	}
	return nil
}

func validateCosignerConfig(cfg DiskConfig) error {
	if cfg.ChainID == "" {
		return fmt.Errorf("chain-id cannot be empty")
	}
	if cfg.CosignerConfig == nil {
		return fmt.Errorf("cosigner config can't be empty")
	}
	if float32(len(cfg.CosignerConfig.Peers))/float32(2) >= float32(cfg.CosignerConfig.Threshold) {
		return fmt.Errorf("the threshold, t = (%d) must be greater than, 'peers/2' = (%.1f)",
			cfg.CosignerConfig.Threshold, float32(len(cfg.CosignerConfig.Peers))/2)
	}

	_, err := time.ParseDuration(cfg.CosignerConfig.Timeout)
	if err != nil {
		return fmt.Errorf("%s is not a valid duration string for --timeout ", cfg.CosignerConfig.Timeout)
	}
	if _, err := url.Parse(cfg.CosignerConfig.P2PListen); err != nil {
		return fmt.Errorf("failed to parse p2p listen address")
	}
	if err := validateCosignerPeers(cfg.CosignerConfig.Peers, cfg.CosignerConfig.Shares); err != nil {
		return err
	}
	if err := validateChainNodes(cfg.ChainNodes); err != nil {
		return err
	}
	return nil
}

var nodesCmd = &cobra.Command{
	Use:   "nodes",
	Short: "Commands to configure the chain nodes",
}

func addNodesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "add [chain-nodes]",
		Aliases: []string{"a"},
		Short:   "add chain node(s) to the cosigner's configuration",
		Long: "add chain node(s) to the cosigner's configuration.\n\n" +
			"[chain-nodes] is a comma separated array of chain node addresses i.e.\n" +
			"tcp://chain-node-1:1234,tcp://chain-node-2:1234",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argNodes, err := chainNodesFromArg(args[0])
			if err != nil {
				return err
			}
			diff := diffSetChainNode(argNodes, config.Config.ChainNodes)
			if len(diff) == 0 {
				return errors.New("no new chain nodes in args")
			}
			diff = append(config.Config.ChainNodes, diff...)
			if err := validateChainNodes(diff); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			config.Config.ChainNodes = diff
			if err := config.writeConfigFile(); err != nil {
				return err
			}
			return nil
		},
	}
}

func removeNodesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove [chain-nodes]",
		Aliases: []string{"r"},
		Short:   "remove chain node(s) from the cosigner's configuration",
		Long: "remove chain node(s) from the cosigner's configuration.\n\n" +
			"[chain-nodes] is a comma separated array of chain node addresses i.e.\n" +
			"tcp://chain-node-1:1234,tcp://chain-node-2:1234",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argNodes, err := chainNodesFromArg(args[0])
			if err != nil {
				return err
			}
			diff := diffSetChainNode(config.Config.ChainNodes, argNodes)
			if len(diff) == 0 {
				return errors.New("cannot remove all chain nodes from config, please leave at least one")
			}
			// If none of the chain nodes in the args are listed in the config, just continue
			// without throwing an error, as the chain nodes in the config remain untouched.
			if err := validateChainNodes(diff); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			config.Config.ChainNodes = diff
			if err := config.writeConfigFile(); err != nil {
				return err
			}
			return nil
		},
	}
}

// diffSetCosignerPeer returns the difference set for ChainNodes of setA-setB.
// Example: [1,2,3] & [2,3,4] => [1]
func diffSetChainNode(setA, setB []ChainNode) (diff []ChainNode) {
	for _, a := range setA {
		found := false
		for _, b := range setB {
			if a == b {
				found = true
			}
		}
		if !found {
			diff = append(diff, a)
		}
	}
	return
}

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "Commands to configure the peer nodes",
}

func addPeersCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "add [peer-nodes]",
		Aliases: []string{"a"},
		Short:   "add peer node(s) to the cosigner's configuration",
		Long: "add peer node(s) to the cosigner's configuration.\n\n" +
			"[peer-nodes] is a comma separated array of peer node addresses i.e.\n" +
			"tcp://peer-node-1:1234,tcp://peer-node-2:1234",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argPeers, err := peersFromFlag(args[0])
			if err != nil {
				return err
			}
			diff := diffSetCosignerPeer(argPeers, config.Config.CosignerConfig.Peers)
			if len(diff) == 0 {
				return errors.New("no new peer nodes in args")
			}
			diff = append(config.Config.CosignerConfig.Peers, diff...)
			if err := validateCosignerPeers(diff, config.Config.CosignerConfig.Shares); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			config.Config.CosignerConfig.Peers = diff
			if err := config.writeConfigFile(); err != nil {
				return err
			}
			return nil
		},
	}
}

func removePeersCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove [peer-node-ids]",
		Aliases: []string{"r"},
		Short:   "remove peer node(s) from the cosigner's configuration",
		Long: "remove peer node(s) from the cosigner's configuration.\n\n" +
			"[peer-node-ids] is a comma separated array of peer node IDs i.e.\n" +
			"1,2",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			var argPeers []CosignerPeer
			for _, peer := range config.Config.CosignerConfig.Peers {
				for _, id := range strings.Split(args[0], ",") {
					id, err := strconv.Atoi(id)
					if err != nil {
						return err
					}
					if peer.ShareID == id {
						argPeers = append(argPeers, peer)
					}
				}
			}

			diff := diffSetCosignerPeer(config.Config.CosignerConfig.Peers, argPeers)
			if len(diff) == 0 {
				return errors.New("cannot remove all peer nodes from config, please leave at least one")
			}
			// If none of the peer nodes in the args are listed in the config, just continue
			// without throwing an error, as the peer nodes in the config remain untouched.
			if err := validateCosignerPeers(diff, config.Config.CosignerConfig.Shares); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			config.Config.CosignerConfig.Peers = diff
			if err := config.writeConfigFile(); err != nil {
				return err
			}
			return nil
		},
	}
}

func setSharesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "set-shares [num-shares]",
		Aliases: []string{"shares"},
		Short:   "set the number of key shares",
		Long: "set the number of key shares.\n\n" +
			"[num-shares] is the number of generated key shares, used to limit the number of peers i.e." +
			"3",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			numShares, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			if err := validateCosignerPeers(config.Config.CosignerConfig.Peers, numShares); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			config.Config.CosignerConfig.Shares = numShares
			if err := config.writeConfigFile(); err != nil {
				return err
			}
			return nil
		},
	}
}

// diffSetCosignerPeer returns the difference set for CosignerPeers of setA-setB.
// Example: [1,2,3] & [2,3,4] => [1]
func diffSetCosignerPeer(setA, setB []CosignerPeer) (diff []CosignerPeer) {
	for _, a := range setA {
		found := false
		for _, b := range setB {
			if a == b {
				found = true
			}
		}
		if !found {
			diff = append(diff, a)
		}
	}
	return
}

var chainIDCmd = &cobra.Command{
	Use:   "chain-id",
	Short: "Commands to configure the chain ID",
}

func setChainIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "set [chain-ID]",
		Aliases: []string{"s"},
		Short:   "set the chain ID",
		Long: "set the chain ID.\n\n" +
			"[chain-id] is a string i.e.\n" +
			"cosmoshub-4",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			oldChainID := config.Config.ChainID
			newChainID := args[0]
			pvOldPath := config.privValStateFile(oldChainID)
			pvNewPath := config.privValStateFile(newChainID)
			shareOldPath := config.shareStateFile(oldChainID)
			shareNewPath := config.shareStateFile(newChainID)

			if _, err := os.Stat(pvOldPath); err == nil {
				if err = os.Rename(pvOldPath, pvNewPath); err != nil {
					return err
				}
			}
			if _, err := os.Stat(shareOldPath); err == nil {
				if err = os.Rename(shareOldPath, shareNewPath); err != nil {
					return err
				}
			}

			config.Config.ChainID = args[0]
			if err = config.writeConfigFile(); err != nil {
				return err
			}
			return nil
		},
	}
}

// Config maps to the on-disk JSON format
type DiskConfig struct {
	PrivValKeyFile *string         `json:"key-file,omitempty" yaml:"key-file,omitempty"`
	ChainID        string          `json:"chain-id" yaml:"chain-id"`
	CosignerConfig *CosignerConfig `json:"cosigner,omitempty" yaml:"cosigner,omitempty"`
	ChainNodes     []ChainNode     `json:"chain-nodes,omitempty" yaml:"chain-nodes,omitempty"`
}

func (c *DiskConfig) Nodes() []signer.NodeConfig {
	out := make([]signer.NodeConfig, len(c.ChainNodes))
	for i, n := range c.ChainNodes {
		out[i] = signer.NodeConfig{Address: n.PrivValAddr}
	}
	return out
}

func (c *DiskConfig) MustMarshalYaml() []byte {
	out, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	return out
}

type RuntimeConfig struct {
	HomeDir    string
	ConfigFile string
	StateDir   string
	PidFile    string
	Config     DiskConfig
}

func (c *RuntimeConfig) keyFilePath(cosigner bool) string {
	if c.Config.PrivValKeyFile != nil && *c.Config.PrivValKeyFile != "" {
		return *c.Config.PrivValKeyFile
	}
	if cosigner {
		return filepath.Join(c.HomeDir, "share.json")
	}
	return filepath.Join(c.HomeDir, "priv_validator_key.json")
}

func (c RuntimeConfig) privValStateFile(chainID string) string {
	return filepath.Join(c.StateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))
}

func (c RuntimeConfig) shareStateFile(chainID string) string {
	return filepath.Join(c.StateDir, fmt.Sprintf("%s_share_sign_state.json", chainID))
}

func (c RuntimeConfig) writeConfigFile() error {
	return os.WriteFile(c.ConfigFile, c.Config.MustMarshalYaml(), 0644) //nolint
}

type CosignerConfig struct {
	Threshold int            `json:"threshold"   yaml:"threshold"`
	Shares    int            `json:"shares" yaml:"shares"`
	P2PListen string         `json:"p2p-listen"  yaml:"p2p-listen"`
	Peers     []CosignerPeer `json:"peers"       yaml:"peers"`
	Timeout   string         `json:"rpc-timeout" yaml:"rpc-timeout"`
}

func (c *DiskConfig) CosignerPeers() (out []signer.CosignerConfig) {
	for _, p := range c.CosignerConfig.Peers {
		out = append(out, signer.CosignerConfig{ID: p.ShareID, Address: p.P2PAddr})
	}
	return
}

type CosignerPeer struct {
	ShareID int    `json:"share-id" yaml:"share-id"`
	P2PAddr string `json:"p2p-addr" yaml:"p2p-addr"`
}

func validateCosignerPeers(peers []CosignerPeer, shares int) error {
	// Check IDs to make sure none are duplicated
	if dupl := duplicatePeers(peers); len(dupl) != 0 {
		return fmt.Errorf("found duplicate share IDs in args: %v", dupl)
	}

	// Make sure that the peers' IDs match the number of shares.
	for _, peer := range peers {
		if peer.ShareID < 1 || peer.ShareID > shares {
			return fmt.Errorf("peer ID %v in args is out of range, must be between 1 and %v",
				peer.ShareID, shares)
		}
	}

	// Check that no more than {num-shares}-1 peers are in the peer list, assuming
	// the remaining peer ID is the ID the local node is configured with.
	if len(peers) == shares {
		return fmt.Errorf("too many peers (%v+local node = %v) for the specified number of key shares (%v)",
			len(peers), len(peers)+1, shares)
	}
	return nil
}

func duplicatePeers(peers []CosignerPeer) (duplicates []CosignerPeer) {
	encountered := make(map[int]string)
	for _, peer := range peers {
		if _, found := encountered[peer.ShareID]; !found {
			encountered[peer.ShareID] = peer.P2PAddr
		} else {
			duplicates = append(duplicates, CosignerPeer{peer.ShareID, peer.P2PAddr})
		}
	}
	return
}

func peersFromFlag(peers string) (out []CosignerPeer, err error) {
	for _, p := range strings.Split(peers, ",") {
		ps := strings.Split(p, "|")
		if len(ps) != 2 {
			return nil, fmt.Errorf("invalid peer string %s", p)
		}
		shareid, err := strconv.ParseInt(ps[1], 10, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, CosignerPeer{ShareID: int(shareid), P2PAddr: ps[0]})
	}
	return
}

type ChainNode struct {
	PrivValAddr string `json:"priv-val-addr" yaml:"priv-val-addr"`
}

func chainNodesFromArg(arg string) ([]ChainNode, error) {
	cn := parseChainNodes(arg)
	return cn, validateChainNodes(cn)
}

func parseChainNodes(nodes string) (out []ChainNode) {
	for _, n := range strings.Split(nodes, ",") {
		out = append(out, ChainNode{PrivValAddr: n})
	}
	return
}

func validateChainNodes(nodes []ChainNode) (err error) {
	for _, n := range nodes {
		_, err = url.Parse(n.PrivValAddr)
	}
	return
}
