package cmd

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/strangelove-ventures/horcrux/signer/proto"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func init() {
	rootCmd.AddCommand(leaderElectionCmd)
}

var leaderElectionCmd = &cobra.Command{
	Use:   "elect",
	Short: "Elect new raft leader",
	Long: `To choose the next eligible leader, pass no argument.
To choose a specific leader, pass that leader's ID as an argument.
`,
	Args: cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if _, err := os.Stat(homeDir); !os.IsNotExist(err) {
			return fmt.Errorf("%s is not empty, check for existing configuration and clear path before trying again", homeDir)
		}

		if config == nil {
			return fmt.Errorf("no configuration file exists")
		}

		if config.CosignerConfig == nil {
			return fmt.Errorf("cosigner configuration is not present in config file")
		}

		if len(config.CosignerConfig.Peers) == 0 {
			return fmt.Errorf("cosigner configuration has no peers")
		}

		serviceConfig := `{"healthCheckConfig": {"serviceName": "Leader"}, "loadBalancingConfig": [ { "round_robin": {} } ]}`
		retryOpts := []grpc_retry.CallOption{
			grpc_retry.WithBackoff(grpc_retry.BackoffExponential(100 * time.Millisecond)),
			grpc_retry.WithMax(5),
		}
		grpcAddress := "multi:///"

		for _, peer := range config.CosignerConfig.Peers {
			url, err := url.Parse(peer.P2PAddr)
			if err != nil {
				grpcAddress += peer.P2PAddr
			} else {
				grpcAddress += url.Host
			}
		}
		conn, err := grpc.Dial(grpcAddress,
			grpc.WithDefaultServiceConfig(serviceConfig), grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
			grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(retryOpts...)))
		if err != nil {
			log.Fatalf("dialing failed: %v", err)
		}
		defer conn.Close()

		leaderID := ""

		if len(args) > 0 {
			leaderID = args[0]
		}

		grpcClient := proto.NewCosignerGRPCClient(conn)
		_, err = grpcClient.TransferLeadership(
			context.Background(),
			&proto.CosignerGRPCTransferLeadershipRequest{LeaderID: leaderID},
		)
		if err != nil {
			return err
		}

		return nil
	},
}
