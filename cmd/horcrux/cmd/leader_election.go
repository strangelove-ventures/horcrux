package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"

	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/client"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	"github.com/strangelove-ventures/horcrux/src/multiresolver"

	// "github.com/strangelove-ventures/horcrux/src/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func init() {
	multiresolver.Register()
}

func leaderElectionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "elect [node_id]",
		Short: "Elect new raft leader",
		Long: `To choose the next eligible leader, pass no argument.
To choose a specific leader, pass that leader's Index as an argument.
`,
		Args: cobra.RangeArgs(0, 1),
		Example: `horcrux elect # elect next eligible leader
horcrux elect 2 # elect specific leader`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if config.Config.ThresholdModeConfig == nil {
				return fmt.Errorf("threshold mode configuration is not present in config file")
			}

			if len(config.Config.ThresholdModeConfig.Cosigners) == 0 {
				return fmt.Errorf("threshold mode configuration has no cosigners")
			}

			serviceConfig := `{"healthCheckConfig": {"serviceName": "Leader"}, "loadBalancingConfig": [ { "round_robin": {} } ]}`
			retryOpts := []grpcretry.CallOption{
				grpcretry.WithBackoff(grpcretry.BackoffExponential(100 * time.Millisecond)),
				grpcretry.WithMax(5),
			}

			grpcAddress, err := config.Config.ThresholdModeConfig.LeaderElectMultiAddress()
			if err != nil {
				return err
			}

			fmt.Printf("Broadcasting to address: %s\n", grpcAddress)
			conn, err := grpc.Dial(grpcAddress,
				grpc.WithDefaultServiceConfig(serviceConfig), grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
				grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)))
			if err != nil {
				return fmt.Errorf("dialing failed: %v", err)
			}
			defer conn.Close()

			leaderID := ""

			if len(args) > 0 {
				leaderID = args[0]
			}

			ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelFunc()

			grpcClient := proto.NewNodeServiceClient(conn)
			_, err = grpcClient.TransferLeadership(
				ctx,
				&proto.TransferLeadershipRequest{LeaderID: leaderID},
			)
			if err != nil {
				return err
			}

			res, err := grpcClient.GetLeader(ctx, &proto.GetLeaderRequest{})
			if err != nil {
				return err
			}

			fmt.Printf("Leader election successful. New leader: %d\n", res.Leader)

			return nil
		},
	}
}

func getLeaderCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "leader",
		Short:        "Get current raft leader",
		Args:         cobra.NoArgs,
		Example:      `horcrux leader`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			thresholdCfg := config.Config.ThresholdModeConfig
			if thresholdCfg == nil {
				return fmt.Errorf("threshold mode configuration is not present in config file")
			}

			if len(thresholdCfg.Cosigners) == 0 {
				return fmt.Errorf("threshold mode configuration has no cosigners")
			}

			var id int

			keyFileECIES, err := config.KeyFileExistsCosignerECIES()
			if err != nil {
				keyFileRSA, err := config.KeyFileExistsCosignerRSA()
				if err != nil {
					return fmt.Errorf("cosigner encryption keys not found (%s) - (%s): %w", keyFileECIES, keyFileRSA, err)
				}

				key, err := nodesecurity.LoadCosignerRSAKey(keyFileRSA)
				if err != nil {
					return fmt.Errorf("error reading cosigner key (%s): %w", keyFileRSA, err)
				}

				id = key.ID
			} else {
				key, err := nodesecurity.LoadCosignerECIESKey(keyFileECIES)
				if err != nil {
					return fmt.Errorf("error reading cosigner key (%s): %w", keyFileECIES, err)
				}

				id = key.ID
			}

			var p2pListen string

			for _, c := range thresholdCfg.Cosigners {
				if c.ShardID == id {
					p2pListen = c.P2PAddr
				}
			}

			if p2pListen == "" {
				return fmt.Errorf("cosigner config does not exist for our shard Index %d", id)
			}

			retryOpts := []grpcretry.CallOption{
				grpcretry.WithBackoff(grpcretry.BackoffExponential(100 * time.Millisecond)),
				grpcretry.WithMax(5),
			}

			grpcAddress, err := client.SanitizeAddress(p2pListen)
			if err != nil {
				return err
			}

			fmt.Printf("Request address: %s\n", grpcAddress)
			conn, err := grpc.Dial(grpcAddress,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
				grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)))
			if err != nil {
				return fmt.Errorf("dialing failed: %v", err)
			}
			defer conn.Close()

			ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelFunc()

			grpcClient := proto.NewNodeServiceClient(conn)

			res, err := grpcClient.GetLeader(ctx, &proto.GetLeaderRequest{})
			if err != nil {
				return err
			}

			fmt.Printf("Current leader: %d\n", res.Leader)

			return nil
		},
	}

}
