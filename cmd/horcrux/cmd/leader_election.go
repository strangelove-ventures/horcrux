package cmd

import (
	"context"
	"fmt"
	"time"

	_ "github.com/Jille/grpc-multi-resolver" // required to register resolver
	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/client"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/strangelove-ventures/horcrux/signer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func leaderElectionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "elect [node_id]",
		Short: "Elect new raft leader",
		Long: `To choose the next eligible leader, pass no argument.
To choose a specific leader, pass that leader's ID as an argument.
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

			grpcClient := proto.NewCosignerGRPCClient(conn)
			_, err = grpcClient.TransferLeadership(
				ctx,
				&proto.CosignerGRPCTransferLeadershipRequest{LeaderID: leaderID},
			)
			if err != nil {
				return err
			}

			res, err := grpcClient.GetLeader(ctx, &proto.CosignerGRPCGetLeaderRequest{})
			if err != nil {
				return err
			}

			fmt.Printf("Leader election successful. New leader: %s\n", res.Leader)

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

			keyFile, err := config.KeyFileExistsCosignerRSA()
			if err != nil {
				return err
			}

			key, err := signer.LoadCosignerRSAKey(keyFile)
			if err != nil {
				return fmt.Errorf("error reading cosigner key (%s): %w", keyFile, err)
			}

			var p2pListen string

			for _, c := range thresholdCfg.Cosigners {
				if c.ShardID == key.ID {
					p2pListen = c.P2PAddr
				}
			}

			if p2pListen == "" {
				return fmt.Errorf("cosigner config does not exist for our shard ID %d", key.ID)
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

			grpcClient := proto.NewCosignerGRPCClient(conn)

			res, err := grpcClient.GetLeader(ctx, &proto.CosignerGRPCGetLeaderRequest{})
			if err != nil {
				return err
			}

			fmt.Printf("Current leader: %s\n", res.Leader)

			return nil
		},
	}

}
