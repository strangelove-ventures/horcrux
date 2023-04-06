package cmd

import (
	"context"
	"fmt"
	"log"
	"time"

	_ "github.com/Jille/grpc-multi-resolver"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/client"
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
			if config.Config.CosignerConfig == nil {
				return fmt.Errorf("cosigner configuration is not present in config file")
			}

			if len(config.Config.CosignerConfig.Peers) == 0 {
				return fmt.Errorf("cosigner configuration has no peers")
			}

			serviceConfig := `{"healthCheckConfig": {"serviceName": "Leader"}, "loadBalancingConfig": [ { "round_robin": {} } ]}`
			retryOpts := []grpc_retry.CallOption{
				grpc_retry.WithBackoff(grpc_retry.BackoffExponential(100 * time.Millisecond)),
				grpc_retry.WithMax(5),
			}

			grpcAddress, err := config.Config.CosignerConfig.LeaderElectMultiAddress()
			if err != nil {
				return err
			}

			fmt.Printf("Broadcasting to address: %s\n", grpcAddress)
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
			if config.Config.CosignerConfig == nil {
				return fmt.Errorf("cosigner configuration is not present in config file")
			}

			if len(config.Config.CosignerConfig.Peers) == 0 {
				return fmt.Errorf("cosigner configuration has no peers")
			}

			retryOpts := []grpc_retry.CallOption{
				grpc_retry.WithBackoff(grpc_retry.BackoffExponential(100 * time.Millisecond)),
				grpc_retry.WithMax(5),
			}

			grpcAddress, err := client.SanitizeAddress(config.Config.CosignerConfig.P2PListen)
			if err != nil {
				return err
			}

			fmt.Printf("Request address: %s\n", grpcAddress)
			conn, err := grpc.Dial(grpcAddress,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
				grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(retryOpts...)))
			if err != nil {
				log.Fatalf("dialing failed: %v", err)
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
