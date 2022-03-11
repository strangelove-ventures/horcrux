package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	_ "github.com/Jille/grpc-multi-resolver"
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

		var grpcAddresses []string
		url, err := url.Parse(config.CosignerConfig.P2PListen)
		if err != nil {
			fmt.Printf("Error parsing peer URL: %v", err)
		} else {
			host, port, err := net.SplitHostPort(url.Host)
			if err == nil {
				grpcAddresses = append(grpcAddresses, fmt.Sprintf("%s:%s", host, port))
			}
		}

		for _, peer := range config.CosignerConfig.Peers {
			url, err := url.Parse(peer.P2PAddr)
			if err != nil {
				fmt.Printf("Error parsing peer URL: %v", err)
			} else {
				host, port, err := net.SplitHostPort(url.Host)
				if err == nil {
					grpcAddresses = append(grpcAddresses, fmt.Sprintf("%s:%s", host, port))
				}
			}
		}

		grpcAddress := fmt.Sprintf("multi:///%s", strings.Join(grpcAddresses, ","))

		fmt.Println(grpcAddress)
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

		context, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelFunc()

		grpcClient := proto.NewCosignerGRPCClient(conn)
		_, err = grpcClient.TransferLeadership(
			context,
			&proto.CosignerGRPCTransferLeadershipRequest{LeaderID: leaderID},
		)
		if err != nil {
			return err
		}

		return nil
	},
}
