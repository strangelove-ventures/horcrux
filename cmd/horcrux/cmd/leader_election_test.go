package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLeaderElectionMultiAddressDomain(t *testing.T) {
	cfg := &CosignerConfig{
		P2PListen: "tcp://signer-1:2222",
		Peers: []CosignerPeer{
			{
				P2PAddr: "tcp://signer-2:2222",
			},
			{
				P2PAddr: "tcp://signer-3:2222",
			},
		},
	}

	multiAddress := leaderElectMultiAddress(cfg)

	require.Equal(t, "multi:///signer-1:2222,signer-2:2222,signer-3:2222", multiAddress)
}

func TestLeaderElectionMultiAddressIPv4(t *testing.T) {
	cfg := &CosignerConfig{
		P2PListen: "tcp://10.0.0.1:2222",
		Peers: []CosignerPeer{
			{
				P2PAddr: "tcp://10.0.0.2:2222",
			},
			{
				P2PAddr: "tcp://10.0.0.3:2222",
			},
		},
	}

	multiAddress := leaderElectMultiAddress(cfg)

	require.Equal(t, "multi:///10.0.0.1:2222,10.0.0.2:2222,10.0.0.3:2222", multiAddress)
}

func TestLeaderElectionMultiAddressIPv6(t *testing.T) {
	cfg := &CosignerConfig{
		P2PListen: "tcp://[2001:db8:3333:4444:5555:6666:7777:8888]:2222",
		Peers: []CosignerPeer{
			{
				P2PAddr: "tcp://[::]:2222",
			},
			{
				P2PAddr: "tcp://[::1234:5678]:2222",
			},
			{
				P2PAddr: "tcp://[2001:db8::]:2222",
			},
			{
				P2PAddr: "tcp://[2001:db8::1234:5678]:2222",
			},
		},
	}

	multiAddress := leaderElectMultiAddress(cfg)

	const expected = "multi:///" +
		"[2001:db8:3333:4444:5555:6666:7777:8888]:2222" +
		",[::]:2222,[::1234:5678]:2222" +
		",[2001:db8::]:2222" +
		",[2001:db8::1234:5678]:2222"

	require.Equal(t, expected, multiAddress)
}
