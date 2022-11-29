package client_test

import (
	"testing"

	"github.com/strangelove-ventures/horcrux/client"
	"github.com/stretchr/testify/require"
)

func TestLeaderElectionMultiAddressDomain(t *testing.T) {
	addresses := []string{
		"tcp://signer-1:2222",
		"tcp://signer-2:2222",
		"tcp://signer-3:2222",
	}

	multiAddress, err := client.MultiAddress(addresses)
	require.NoError(t, err, "failed to assemble fqdn multi address")

	require.Equal(t, "multi:///signer-1:2222,signer-2:2222,signer-3:2222", multiAddress)
}

func TestLeaderElectionMultiAddressIPv4(t *testing.T) {
	addresses := []string{
		"tcp://10.0.0.1:2222",
		"tcp://10.0.0.2:2222",
		"tcp://10.0.0.3:2222",
	}

	multiAddress, err := client.MultiAddress(addresses)
	require.NoError(t, err, "failed to assemble ipv4 multi address")

	require.Equal(t, "multi:///10.0.0.1:2222,10.0.0.2:2222,10.0.0.3:2222", multiAddress)
}

func TestLeaderElectionMultiAddressIPv6(t *testing.T) {
	addresses := []string{
		"tcp://[2001:db8:3333:4444:5555:6666:7777:8888]:2222",
		"tcp://[::]:2222",
		"tcp://[::1234:5678]:2222",
		"tcp://[2001:db8::]:2222",
		"tcp://[2001:db8::1234:5678]:2222",
	}

	multiAddress, err := client.MultiAddress(addresses)
	require.NoError(t, err, "failed to assemble ipv6 multi address")

	const expected = "multi:///" +
		"[2001:db8:3333:4444:5555:6666:7777:8888]:2222" +
		",[::]:2222,[::1234:5678]:2222" +
		",[2001:db8::]:2222" +
		",[2001:db8::1234:5678]:2222"

	require.Equal(t, expected, multiAddress)
}
