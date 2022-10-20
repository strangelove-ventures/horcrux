package client

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func SanitizeAddress(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("error parsing peer URL: %w", err)
	}

	hostname, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", fmt.Errorf("error splitting host port from parsed URL: %w", err)
	}

	if strings.Contains(hostname, ":") {
		// IPv6 Addreses need to be wrapped in brackets
		return fmt.Sprintf("[%s]:%s", hostname, port), nil
	} else {
		return fmt.Sprintf("%s:%s", hostname, port), nil
	}
}

func MultiAddress(addresses []string) (string, error) {
	grpcAddresses := make([]string, len(addresses))

	for i, addr := range addresses {
		peerAddr, err := SanitizeAddress(addr)
		if err != nil {
			return "", err
		}
		grpcAddresses[i] = peerAddr
	}

	return fmt.Sprintf("multi:///%s", strings.Join(grpcAddresses, ",")), nil
}
