package client

import (
	"fmt"
	"net/url"
	"strings"
)

type clientAdresses struct {
	id []string
}

func SanitizeAddress(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("error parsing URL: %w", err)
	}

	return u.Host, nil
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
