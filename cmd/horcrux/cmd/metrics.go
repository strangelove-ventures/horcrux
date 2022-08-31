package cmd

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func StartMetrics() {
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":2112", nil); err != nil {
		fmt.Printf("Prometheus Endpoint failed to start: %s\n", err)
	}
}
