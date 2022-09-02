package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	tmlog "github.com/tendermint/tendermint/libs/log"
)

func StartMetrics() {
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "metrics")

	if len(config.Config.PrometheusListenAddress) == 0 {
		logger.Error("prometheus-listen-address not defined")
		return
	}
	logger.Info("Prometheus Metrics Listening", "address", config.Config.PrometheusListenAddress)
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(config.Config.PrometheusListenAddress, nil); err != nil {
		logger.Error(fmt.Sprintf("Prometheus Endpoint failed to start: %s", err))
	}
}
