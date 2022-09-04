package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"

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

	srv := &http.Server{
		Addr:              config.Config.PrometheusListenAddress,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		logger.Error(fmt.Sprintf("Prometheus Endpoint failed to start: %s", err))
	}
}
