package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/armon/go-metrics"
	gmprometheus "github.com/armon/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	tmlog "github.com/tendermint/tendermint/libs/log"
)

func StartMetrics() {
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "metrics")

	// Add raft metrics to prometheus
	enableRaftMetrics := true
	if enableRaftMetrics {
		// PrometheusSink config w/ definitions for each metric type
		cfg := gmprometheus.DefaultPrometheusOpts
		sink, err := gmprometheus.NewPrometheusSinkFrom(cfg)
		if err != nil {
			logger.Error("Could not configure Raft Metrics")
		}
		defer prometheus.Unregister(sink)
		_, err = metrics.NewGlobal(metrics.DefaultConfig("horcrux"), sink)
		if err != nil {
			logger.Error("Could not add Raft Metrics")
		}
	}

	// Configure Prometheus HTTP Server and Handler

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
