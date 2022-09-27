package cmd

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/armon/go-metrics"
	gmprometheus "github.com/armon/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	tmlog "github.com/tendermint/tendermint/libs/log"
)

func AddPrometheusMetrics(mux *http.ServeMux) {
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

	mux.Handle("/metrics", promhttp.Handler())
	logger.Info("Prometheus Metrics Listening", "address", config.Config.DebugListenAddress, "path", "/metrics")
}

// EnableDebugAndMetrics - Initialization errors are not fatal, only logged
func EnableDebugAndMetrics() {
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "debugserver")

	// Configure Shared Debug HTTP Server for pprof and prometheus
	if len(config.Config.DebugListenAddress) == 0 {
		logger.Error("debug-listen-address not defined")
		return
	}
	logger.Info("Debug Server Listening", "address", config.Config.DebugListenAddress)

	// Set up new mux identical to the default mux configuration in net/http/pprof.
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// And redirect the browser to the /debug/pprof root,
	// so operators don't see a mysterious 404 page.
	mux.Handle("/", http.RedirectHandler("/debug/pprof", http.StatusSeeOther))

	// Add prometheus metrics
	AddPrometheusMetrics(mux)

	// Configure Debug Server Network Parameters
	srv := &http.Server{
		Handler: mux,
		//ErrorLog: &logger,

		Addr:              config.Config.DebugListenAddress,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Start Debug Server.
	if err := srv.ListenAndServe(); err != nil {
		logger.Error(fmt.Sprintf("Debug Endpoint failed to start: %s", err))
		return
	}
}
