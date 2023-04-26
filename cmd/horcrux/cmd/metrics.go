package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/armon/go-metrics"
	gmprometheus "github.com/armon/go-metrics/prometheus"
	tmlog "github.com/cometbft/cometbft/libs/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func AddPrometheusMetrics(mux *http.ServeMux) {
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "metrics")

	// Add metrics from raft's implementation of go-metrics
	cfg := gmprometheus.DefaultPrometheusOpts
	sink, err := gmprometheus.NewPrometheusSinkFrom(cfg)
	if err != nil {
		logger.Error("Could not configure Raft Metrics")
		panic(err)
	}
	_, err = metrics.NewGlobal(metrics.DefaultConfig("horcrux"), sink)
	if err != nil {
		logger.Error("Could not add Raft Metrics")
		panic(err)
	}

	mux.Handle("/metrics", promhttp.Handler())
	logger.Info("Prometheus Metrics Listening", "address", config.Config.DebugAddr, "path", "/metrics")
}

// EnableDebugAndMetrics - Initialization errors are not fatal, only logged
func EnableDebugAndMetrics(ctx context.Context) {
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "debugserver")

	// Configure Shared Debug HTTP Server for pprof and prometheus
	if len(config.Config.DebugAddr) == 0 {
		logger.Info("debug-addr not defined; debug server disabled")
		return
	}
	logger.Info("Debug Server Listening", "address", config.Config.DebugAddr)

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
		Handler:           mux,
		Addr:              config.Config.DebugAddr,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Start Debug Server.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				logger.Info("Debug Server Shutdown Complete")
				return
			}
			logger.Error(fmt.Sprintf("Debug Endpoint failed to start: %+v", err))
			panic(err)
		}
	}()

	// Shutdown Debug Server on ctx request
	go func() {
		<-ctx.Done()
		logger.Info("Gracefully Stopping Debug Server")
		if err := srv.Shutdown(context.Background()); err != nil {
			logger.Error("Error in Stopping Debug Server", err)
			logger.Info("Force Stopping Debug Server")
			if err = srv.Close(); err != nil {
				logger.Error("Error in Force Stopping Debug Server", err)
			}
		}
	}()

}
