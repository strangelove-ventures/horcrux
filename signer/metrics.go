package signer

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Variables to calculate Prometheus Metrics
	previousPrecommitHeight = int64(0)
	previousPrevoteHeight   = int64(0)
	previousPrecommitTime   = time.Now()
	previousPrevoteTime     = time.Now()

	// Prometheus Metrics
	lastPrecommitHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_precommit_height",
		Help: "Last Height Precommit Signed",
	})
	lastPrevoteHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_prevote_height",
		Help: "Last Height Prevote Signed",
	})
	lastProposalHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_proposal_height",
		Help: "Last Height Proposal Signed",
	})
	lastPrecommitRound = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_precommit_round",
		Help: "Last Round Precommit Signed",
	})
	lastPrevoteRound = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_prevote_round",
		Help: "Last Round Prevote Signed",
	})
	lastProposalRound = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_proposal_round",
		Help: "Last Round Proposal Signed",
	})

	totalPrecommitsSigned = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_total_precommits_signed",
		Help: "Total Precommit Signed",
	})
	totalPrevotesSigned = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_total_prevotes_signed",
		Help: "Total Prevote Signed",
	})
	totalProposalsSigned = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_total_proposals_signed",
		Help: "Total Proposal Signed",
	})

	secondsSinceLastPrecommit = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_precommit",
		Help: "Seconds Since Last Precommit",
	})
	secondsSinceLastPrevote = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_prevote",
		Help: "Seconds Since Last Prevote",
	})

	missedPrecommits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_missed_precommits",
		Help: "Consecutive Precommit Missed",
	})
	missedPrevotes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_missed_prevotes",
		Help: "Consecutive Prevote Missed",
	})
	totalMissedPrecommits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_total_missed_precommits",
		Help: "Total Precommit Missed",
	})
	totalMissedPrevotes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_total_missed_prevotes",
		Help: "Total Prevote Missed",
	})

	totalSentryConnectTries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_sentry_connect_tries",
		Help: "Total Number of times sentry TCP connect has been tried",
	})
)

func StartMetrics() {
	for {
		secondsSinceLastPrecommit.Set(time.Since(previousPrecommitTime).Seconds())
		secondsSinceLastPrevote.Set(time.Since(previousPrevoteTime).Seconds())
		<-time.After(250 * time.Millisecond)
	}
}
