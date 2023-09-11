package signer

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metricsTimer struct {
	mu                                              sync.Mutex
	previousPrecommit, previousPrevote              time.Time
	previousLocalSignStart, previousLocalSignFinish time.Time
	previousLocalNonce                              time.Time
}

func newMetricsTimer() *metricsTimer {
	now := time.Now()
	return &metricsTimer{
		mu:                sync.Mutex{},
		previousPrecommit: now, previousPrevote: now,
		previousLocalSignStart: now, previousLocalSignFinish: now,
		previousLocalNonce: now,
	}
}

func (mt *metricsTimer) SetPreviousPrecommit(t time.Time) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.previousPrecommit = t
}

func (mt *metricsTimer) SetPreviousPrevote(t time.Time) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.previousPrevote = t
}

func (mt *metricsTimer) SetPreviousLocalSignStart(t time.Time) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.previousLocalSignStart = t
}

func (mt *metricsTimer) SetPreviousLocalSignFinish(t time.Time) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.previousLocalSignFinish = t
}

func (mt *metricsTimer) SetPreviousLocalNonce(t time.Time) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.previousLocalNonce = t
}

func (mt *metricsTimer) UpdatePrometheusMetrics() {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Update Prometheus Gauges
	secondsSinceLastPrecommit.Set(time.Since(mt.previousPrecommit).Seconds())
	secondsSinceLastPrevote.Set(time.Since(mt.previousPrevote).Seconds())
	secondsSinceLastLocalSignStart.Set(time.Since(mt.previousLocalSignStart).Seconds())
	secondsSinceLastLocalSignFinish.Set(time.Since(mt.previousLocalSignFinish).Seconds())
	secondsSinceLastLocalNonceTime.Set(time.Since(mt.previousLocalNonce).Seconds())
}

var (
	// Variables to calculate Prometheus Metrics
	previousPrecommitHeight = int64(0)
	previousPrevoteHeight   = int64(0)
	metricsTimeKeeper       = newMetricsTimer()

	// Prometheus Metrics
	totalPubKeyRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_pubkey_requests",
			Help: "Total times public key requested (High count may indicate validator restarts)",
		},
		[]string{"chain_id", "node"},
	)
	lastPrecommitHeight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_last_precommit_height",
			Help: "Last Height Precommit Signed",
		},
		[]string{"chain_id", "node"},
	)

	lastPrevoteHeight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_last_prevote_height",
			Help: "Last Height Prevote Signed",
		},
		[]string{"chain_id", "node"},
	)

	lastProposalHeight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_last_proposal_height",
			Help: "Last Height Proposal Signed",
		},
		[]string{"chain_id", "node"},
	)
	lastPrecommitRound = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_last_precommit_round",
			Help: "Last Round Precommit Signed",
		},
		[]string{"chain_id", "node"},
	)
	lastPrevoteRound = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_last_prevote_round",
			Help: "Last Round Prevote Signed",
		},
		[]string{"chain_id", "node"},
	)
	lastProposalRound = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_last_proposal_round",
			Help: "Last Round Proposal Signed",
		},
		[]string{"chain_id", "node"},
	)

	totalPrecommitsSigned = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_precommits_signed",
			Help: "Total Precommit Signed",
		},
		[]string{"chain_id", "node"},
	)
	totalPrevotesSigned = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_prevotes_signed",
			Help: "Total Prevote Signed",
		},
		[]string{"chain_id", "node"},
	)
	totalProposalsSigned = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_proposals_signed",
			Help: "Total Proposal Signed",
		},
		[]string{"chain_id", "node"},
	)

	secondsSinceLastPrecommit = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_precommit",
		Help: "Seconds Since Last Precommit (Useful for Signing Co-Signer Node, Single Signer)",
	})
	secondsSinceLastPrevote = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_prevote",
		Help: "Seconds Since Last Prevote (Useful for Signing Co-Signer Node, Single Signer)",
	})
	secondsSinceLastLocalSignStart = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_local_sign_start_time",
		Help: "Seconds Since Last Local Start Sign (May increase beyond block time, Rarely important) ",
	})
	secondsSinceLastLocalSignFinish = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_local_sign_finish_time",
		Help: "Seconds Since Last Local Finish Sign (Should stay below 2 * Block Time)",
	})

	secondsSinceLastLocalNonceTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_local_ephemeral_share_time",
		Help: "Seconds Since Last Local Ephemeral Share Sign " +
			"(Should not increase beyond block time; If high, may indicate raft joining issue for CoSigner) ",
	})

	missedPrecommits = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_missed_precommits",
			Help: "Consecutive Precommit Missed",
		},
		[]string{"chain_id", "node"},
	)
	missedPrevotes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_missed_prevotes",
			Help: "Consecutive Prevote Missed",
		},
		[]string{"chain_id", "node"},
	)
	totalMissedPrecommits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_missed_precommits",
			Help: "Total Precommit Missed",
		},
		[]string{"chain_id", "node"},
	)
	totalMissedPrevotes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_missed_prevotes",
			Help: "Total Prevote Missed",
		},
		[]string{"chain_id", "node"},
	)

	missedNonces = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_missed_ephemeral_shares",
			Help: "Consecutive Threshold Signature Parts Missed",
		},
		[]string{"peerid"},
	)
	totalMissedNonces = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_missed_ephemeral_shares",
			Help: "Total Threshold Signature Parts Missed",
		},
		[]string{"peerid"},
	)

	sentryConnectTries = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_sentry_connect_tries",
			Help: "Consecutive Number of times sentry TCP connect has been tried (High count may indicate validator restarts)",
		},
		[]string{"node"},
	)
	totalSentryConnectTries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_sentry_connect_tries",
			Help: "Total Number of times sentry TCP connect has been tried (High count may indicate validator restarts)",
		},
		[]string{"node"},
	)

	beyondBlockErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_beyond_block_errors",
			Help: "Total Times Signing Started but duplicate height/round request arrives",
		},
		[]string{"chain_id", "node"},
	)
	failedSignVote = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_failed_sign_vote",
			Help: "Total Times Signer Failed to sign block - Unstarted and Unexepcted Height",
		},
		[]string{"chain_id", "node"},
	)

	totalRaftLeader = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_raft_leader",
		Help: "Total Times Signer is Raft Leader",
	})
	totalNotRaftLeader = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_raft_not_leader",
		Help: "Total Times Signer is NOT Raft Leader (Proxy signing to Raft Leader)",
	})
	totalRaftLeaderElectiontimeout = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_raft_leader_election_timeout",
		Help: "Total Times Raft Leader Failed Election (Lacking Peers)",
	})

	totalInvalidSignature = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_error_total_invalid_signatures",
		Help: "Total Times Combined Signature is Invalid",
	})

	totalInsufficientCosigners = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_error_total_insufficient_cosigners",
		Help: "Total Times Cosigners doesn't reach threshold",
	})

	timedSignBlockThresholdLag = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "signer_sign_block_threshold_lag_seconds",
		Help:       "Seconds taken to get threshold of cosigners available",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	timedSignBlockCosignerLag = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "signer_sign_block_cosigner_lag_seconds",
		Help:       "Seconds taken to get all cosigner signatures",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	timedSignBlockLag = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "signer_sign_block_lag_seconds",
		Help:       "Seconds taken to sign block",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	timedCosignerNonceLag = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "signer_cosigner_ephemeral_share_lag_seconds",
			Help:       "Time taken to get cosigner ephemeral share",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"peerid"},
	)
	timedCosignerSignLag = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "signer_cosigner_sign_lag_seconds",
			Help:       "Time taken to get cosigner signature",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"peerid"},
	)
)

func StartMetrics() {
	// Update elapsed times on an interval basis
	for {
		metricsTimeKeeper.UpdatePrometheusMetrics()

		// Prometheus often only polls every 1 to every few seconds
		// Frequent updates minimize reporting error.
		// Accuracy of 100ms is probably sufficient
		<-time.After(100 * time.Millisecond)
	}
}
