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
	previousLocalEphemeralShare                     time.Time
}

func newMetricsTimer() *metricsTimer {
	now := time.Now()
	return &metricsTimer{
		mu:                sync.Mutex{},
		previousPrecommit: now, previousPrevote: now,
		previousLocalSignStart: now, previousLocalSignFinish: now,
		previousLocalEphemeralShare: now,
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

func (mt *metricsTimer) SetPreviousLocalEphemeralShare(t time.Time) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.previousLocalEphemeralShare = t
}

func (mt *metricsTimer) UpdatePrometheusMetrics(t time.Time) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Update Prometheus Gauges
	secondsSinceLastPrecommit.Set(time.Since(mt.previousPrecommit).Seconds())
	secondsSinceLastPrevote.Set(time.Since(mt.previousPrevote).Seconds())
	secondsSinceLastLocalSignStart.Set(time.Since(mt.previousLocalSignStart).Seconds())
	secondsSinceLastLocalSignFinish.Set(time.Since(mt.previousLocalSignFinish).Seconds())
	secondsSinceLastLocalEphemeralShareTime.Set(time.Since(mt.previousLocalEphemeralShare).Seconds())
}

var (
	// Variables to calculate Prometheus Metrics
	previousPrecommitHeight = int64(0)
	previousPrevoteHeight   = int64(0)
	metricsTimeKeeper       = newMetricsTimer()

	// Prometheus Metrics
	totalPubKeyRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_pubkey_requests",
		Help: "Total times public key requested (High count may indicate validator restarts)",
	})
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

	totalPrecommitsSigned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_precommits_signed",
		Help: "Total Precommit Signed",
	})
	totalPrevotesSigned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_prevotes_signed",
		Help: "Total Prevote Signed",
	})
	totalProposalsSigned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_proposals_signed",
		Help: "Total Proposal Signed",
	})

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

	secondsSinceLastLocalEphemeralShareTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_local_ephemeral_share_time",
		Help: "Seconds Since Last Local Ephemeral Share Sign " +
			"(Should not increase beyond block time; If high, may indicate raft joining issue for CoSigner) ",
	})

	missedPrecommits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_missed_precommits",
		Help: "Consecutive Precommit Missed",
	})
	missedPrevotes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_missed_prevotes",
		Help: "Consecutive Prevote Missed",
	})
	totalMissedPrecommits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_missed_precommits",
		Help: "Total Precommit Missed",
	})
	totalMissedPrevotes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_missed_prevotes",
		Help: "Total Prevote Missed",
	})

	missedEphemeralShares = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_missed_ephemeral_shares",
			Help: "Consecutive Threshold Signature Parts Missed",
		},
		[]string{"peerid"},
	)
	totalMissedEphemeralShares = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_missed_ephemeral_shares",
			Help: "Total Threshold Signature Parts Missed",
		},
		[]string{"peerid"},
	)

	sentryConnectTries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_sentry_connect_tries",
		Help: "Consecutive Number of times sentry TCP connect has been tried (High count may indicate validator restarts)",
	})
	totalSentryConnectTries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_sentry_connect_tries",
		Help: "Total Number of times sentry TCP connect has been tried (High count may indicate validator restarts)",
	})

	beyondBlockErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_beyond_block_errors",
		Help: "Total Times Signing Started but duplicate height/round request arrives",
	})
	failedSignVote = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_failed_sign_vote",
		Help: "Total Times Signer Failed to sign block - Unstarted and Unexepcted Height",
	})

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

	timedCosignerEphemeralShareLag = promauto.NewSummaryVec(
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
		metricsTimeKeeper.UpdatePrometheusMetrics(time.Now())

		// Prometheus often only polls every 1 to every few seconds
		// Frequent updates minimize reporting error.
		// Accuracy of 100ms is probably sufficient
		<-time.After(100 * time.Millisecond)
	}
}
