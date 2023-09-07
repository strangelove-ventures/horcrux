package metrics

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
	SecondsSinceLastPrecommit.Set(time.Since(mt.previousPrecommit).Seconds())
	SecondsSinceLastPrevote.Set(time.Since(mt.previousPrevote).Seconds())
	SecondsSinceLastLocalSignStart.Set(time.Since(mt.previousLocalSignStart).Seconds())
	SecondsSinceLastLocalSignFinish.Set(time.Since(mt.previousLocalSignFinish).Seconds())
	SecondsSinceLastLocalNonceTime.Set(time.Since(mt.previousLocalNonce).Seconds())
}

var (
	// Variables to calculate Prometheus Metrics
	PreviousPrecommitHeight = int64(0)
	PreviousPrevoteHeight   = int64(0)
	MetricsTimeKeeper       = newMetricsTimer()

	// Prometheus Metrics
	TotalPubKeyRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_pubkey_requests",
		Help: "Total times public key requested (High count may indicate validator restarts)",
	})
	LastPrecommitHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_precommit_height",
		Help: "Last Height Precommit Signed",
	})
	LastPrevoteHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_prevote_height",
		Help: "Last Height Prevote Signed",
	})

	LastProposalHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_proposal_height",
		Help: "Last Height Proposal Signed",
	})
	LastPrecommitRound = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_precommit_round",
		Help: "Last Round Precommit Signed",
	})
	LastPrevoteRound = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_prevote_round",
		Help: "Last Round Prevote Signed",
	})
	LastProposalRound = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_last_proposal_round",
		Help: "Last Round Proposal Signed",
	})

	TotalPrecommitsSigned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_precommits_signed",
		Help: "Total Precommit Signed",
	})
	TotalPrevotesSigned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_prevotes_signed",
		Help: "Total Prevote Signed",
	})
	TotalProposalsSigned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_proposals_signed",
		Help: "Total Proposal Signed",
	})

	SecondsSinceLastPrecommit = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_precommit",
		Help: "Seconds Since Last Precommit (Useful for Signing Co-Signer Node, Single Signer)",
	})
	SecondsSinceLastPrevote = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_prevote",
		Help: "Seconds Since Last Prevote (Useful for Signing Co-Signer Node, Single Signer)",
	})
	SecondsSinceLastLocalSignStart = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_local_sign_start_time",
		Help: "Seconds Since Last Local Start Sign (May increase beyond block time, Rarely important) ",
	})
	SecondsSinceLastLocalSignFinish = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_local_sign_finish_time",
		Help: "Seconds Since Last Local Finish Sign (Should stay below 2 * Block Time)",
	})

	SecondsSinceLastLocalNonceTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_seconds_since_last_local_ephemeral_share_time",
		Help: "Seconds Since Last Local Ephemeral Share Sign " +
			"(Should not increase beyond block time; If high, may indicate raft joining issue for CoSigner) ",
	})

	MissedPrecommits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_missed_precommits",
		Help: "Consecutive Precommit Missed",
	})
	MissedPrevotes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_missed_prevotes",
		Help: "Consecutive Prevote Missed",
	})
	TotalMissedPrecommits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_missed_precommits",
		Help: "Total Precommit Missed",
	})
	TotalMissedPrevotes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_missed_prevotes",
		Help: "Total Prevote Missed",
	})

	MissedNonces = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "signer_missed_ephemeral_shares",
			Help: "Consecutive Threshold Signature Parts Missed",
		},
		[]string{"peerid"},
	)
	TotalMissedNonces = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_total_missed_ephemeral_shares",
			Help: "Total Threshold Signature Parts Missed",
		},
		[]string{"peerid"},
	)

	SentryConnectTries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "signer_sentry_connect_tries",
		Help: "Consecutive Number of times sentry TCP connect has been tried (High count may indicate validator restarts)",
	})
	TotalSentryConnectTries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_sentry_connect_tries",
		Help: "Total Number of times sentry TCP connect has been tried (High count may indicate validator restarts)",
	})

	BeyondBlockErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_beyond_block_errors",
		Help: "Total Times Signing Started but duplicate height/round request arrives",
	})
	FailedSignVote = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_failed_sign_vote",
		Help: "Total Times Signer Failed to sign block - Unstarted and Unexepcted Height",
	})

	TotalRaftLeader = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_raft_leader",
		Help: "Total Times Signer is Raft Leader",
	})
	TotalNotRaftLeader = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_raft_not_leader",
		Help: "Total Times Signer is NOT Raft Leader (Proxy signing to Raft Leader)",
	})
	TotalRaftLeaderElectiontimeout = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_total_raft_leader_election_timeout",
		Help: "Total Times Raft Leader Failed Election (Lacking Peers)",
	})

	TotalInvalidSignature = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_error_total_invalid_signatures",
		Help: "Total Times Combined Signature is Invalid",
	})

	TotalInsufficientCosigners = promauto.NewCounter(prometheus.CounterOpts{
		Name: "signer_error_total_insufficient_cosigners",
		Help: "Total Times Cosigners doesn't reach threshold",
	})

	TimedSignBlockThresholdLag = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "signer_sign_block_threshold_lag_seconds",
		Help:       "Seconds taken to get threshold of cosigners available",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	TimedSignBlockCosignerLag = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "signer_sign_block_cosigner_lag_seconds",
		Help:       "Seconds taken to get all cosigner signatures",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	TimedSignBlockLag = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "signer_sign_block_lag_seconds",
		Help:       "Seconds taken to sign block",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	TimedCosignerNonceLag = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "signer_cosigner_ephemeral_share_lag_seconds",
			Help:       "Time taken to get cosigner ephemeral share",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"peerid"},
	)
	TimedCosignerSignLag = promauto.NewSummaryVec(
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
		MetricsTimeKeeper.UpdatePrometheusMetrics()

		// Prometheus often only polls every 1 to every few seconds
		// Frequent updates minimize reporting error.
		// Accuracy of 100ms is probably sufficient
		<-time.After(100 * time.Millisecond)
	}
}
