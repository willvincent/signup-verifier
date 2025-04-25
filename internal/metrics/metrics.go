package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	SignupAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signup_attempts_total",
			Help: "Total number of signup attempts",
		},
		[]string{"result"}, // success, failure, rate_limited, bot, etc.
	)

	VerifierResults = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "email_verifier_results_total",
			Help: "Total email verifier results",
		},
		[]string{"provider", "result"}, // valid, invalid, error
	)

	SignupDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "signup_duration_seconds",
			Help:    "Duration of signup processing",
			Buckets: prometheus.DefBuckets,
		},
	)
)

func Init() {
	prometheus.MustRegister(SignupAttempts)
	prometheus.MustRegister(VerifierResults)
	prometheus.MustRegister(SignupDuration)
}
