package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/willvincent/signup-verifier/internal/metrics"
)

func TestInit(t *testing.T) {
	metrics.Init()

	metrics.SignupAttempts.WithLabelValues("testcase").Inc()
	val := testutil.ToFloat64(metrics.SignupAttempts.WithLabelValues("testcase"))
	if val != 1 {
		t.Errorf("Expected counter to be 1, got %f", val)
	}
}
