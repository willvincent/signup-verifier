package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter_Allow(t *testing.T) {
	rl := New(10, 2) // 10 req/min, burst 2

	ip := "1.2.3.4"
	if !rl.Allow(ip) {
		t.Fatal("first request should be allowed")
	}
	if !rl.Allow(ip) {
		t.Fatal("second request should be allowed (burst)")
	}
	if rl.Allow(ip) {
		t.Fatal("third request should be denied (over burst)")
	}

	time.Sleep(6 * time.Second) // refill some tokens (10 req/min = 1 per 6s)
	if !rl.Allow(ip) {
		t.Fatal("request after wait should be allowed")
	}
}
