package ratelimit

import (
	"sync"

	"golang.org/x/time/rate"
)

type Limiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

func New(rps int, burst int) *Limiter {
	return &Limiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(float64(rps) / 60), // per minute to per second
		burst:    burst,
	}
}

func (l *Limiter) getLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.limiters[ip] = limiter
	}
	return limiter
}

func (l *Limiter) Allow(ip string) bool {
	return l.getLimiter(ip).Allow()
}
