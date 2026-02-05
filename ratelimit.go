package vulners

import (
	"context"
	"sync"
	"time"
)

const (
	minRate = 0.001 // minimum rate to prevent division by zero
)

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	mu         sync.Mutex
	rate       float64   // tokens per second
	burst      int       // max tokens
	tokens     float64   // current tokens
	lastUpdate time.Time // last token update time
}

// NewRateLimiter creates a new rate limiter with the specified rate and burst.
// rate is the number of requests allowed per second (minimum 0.001).
// burst is the maximum number of tokens (requests) that can accumulate.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	if rate < minRate {
		rate = minRate
	}
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst), // start full
		lastUpdate: time.Now(),
	}
}

// Wait blocks until a token is available.
// For context-aware waiting, use WaitContext instead.
func (r *RateLimiter) Wait() {
	_ = r.WaitContext(context.Background())
}

// WaitContext blocks until a token is available or the context is cancelled.
// Returns nil if a token was acquired, or the context error if cancelled.
func (r *RateLimiter) WaitContext(ctx context.Context) error {
	r.mu.Lock()

	for {
		r.refill()

		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}

		// Calculate wait time for one token
		// Guard against rate being too small
		rate := r.rate
		if rate < minRate {
			rate = minRate
		}
		waitTime := time.Duration((1 - r.tokens) / rate * float64(time.Second))

		// Release lock while sleeping
		r.mu.Unlock()

		// Wait with context support
		timer := time.NewTimer(waitTime)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}

		r.mu.Lock()
	}
}

// TryAcquire attempts to acquire a token without blocking.
// Returns true if a token was acquired, false otherwise.
func (r *RateLimiter) TryAcquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refill()

	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

// UpdateRate updates the rate limiter's rate.
// This is useful when the API returns rate limit headers.
// Rate must be positive; values <= 0 are ignored.
func (r *RateLimiter) UpdateRate(rate float64) {
	if rate < minRate {
		return // ignore invalid rates
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rate = rate
}

// UpdateBurst updates the rate limiter's burst size.
// Burst must be at least 1; values < 1 are ignored.
func (r *RateLimiter) UpdateBurst(burst int) {
	if burst < 1 {
		return // ignore invalid burst
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.burst = burst
	if r.tokens > float64(burst) {
		r.tokens = float64(burst)
	}
}

// Rate returns the current rate.
func (r *RateLimiter) Rate() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rate
}

// Burst returns the current burst size.
func (r *RateLimiter) Burst() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.burst
}

// refill adds tokens based on elapsed time. Must be called with mu held.
func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens += elapsed * r.rate
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}
	// Ensure tokens never go negative
	if r.tokens < 0 {
		r.tokens = 0
	}
	r.lastUpdate = now
}
