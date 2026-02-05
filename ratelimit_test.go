package vulners

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_Basic(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	// Should have 5 tokens available initially
	for i := 0; i < 5; i++ {
		if !rl.TryAcquire() {
			t.Errorf("expected TryAcquire to succeed on attempt %d", i+1)
		}
	}

	// 6th attempt should fail (no tokens left)
	if rl.TryAcquire() {
		t.Error("expected TryAcquire to fail when no tokens available")
	}
}

func TestRateLimiter_Refill(t *testing.T) {
	rl := NewRateLimiter(100, 1) // 100 tokens/sec, burst of 1

	// Use the one token
	if !rl.TryAcquire() {
		t.Error("expected first TryAcquire to succeed")
	}

	// Should fail immediately
	if rl.TryAcquire() {
		t.Error("expected second TryAcquire to fail")
	}

	// Wait for refill (10ms should give us at least 1 token at 100/sec)
	time.Sleep(15 * time.Millisecond)

	// Should succeed after refill
	if !rl.TryAcquire() {
		t.Error("expected TryAcquire to succeed after refill")
	}
}

func TestRateLimiter_Wait(t *testing.T) {
	rl := NewRateLimiter(100, 1) // 100 tokens/sec

	// Use the one token
	rl.Wait()

	start := time.Now()
	rl.Wait() // Should wait ~10ms
	elapsed := time.Since(start)

	// Should have waited at least 5ms (allowing for some timing variance)
	if elapsed < 5*time.Millisecond {
		t.Errorf("expected Wait to block, but only took %v", elapsed)
	}
}

func TestRateLimiter_UpdateRate(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	if rl.Rate() != 10 {
		t.Errorf("expected rate=10, got %f", rl.Rate())
	}

	rl.UpdateRate(20)

	if rl.Rate() != 20 {
		t.Errorf("expected rate=20 after update, got %f", rl.Rate())
	}
}

func TestRateLimiter_UpdateBurst(t *testing.T) {
	rl := NewRateLimiter(10, 10)

	if rl.Burst() != 10 {
		t.Errorf("expected burst=10, got %d", rl.Burst())
	}

	rl.UpdateBurst(5)

	if rl.Burst() != 5 {
		t.Errorf("expected burst=5 after update, got %d", rl.Burst())
	}
}

func TestRateLimiter_ZeroRate(t *testing.T) {
	// Rate of 0 should be converted to minRate
	rl := NewRateLimiter(0, 5)

	// Should still work (not panic or hang)
	if rl.Rate() < 0.001 {
		t.Errorf("expected rate >= minRate, got %f", rl.Rate())
	}

	// Should be able to acquire tokens
	if !rl.TryAcquire() {
		t.Error("expected TryAcquire to succeed with zero rate")
	}
}

func TestRateLimiter_UpdateRateZero(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	originalRate := rl.Rate()

	// Updating to 0 should be ignored
	rl.UpdateRate(0)

	if rl.Rate() != originalRate {
		t.Errorf("expected rate to remain %f after zero update, got %f", originalRate, rl.Rate())
	}

	// Negative rate should also be ignored
	rl.UpdateRate(-5)

	if rl.Rate() != originalRate {
		t.Errorf("expected rate to remain %f after negative update, got %f", originalRate, rl.Rate())
	}
}

func TestRateLimiter_UpdateBurstZero(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	originalBurst := rl.Burst()

	// Updating to 0 should be ignored
	rl.UpdateBurst(0)

	if rl.Burst() != originalBurst {
		t.Errorf("expected burst to remain %d after zero update, got %d", originalBurst, rl.Burst())
	}
}

func TestRateLimiter_ConcurrentWait(t *testing.T) {
	rl := NewRateLimiter(100, 10) // 100 tokens/sec, burst of 10

	var wg sync.WaitGroup
	numGoroutines := 20

	// Launch many goroutines that all try to acquire tokens
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.Wait()
		}()
	}

	// All goroutines should eventually complete (not deadlock)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Error("concurrent Wait deadlocked")
	}
}
