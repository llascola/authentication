package port_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"authentication/internal/port"
)

var _ port.RateLimiter = (*fakeLimiter)(nil)

// fakeLimiter allows the first n calls per key, then denies with retryAfter.
// errKeys forces the error branch so the contract's "allowed is meaningless on
// error" rule has something to exercise.
type fakeLimiter struct {
	n          int
	retryAfter time.Duration
	seen       map[string]int
	errKeys    map[string]error
}

func newFakeLimiter(n int, retryAfter time.Duration) *fakeLimiter {
	return &fakeLimiter{n: n, retryAfter: retryAfter, seen: map[string]int{}, errKeys: map[string]error{}}
}

func (f *fakeLimiter) Allow(_ context.Context, key string) (bool, time.Duration, error) {
	if err, ok := f.errKeys[key]; ok {
		return false, 0, err
	}
	f.seen[key]++
	if f.seen[key] > f.n {
		return false, f.retryAfter, nil
	}
	return true, 0, nil
}

func TestRateLimiterAllowsUntilLimitThenDenies(t *testing.T) {
	const retryAfter = 30 * time.Second
	var rl port.RateLimiter = newFakeLimiter(2, retryAfter)

	for i := range 2 {
		allowed, wait, err := rl.Allow(context.Background(), "k")
		if err != nil {
			t.Fatalf("call %d: Allow returned error: %v", i, err)
		}
		if !allowed {
			t.Errorf("call %d: allowed = false, want true (under limit)", i)
		}
		if wait != 0 {
			t.Errorf("call %d: retryAfter = %v, want 0 when allowed", i, wait)
		}
	}

	allowed, wait, err := rl.Allow(context.Background(), "k")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if allowed {
		t.Error("allowed = true past the limit, want false")
	}
	if wait <= 0 {
		t.Errorf("retryAfter = %v, want > 0 when denied", wait)
	}
}

func TestRateLimiterKeysAreIndependent(t *testing.T) {
	var rl port.RateLimiter = newFakeLimiter(1, time.Second)

	if allowed, _, _ := rl.Allow(context.Background(), "a"); !allowed {
		t.Fatal("first call on key a denied")
	}
	if allowed, _, _ := rl.Allow(context.Background(), "a"); allowed {
		t.Fatal("second call on key a allowed, want denied")
	}
	// Exhausting one key must not spend another's quota.
	if allowed, _, _ := rl.Allow(context.Background(), "b"); !allowed {
		t.Error("first call on key b denied; keys must be independent")
	}
}

func TestRateLimiterReportsError(t *testing.T) {
	errBackend := errors.New("limiter backend unreachable")
	f := newFakeLimiter(1, time.Second)
	f.errKeys["broken"] = errBackend

	var rl port.RateLimiter = f
	_, _, err := rl.Allow(context.Background(), "broken")
	if !errors.Is(err, errBackend) {
		t.Errorf("Allow error = %v, want %v", err, errBackend)
	}
}
