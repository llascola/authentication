package ratelimit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authentication/internal/adapter/ratelimit"
)

var (
	ctx       = context.Background()
	timeFixed = time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
)

// testClock is a settable port.Clock. Time is injected (ADR 0002) so a test can
// prove a window refills without sleeping for it.
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }
func (c *testClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// allow calls Allow and fails the test on an unexpected error.
func allow(t *testing.T, m *ratelimit.Memory, key string) (bool, time.Duration) {
	t.Helper()
	allowed, retryAfter, err := m.Allow(ctx, key)
	if err != nil {
		t.Fatalf("Allow(%q) returned error: %v", key, err)
	}
	return allowed, retryAfter
}

func TestAllowsUpToLimitThenDenies(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(3, time.Minute, clock)

	for i := range 3 {
		allowed, retryAfter := allow(t, m, "k")
		if !allowed {
			t.Errorf("call %d: allowed = false, want true (under limit)", i)
		}
		if retryAfter != 0 {
			t.Errorf("call %d: retryAfter = %v, want 0 when allowed", i, retryAfter)
		}
	}

	allowed, retryAfter := allow(t, m, "k")
	if allowed {
		t.Error("call past the limit was allowed, want denied")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0 when denied", retryAfter)
	}
	if retryAfter > time.Minute {
		t.Errorf("retryAfter = %v, want <= the window (1m)", retryAfter)
	}
}

// TestRetryAfterIsTimeToNextToken pins the value, not just its sign: at 3 per
// 3s the bucket earns a token every second, so a denial one instant after
// exhaustion owes just under a second, rounded up to exactly 1s.
func TestRetryAfterIsTimeToNextToken(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(3, 3*time.Second, clock)

	for range 3 {
		allow(t, m, "k")
	}
	_, retryAfter := allow(t, m, "k")
	if retryAfter != time.Second {
		t.Errorf("retryAfter = %v, want 1s (3 tokens per 3s = 1 token per second)", retryAfter)
	}
}

func TestRefillsAfterWindow(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(2, time.Minute, clock)

	for range 2 {
		allow(t, m, "k")
	}
	if allowed, _ := allow(t, m, "k"); allowed {
		t.Fatal("expected the bucket to be empty")
	}

	clock.advance(time.Minute)

	for i := range 2 {
		if allowed, _ := allow(t, m, "k"); !allowed {
			t.Errorf("call %d after a full window: allowed = false, want true", i)
		}
	}
	if allowed, _ := allow(t, m, "k"); allowed {
		t.Error("refill exceeded capacity: a third call was allowed")
	}
}

// TestRefillIsPartialWithinWindow proves the refill is continuous rather than a
// step at the window boundary — the property a fixed-window counter lacks.
func TestRefillIsPartialWithinWindow(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(2, 2*time.Second, clock)

	for range 2 {
		allow(t, m, "k")
	}
	clock.advance(time.Second) // one token's worth, not two

	if allowed, _ := allow(t, m, "k"); !allowed {
		t.Error("first call after a half window: allowed = false, want true")
	}
	if allowed, _ := allow(t, m, "k"); allowed {
		t.Error("second call after a half window was allowed; only one token had accrued")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(1, time.Minute, clock)

	allow(t, m, "a")
	if allowed, _ := allow(t, m, "a"); allowed {
		t.Fatal("key a exceeded its limit")
	}
	if allowed, _ := allow(t, m, "b"); !allowed {
		t.Error("key b was denied; exhausting one key must not spend another's quota")
	}
}

// TestClockGoingBackwardsDoesNotDrainOrGrant guards the NTP-step case: a
// negative elapsed must not subtract tokens (throttling an innocent caller) and
// must not be treated as forward progress either.
func TestClockGoingBackwardsDoesNotDrainOrGrant(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(2, time.Minute, clock)

	allow(t, m, "k") // 1 token left
	clock.advance(-time.Hour)

	if allowed, _ := allow(t, m, "k"); !allowed {
		t.Error("a backwards clock step drained the bucket")
	}
	if allowed, _ := allow(t, m, "k"); allowed {
		t.Error("a backwards clock step granted tokens")
	}
}

// TestSweepReclaimsIdleBuckets is the memory-growth guard: an attacker varying
// the key mints a bucket per request, so idle ones have to be freed or the map
// grows without bound.
func TestSweepReclaimsIdleBuckets(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(1, time.Minute, clock)

	for _, key := range []string{"a", "b", "c"} {
		allow(t, m, key)
	}
	if got := m.BucketCountForTest(); got != 3 {
		t.Fatalf("bucket count = %d, want 3 before any sweep", got)
	}

	clock.advance(time.Minute + time.Second)
	allow(t, m, "d") // any write triggers the due sweep

	if got := m.BucketCountForTest(); got != 1 {
		t.Errorf("bucket count = %d, want 1 (only the fresh key d survives)", got)
	}
}

func TestSweepKeepsActiveBuckets(t *testing.T) {
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(4, time.Minute, clock)

	allow(t, m, "idle")
	allow(t, m, "active")

	clock.advance(30 * time.Second)
	allow(t, m, "active") // touched halfway through, so not idle a full window

	clock.advance(31 * time.Second) // a sweep is now due
	allow(t, m, "active")

	if got := m.BucketCountForTest(); got != 1 {
		t.Errorf("bucket count = %d, want 1: the idle key is reclaimed, the active one kept", got)
	}
	// The kept bucket must retain its spent quota, not be silently reset.
	if allowed, _ := allow(t, m, "active"); !allowed {
		t.Error("active key denied; it had quota left")
	}
}

// TestConcurrentAllowGrantsExactlyCapacity is the -race proof and the
// correctness proof at once: with time pinned, no tokens accrue during the run,
// so exactly capacity calls may win no matter how the goroutines interleave.
func TestConcurrentAllowGrantsExactlyCapacity(t *testing.T) {
	const (
		capacity = 50
		callers  = 400
	)
	clock := &testClock{now: timeFixed}
	m := ratelimit.NewMemory(capacity, time.Minute, clock)

	var granted atomic.Int64
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			allowed, _, err := m.Allow(ctx, "hot")
			if err == nil && allowed {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := granted.Load(); got != capacity {
		t.Errorf("granted = %d, want exactly %d", got, capacity)
	}
}

func TestNewMemoryClampsTowardRestrictive(t *testing.T) {
	clock := &testClock{now: timeFixed}

	m := ratelimit.NewMemory(0, time.Minute, clock)
	if allowed, _ := allow(t, m, "k"); !allowed {
		t.Error("limit 0 clamped to something that denies everything; want a limit of 1")
	}
	if allowed, _ := allow(t, m, "k"); allowed {
		t.Error("limit 0 was not clamped to 1: a second call was allowed")
	}

	// A non-positive window must not mean "refills instantly".
	zeroWindow := ratelimit.NewMemory(1, 0, clock)
	allow(t, zeroWindow, "k")
	if allowed, _ := allow(t, zeroWindow, "k"); allowed {
		t.Error("window 0 left the limiter permissive; want the one-minute fallback")
	}
}

func TestNewMemoryPanicsOnNilClock(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewMemory(nil clock) did not panic; a nil clock is a wiring bug")
		}
	}()
	_ = ratelimit.NewMemory(1, time.Minute, nil)
}
