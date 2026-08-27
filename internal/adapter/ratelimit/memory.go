// Package ratelimit provides the in-process implementation of
// port.RateLimiter: a token bucket per key, guarded by one mutex.
//
// Token bucket rather than a fixed window: a fixed window lets a caller spend a
// full window's quota at the end of one window and another full quota at the
// start of the next, so the observed burst is twice the configured limit right
// across the boundary. A bucket refills continuously, so the limit holds over
// every interval, and the time until the next token is exactly the retryAfter
// the caller owes the client.
//
// In-memory means PER-PROCESS. Two replicas enforce two independent limits, so
// the effective limit is the configured one times the replica count. That is
// acceptable for the current single-process deployment; a shared backend
// (Redis) is a swap of this adapter, not a redesign, which is why
// port.RateLimiter carries an error return this implementation never uses.
package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"

	"authentication/internal/port"
)

var _ port.RateLimiter = (*Memory)(nil)

// maxSweepInterval caps how long reclamation may be deferred, independently of
// the policy window.
//
// Sweeping once per window reads as the natural cadence, but three of the four
// wired limiters use a one-hour window, and "at most one sweep per hour" means
// an entry that fell idle just after a sweep survives nearly two hours. Every
// distinct key mints an entry, and keys are cheap to vary — a fresh source
// address out of an IPv6 /64, or a subaddressed email, per request — so that
// second window is pure accumulation. Checking more often does not change WHICH
// buckets are droppable (still: idle for a full window), only how promptly the
// droppable ones go.
const maxSweepInterval = time.Minute

// defaultMaxKeys is the ceiling on live buckets before sweep starts evicting
// under pressure, whatever their age. It is not configurable: this adapter is
// the single-process stand-in that Phase 07 replaces with a shared backend, and
// a limit nobody can tune is one nobody can accidentally set to zero.
//
// At roughly 150 bytes per entry (bucket, map overhead, key string) this is
// ~15 MB per limiter, four limiters wired — a bound worth having, and orders of
// magnitude above any honest key count.
const defaultMaxKeys = 100_000

// bucket is one key's remaining quota. tokens is fractional so refill is
// continuous rather than stepped; last is the instant tokens was computed at.
type bucket struct {
	tokens float64
	last   time.Time
}

// Memory is a token-bucket rate limiter held in this process's memory. It is
// safe for concurrent use: every operation takes mu for its whole duration,
// which serializes the read-modify-write on a key's bucket.
//
// One Memory carries one policy. Wire one per protected action.
type Memory struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
	maxKeys   int

	capacity   float64 // burst size, == limit
	perSecond  float64 // refill rate: capacity tokens per window
	window     time.Duration
	sweepEvery time.Duration // how often reclamation runs; <= window
	clock      port.Clock
}

// NewMemory returns a limiter allowing limit actions per key per window, with
// bursts up to limit.
//
// Out-of-range arguments are clamped toward the RESTRICTIVE end — limit below 1
// becomes 1, a non-positive window becomes one minute — never toward the
// permissive one. A misconfigured throttle that lets everything through is a
// silent hole; one that is too tight is visible the moment someone is throttled.
//
// clock must not be nil. A nil clock is a wiring bug, and panicking here fails
// at startup rather than nil-dereferencing on the first request under load.
func NewMemory(limit int, window time.Duration, clock port.Clock) *Memory {
	if clock == nil {
		panic("ratelimit: NewMemory requires a non-nil port.Clock")
	}
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Memory{
		buckets:    make(map[string]*bucket),
		lastSweep:  clock.Now(),
		maxKeys:    defaultMaxKeys,
		capacity:   float64(limit),
		perSecond:  float64(limit) / window.Seconds(),
		window:     window,
		sweepEvery: min(window, maxSweepInterval),
		clock:      clock,
	}
}

// Allow consumes one token for key and reports whether the action may proceed.
// When it may not, retryAfter is the time until the next token accrues, always
// strictly positive. The error return is always nil: nothing here can fail.
func (m *Memory) Allow(_ context.Context, key string) (bool, time.Duration, error) {
	now := m.clock.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.sweep(now)

	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{tokens: m.capacity, last: now}
		m.buckets[key] = b
	} else {
		b.refill(now, m.perSecond, m.capacity)
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0, nil
	}
	return false, m.waitFor(1 - b.tokens), nil
}

// refill credits the tokens accrued since last, capped at capacity, and marks
// the bucket as seen now.
func (b *bucket) refill(now time.Time, perSecond, capacity float64) {
	b.tokens = b.tokensAt(now, perSecond, capacity)
	b.last = now
}

// tokensAt reports what the balance would be at now WITHOUT mutating anything,
// so eviction can judge a bucket without disturbing its idle clock — stamping
// last would make every bucket it inspected look freshly used and postpone the
// ordinary age-based reclamation.
//
// A non-positive elapsed contributes nothing. Time can move backwards across an
// NTP step, and letting a negative elapsed subtract tokens would throttle an
// innocent caller for as long as the step was large.
func (b *bucket) tokensAt(now time.Time, perSecond, capacity float64) float64 {
	elapsed := now.Sub(b.last)
	if elapsed <= 0 {
		return b.tokens
	}
	return math.Min(capacity, b.tokens+elapsed.Seconds()*perSecond)
}

// waitFor converts a token deficit into the time needed to accrue it, rounded
// up so the result is never zero — a retryAfter of 0 on a denial would invite
// an immediate retry that is certain to be denied again.
func (m *Memory) waitFor(deficit float64) time.Duration {
	seconds := deficit / m.perSecond
	return time.Duration(math.Ceil(seconds * float64(time.Second)))
}

// sweep reclaims buckets. It runs on write, so there is no background goroutine
// with a lifecycle to manage, and it does two separate jobs.
//
// The first is age-based and free of consequence: a bucket idle for a full
// window has refilled to capacity, which makes it indistinguishable from an
// absent one, so dropping it costs no enforcement at all. Without it the map
// grows forever — an attacker varying the key mints an entry per request and
// never frees one. This pass is throttled to once per sweepEvery (the window,
// or maxSweepInterval, whichever is shorter) to keep it amortized.
//
// The second is the pressure valve, and it is NOT free — see evictUnderPressure.
// It runs on every call, because the condition it guards against is a flood, and
// a flood must not have to wait for a timer.
//
// The bound this buys: roughly the keys seen within the last window, plus
// however many of those are currently throttled, and no more than maxKeys of
// anything else.
//
// Callers must hold m.mu.
func (m *Memory) sweep(now time.Time) {
	if now.Sub(m.lastSweep) >= m.sweepEvery {
		m.lastSweep = now
		for key, b := range m.buckets {
			if now.Sub(b.last) >= m.window {
				delete(m.buckets, key)
			}
		}
	}
	if len(m.buckets) > m.maxKeys {
		m.evictUnderPressure(now)
	}
}

// evictUnderPressure drops buckets before their age makes them free to drop,
// to stop a key-rotation flood from growing the map without bound.
//
// Evicting a live bucket RETURNS QUOTA: the key's next request finds no entry
// and starts again at full capacity. So the rule is that a bucket currently
// holding less than one token — a key that is being throttled right now — is
// never evicted. Those are the entries enforcement actually rests on, and
// dropping one would let an attacker switch off their own throttle by flooding
// the map with junk keys, turning memory pressure into a limiter bypass.
//
// What that leaves evictable is the population a flood creates: keys used once
// or twice, sitting near capacity, that would have been dropped a window later
// anyway. Giving one of those its full budget back is worth nothing to an
// attacker who was never going to reuse the key.
//
// The residual: if every bucket is throttled, nothing is evictable and the map
// stays over maxKeys. That is the correct direction — enforcement outranks the
// ceiling — and it is not cheap to reach, since draining a key costs the
// attacker a full limit's worth of requests per entry.
//
// Callers must hold m.mu.
func (m *Memory) evictUnderPressure(now time.Time) {
	for key, b := range m.buckets {
		if len(m.buckets) <= m.maxKeys {
			return
		}
		if b.tokensAt(now, m.perSecond, m.capacity) >= 1 {
			delete(m.buckets, key)
		}
	}
}
