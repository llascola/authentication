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

	capacity  float64 // burst size, == limit
	perSecond float64 // refill rate: capacity tokens per window
	window    time.Duration
	clock     port.Clock
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
		buckets:   make(map[string]*bucket),
		lastSweep: clock.Now(),
		capacity:  float64(limit),
		perSecond: float64(limit) / window.Seconds(),
		window:    window,
		clock:     clock,
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

// refill credits the tokens accrued since last, capped at capacity.
//
// A non-positive elapsed is treated as zero. Time can move backwards across an
// NTP step, and letting a negative elapsed subtract tokens would throttle an
// innocent caller for as long as the step was large.
func (b *bucket) refill(now time.Time, perSecond, capacity float64) {
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens = math.Min(capacity, b.tokens+elapsed.Seconds()*perSecond)
	}
	b.last = now
}

// waitFor converts a token deficit into the time needed to accrue it, rounded
// up so the result is never zero — a retryAfter of 0 on a denial would invite
// an immediate retry that is certain to be denied again.
func (m *Memory) waitFor(deficit float64) time.Duration {
	seconds := deficit / m.perSecond
	return time.Duration(math.Ceil(seconds * float64(time.Second)))
}

// sweep drops buckets that have sat idle long enough to be back at full
// capacity: such a bucket is indistinguishable from an absent one, so keeping
// it only costs memory.
//
// Without this the map grows forever — an attacker varying the key (a fresh
// source IP or address per request) would mint an entry per request and never
// free one. Sweeping on write, at most once per window, keeps the cost
// amortized and avoids a background goroutine with a lifecycle to manage. The
// bound it buys: entries touched within roughly the last two windows, rather
// than every key ever seen.
//
// Callers must hold m.mu.
func (m *Memory) sweep(now time.Time) {
	if now.Sub(m.lastSweep) < m.window {
		return
	}
	m.lastSweep = now
	for key, b := range m.buckets {
		if now.Sub(b.last) >= m.window {
			delete(m.buckets, key)
		}
	}
}
