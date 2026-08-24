package ratelimit

// BucketCountForTest reports how many per-key buckets are currently held, so a
// test can prove reclamation actually frees them. Test-only: bucket bookkeeping
// is an implementation detail, not part of port.RateLimiter.
func (m *Memory) BucketCountForTest() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}
