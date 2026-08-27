package ratelimit

// BucketCountForTest reports how many per-key buckets are currently held, so a
// test can prove reclamation actually frees them. Test-only: bucket bookkeeping
// is an implementation detail, not part of port.RateLimiter.
func (m *Memory) BucketCountForTest() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}

// SetMaxKeysForTest lowers the eviction ceiling so a test can prove the pressure
// valve without allocating a hundred thousand buckets. Test-only: the real
// ceiling is deliberately not configurable.
func (m *Memory) SetMaxKeysForTest(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxKeys = n
}
