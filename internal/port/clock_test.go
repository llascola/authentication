package port_test

import (
	"testing"
	"time"

	"authentication/internal/port"
)

var _ port.Clock = fixedClock{}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time { return c.now }

func TestFixedClockReturnsInjectedInstant(t *testing.T) {
	instant := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	var c port.Clock = fixedClock{now: instant}
	if got := c.Now(); !got.Equal(instant) {
		t.Errorf("Now() = %v, want %v", got, instant)
	}
}
