package clock_test

import (
	"testing"
	"time"

	"authentication/internal/adapter/clock"
)

func TestSystemNowReturnsUTC(t *testing.T) {
	got := clock.System{}.Now()
	if got.Location() != time.UTC {
		t.Errorf("Now() location = %v, want UTC", got.Location())
	}
}

func TestSystemNowIsNonDecreasing(t *testing.T) {
	c := clock.System{}
	first := c.Now()
	second := c.Now()
	if second.Before(first) {
		t.Errorf("second call %v is before first %v", second, first)
	}
}
