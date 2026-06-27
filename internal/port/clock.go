package port

import "time"

// Clock is the application's single, fakeable source of the current instant.
// The domain takes now as an explicit parameter and never calls time.Now
// (ADR 0002); Clock is what produces that value at the application boundary.
// Implementations return UTC (the adapter is time.Now().UTC(), T10); tests
// inject a fixed clock to pin time without touching the wall clock.
type Clock interface {
	Now() time.Time
}
