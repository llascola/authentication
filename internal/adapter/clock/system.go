// Package clock provides the wall-clock implementation of port.Clock. The
// domain never calls time.Now (ADR 0002); this adapter is the single place the
// real clock is read, wired in at main (T22). Tests inject a fixed fake instead.
package clock

import (
	"time"

	"authentication/internal/port"
)

var _ port.Clock = System{}

// System reports the current instant in UTC. UTC is deliberate: the domain
// stores whatever now it is handed, so keeping it UTC everywhere makes
// timestamps compare cleanly.
type System struct{}

// Now returns the current wall-clock time in UTC.
func (System) Now() time.Time { return time.Now().UTC() }
