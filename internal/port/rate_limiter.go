package port

import (
	"context"
	"time"
)

// RateLimiter answers one question: may the action keyed by key proceed right
// now. It is the throttle in front of the unauthenticated, cost-bearing edges —
// login (password spraying across many accounts, which per-account lockout does
// not catch), forgot-password, and resend-verification (both of which put mail
// on the deployment's own SMTP quota and sending reputation).
//
// key is an opaque string. The port stays ignorant of what is in it — IP,
// email, route, or a composition — so the policy decision lives at the edge
// that builds the key, not here.
//
// One limiter instance carries one policy (a limit and a window). Wire a
// separate instance per protected action rather than passing a policy argument
// on every call: that keeps configuration at the wiring site and makes the
// limit a property of the object a handler holds.
//
// Contract:
//
//   - Allow CONSUMES quota when it returns allowed. It is not a peek; call it
//     once per attempt.
//   - retryAfter is meaningful only when allowed is false, and is then strictly
//     positive: it is how long the caller should wait before retrying. When
//     allowed is true it is zero.
//   - When err is non-nil, allowed and retryAfter carry no meaning. Whether the
//     caller then fails open (serve the request) or fails closed (reject it) is
//     a security decision belonging to the caller, not to this port.
//
// The error return exists for implementations that can genuinely fail — a
// Redis- or database-backed limiter shared across replicas. The in-process
// implementation never returns one. Declaring it up front is deliberate:
// widening the interface later would touch every call site.
//
// Implementations must be safe for concurrent use: a limiter is shared by every
// in-flight request, and the read-modify-write on a key's counter has to be
// serialized (ADR 0008's discipline, applied outside the aggregate).
type RateLimiter interface {
	Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error)
}
