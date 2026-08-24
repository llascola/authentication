package screener

import (
	"context"
	"errors"
	"log/slog"

	"authentication/internal/port"
)

var _ port.PasswordScreener = FailOpen{}

// FailOpen wraps a screener so that an unreachable corpus lets the password
// through instead of failing the request.
//
// The port deliberately leaves this to the caller, and it is a security
// decision, not an error-handling detail — so it lives in a named type that is
// wired in explicitly, rather than as a swallowed error somewhere in a use-case
// (ADR 0019).
//
// The trade: fail-open means an attacker who can block or slow the outbound call
// downgrades the deployment to no screening at all. Fail-closed means a third
// party's outage stops registration and password changes dead. For this project
// the second is the worse failure — a total outage of account creation is
// certain and immediate, while the downgrade requires an attacker already able
// to interfere with egress. The choice is reversible per deployment: drop the
// wrapper and the underlying error propagates.
//
// A skipped screen is logged at WARN with the transport error and never the
// password.
type FailOpen struct {
	Inner port.PasswordScreener
	Log   *slog.Logger
}

// Screen passes through a clean result and a breach verdict unchanged, and
// converts any other error — the "could not complete the check" case — into
// acceptance plus a warning.
func (f FailOpen) Screen(ctx context.Context, plaintext string) error {
	err := f.Inner.Screen(ctx, plaintext)
	if err == nil || errors.Is(err, port.ErrPasswordBreached) {
		return err
	}
	if f.Log != nil {
		f.Log.Warn("breach screen unavailable; accepting the password unscreened", "err", err)
	}
	return nil
}
