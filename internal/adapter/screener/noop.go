// Package screener provides implementations of port.PasswordScreener.
//
// NoOp is a PLACEHOLDER: it accepts every password, including known-breached
// ones. It exists only so the Register/ChangePassword/ResetPassword use-cases
// can keep the breach-screen call site wired (ADR 0011 makes breach screening
// the NIST control that replaces composition rules). Swapping in a real
// screener (HIBP range API, local Pwned Passwords dump) later touches only the
// wiring in main (T22), not the use-cases.
//
// DO NOT ship NoOp to any real deployment — it provides no protection.
package screener

import (
	"context"

	"authentication/internal/port"
)

var _ port.PasswordScreener = NoOp{}

// NoOp accepts all passwords. See package doc — placeholder only.
type NoOp struct{}

// Screen always returns nil: no password is ever rejected.
func (NoOp) Screen(_ context.Context, _ string) error { return nil }
