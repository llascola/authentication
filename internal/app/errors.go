// Package app orchestrates the domain through the driven ports. It owns the
// transient plaintext password (normalize → validate → screen → hash → discard);
// the plaintext never enters a domain entity. Use-cases depend on port
// interfaces only, never on a concrete adapter, so they are testable with the
// in-memory store and fakes.
package app

import "errors"

// Enumeration-safe sentinels. Each collapses several distinct internal causes
// into one outward error so the HTTP layer renders an identical response and
// reveals nothing about account or token existence.
var (
	// ErrAuthFailed is returned for every login/credential failure — unknown
	// email, wrong password, locked, inactive, or unverified — so none is
	// distinguishable from another.
	ErrAuthFailed = errors.New("app: authentication failed")

	// ErrNotAuthenticated is returned when a presented session token does not
	// resolve to an active session (unknown, revoked, or expired).
	ErrNotAuthenticated = errors.New("app: not authenticated")

	// ErrInvalidToken is returned when a verification/reset token is unknown,
	// expired, already consumed, or of the wrong purpose.
	ErrInvalidToken = errors.New("app: invalid or expired token")
)
