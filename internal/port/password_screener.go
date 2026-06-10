package port

import (
	"context"
	"errors"
)

// ErrPasswordBreached reports that a candidate password appears in a known
// breach corpus and must be rejected. Callers compare with errors.Is, matching
// the domain's sentinel convention.
var ErrPasswordBreached = errors.New("port: password found in breach corpus")

// PasswordScreener checks a candidate plaintext password against a corpus of
// known-compromised passwords (e.g. a local Pwned Passwords dump, or the HIBP
// range API with k-anonymity). It is the breach-screening control NIST SP
// 800-63B relies on in place of character-composition rules (see ADR 0011): the
// domain's DefaultPasswordPolicy imposes no composition rules, so this screen is
// what keeps weak-but-compliant passwords out.
//
// It lives in the port layer, not the domain, because it needs I/O (a datastore
// or network call) and context — both of which the dependency-free domain must
// not carry. The application layer invokes it alongside NFC normalization and
// hashing, after PasswordPolicy.Validate passes, on the transient plaintext that
// is then discarded; the plaintext never enters a domain entity.
//
// Implementations MUST NOT log or persist the plaintext, and SHOULD prefer a
// k-anonymity range query over sending a full hash to any third party.
type PasswordScreener interface {
	// Screen returns nil when the password is acceptable, ErrPasswordBreached
	// when it appears in the corpus, or another error if the check could not be
	// completed (the caller decides whether to fail open or closed).
	Screen(ctx context.Context, plaintext string) error
}
