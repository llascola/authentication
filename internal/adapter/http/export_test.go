package httpapi

import "net/http"

// Key derivation decides what a rate limit actually counts, so it is worth
// testing directly rather than only through a route. Test-only.
var (
	IPKeyForTest    = ipKey
	EmailKeyForTest = emailKey
)

// Compile-time proof the exported aliases keep the keyFunc shape.
var (
	_ func(*http.Request) (string, bool) = IPKeyForTest
	_ func(*http.Request) (string, bool) = EmailKeyForTest
)

// CSRF token minting and verification are pure functions worth exercising
// directly, not only through a route. Test-only.
var (
	IssueCSRFTokenForTest = issueCSRFToken
	ValidCSRFTokenForTest = validCSRFToken
)
