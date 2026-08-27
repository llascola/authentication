package httpapi

import "net/http"

// Key derivation decides what a rate limit actually counts, so it is worth
// testing directly rather than only through a route. Test-only.
//
// IPKeyForTest takes the proxy depth the router would bind at wiring time; pass
// 0 for the default posture, in which no forwarding header is consulted.
var (
	IPKeyForTest    = func(hops int) func(*http.Request) (string, bool) { return ipKey(hops) }
	EmailKeyForTest = emailKey
	ClientIPForTest = clientIP
)

// Compile-time proof the exported aliases keep the shapes they stand in for.
var (
	_ func(int) func(*http.Request) (string, bool) = IPKeyForTest
	_ func(*http.Request) (string, bool)           = EmailKeyForTest
	_ func(*http.Request, int) string              = ClientIPForTest
)

// CSRF token minting and verification are pure functions worth exercising
// directly, not only through a route. Test-only.
var (
	IssueCSRFTokenForTest = issueCSRFToken
	ValidCSRFTokenForTest = validCSRFToken
)
