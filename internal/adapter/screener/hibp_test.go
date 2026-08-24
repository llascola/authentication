package screener_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"authentication/internal/adapter/screener"
	"authentication/internal/port"
)

// The published SHA-1 of "password", uppercase hex. Hard-coded rather than
// recomputed in the test: it is the value HIBP itself indexes by, so it also
// proves this adapter hashes the way the API expects.
const (
	pwPassword        = "password"
	sha1Password      = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
	prefixPassword    = "5BAA6"
	suffixPassword    = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	suffixSomeoneElse = "0000000000000000000000000000000000A"
)

// roundTripFunc turns a function into an http.RoundTripper, so a test can answer
// requests without a network or a listener.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// stubClient answers every request with the given body and status, and records
// the last request for inspection.
func stubClient(status int, body string) (*http.Client, *http.Request) {
	var seen http.Request
	c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = *r
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	return c, &seen
}

// rangeBody renders a response in HIBP's "SUFFIX:COUNT" form.
func rangeBody(lines ...string) string { return strings.Join(lines, "\r\n") + "\r\n" }

func TestHIBPRejectsABreachedPassword(t *testing.T) {
	client, _ := stubClient(http.StatusOK, rangeBody(
		suffixSomeoneElse+":3",
		suffixPassword+":9659365",
	))
	s := screener.NewHIBP(client)

	if err := s.Screen(context.Background(), pwPassword); !errors.Is(err, port.ErrPasswordBreached) {
		t.Errorf("Screen(%q) = %v, want ErrPasswordBreached", pwPassword, err)
	}
}

func TestHIBPAcceptsAnUnlistedPassword(t *testing.T) {
	// The bucket comes back full of other people's suffixes; ours is not there.
	client, _ := stubClient(http.StatusOK, rangeBody(
		suffixSomeoneElse+":3",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:12",
	))
	s := screener.NewHIBP(client)

	if err := s.Screen(context.Background(), pwPassword); err != nil {
		t.Errorf("Screen = %v, want nil for a suffix not in the bucket", err)
	}
}

// TestHIBPSendsOnlyThePrefix is the assertion that catches a refactor quietly
// sending the whole hash, or worse the password. It is the entire privacy claim
// of k-anonymity, so it checks the URL positively AND negatively.
func TestHIBPSendsOnlyThePrefix(t *testing.T) {
	client, seen := stubClient(http.StatusOK, rangeBody(suffixSomeoneElse+":3"))
	s := screener.NewHIBP(client)

	if err := s.Screen(context.Background(), pwPassword); err != nil {
		t.Fatalf("Screen: %v", err)
	}

	if got := seen.URL.Path; got != "/range/"+prefixPassword {
		t.Errorf("request path = %q, want %q", got, "/range/"+prefixPassword)
	}
	if seen.URL.RawQuery != "" {
		t.Errorf("request carried a query string %q; the prefix belongs in the path alone", seen.URL.RawQuery)
	}
	// Check the path and query, not the whole URL: the host is a constant we
	// chose, and "api.pwnedpasswords.com" happens to contain the word this test
	// uses as its password.
	target := seen.URL.EscapedPath() + "?" + seen.URL.RawQuery
	if strings.Contains(strings.ToUpper(target), suffixPassword) {
		t.Error("the request target contains the hash suffix; only the first 5 characters may leave")
	}
	if strings.Contains(strings.ToUpper(target), sha1Password) {
		t.Error("the request target contains the full SHA-1")
	}
	if strings.Contains(strings.ToLower(target), pwPassword) {
		t.Error("the request target contains the password itself")
	}
	if seen.Body != nil {
		t.Error("the request carried a body; the range API is a plain GET")
	}
}

// TestHIBPRequestsPadding: without padding, the response size narrows down which
// prefix was asked for to anyone watching the encrypted stream.
func TestHIBPRequestsPadding(t *testing.T) {
	client, seen := stubClient(http.StatusOK, rangeBody(suffixSomeoneElse+":3"))
	s := screener.NewHIBP(client)

	if err := s.Screen(context.Background(), pwPassword); err != nil {
		t.Fatalf("Screen: %v", err)
	}
	if got := seen.Header.Get("Add-Padding"); got != "true" {
		t.Errorf("Add-Padding = %q, want \"true\"", got)
	}
}

// TestHIBPIgnoresPaddingEntries: padding arrives as real-looking suffixes with a
// count of 0. Counting one as a hit would reject a password on deliberate noise.
func TestHIBPIgnoresPaddingEntries(t *testing.T) {
	client, _ := stubClient(http.StatusOK, rangeBody(
		suffixPassword+":0", // this is padding, not a breach
		suffixSomeoneElse+":7",
	))
	s := screener.NewHIBP(client)

	if err := s.Screen(context.Background(), pwPassword); err != nil {
		t.Errorf("Screen = %v, want nil: a zero count is padding, not a hit", err)
	}
}

// TestHIBPMatchesSuffixCaseInsensitively: the API returns uppercase, but a
// mirror or a proxy may not. A missed match silently disables the screen.
func TestHIBPMatchesSuffixCaseInsensitively(t *testing.T) {
	client, _ := stubClient(http.StatusOK, rangeBody(strings.ToLower(suffixPassword)+":42"))
	s := screener.NewHIBP(client)

	if err := s.Screen(context.Background(), pwPassword); !errors.Is(err, port.ErrPasswordBreached) {
		t.Errorf("Screen = %v, want ErrPasswordBreached for a lowercase suffix", err)
	}
}

func TestHIBPTolerantOfJunkLines(t *testing.T) {
	client, _ := stubClient(http.StatusOK, rangeBody(
		"",
		"not-a-suffix-line",
		suffixPassword+":5",
	))
	s := screener.NewHIBP(client)

	if err := s.Screen(context.Background(), pwPassword); !errors.Is(err, port.ErrPasswordBreached) {
		t.Errorf("Screen = %v, want the real entry to still be found past junk lines", err)
	}
}

// TestHIBPReportsIncompleteChecks: the adapter itself never decides to allow a
// password it could not check — it reports, and FailOpen decides. A wrong answer
// here would silently disable screening.
func TestHIBPReportsIncompleteChecks(t *testing.T) {
	t.Run("non-200", func(t *testing.T) {
		client, _ := stubClient(http.StatusServiceUnavailable, "")
		err := screener.NewHIBP(client).Screen(context.Background(), pwPassword)
		if err == nil {
			t.Fatal("Screen = nil on a 503, want an error")
		}
		if errors.Is(err, port.ErrPasswordBreached) {
			t.Error("a failed check was reported as a breach")
		}
	})

	t.Run("transport failure", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("dial tcp: connection refused")
		})}
		err := screener.NewHIBP(client).Screen(context.Background(), pwPassword)
		if err == nil {
			t.Fatal("Screen = nil on a transport failure, want an error")
		}
		if errors.Is(err, port.ErrPasswordBreached) {
			t.Error("a failed check was reported as a breach")
		}
	})

	// A body past the read cap is a check that could not be completed: the
	// suffixes beyond the cap were never compared, so reporting "not found"
	// would silently downgrade the screen to nothing.
	t.Run("body past the read cap", func(t *testing.T) {
		client, _ := stubClient(http.StatusOK, oversizedRange())
		err := screener.NewHIBP(client).Screen(context.Background(), pwPassword)
		if err == nil {
			t.Fatal("Screen = nil on an over-cap body, want an error")
		}
		if errors.Is(err, port.ErrPasswordBreached) {
			t.Error("a failed check was reported as a breach")
		}
		// Pin the reason: the cap was hit, not some incidental scan failure.
		if !strings.Contains(err.Error(), "check incomplete") {
			t.Errorf("Screen = %v, want the read-cap error", err)
		}
	})

	// A hit found before the cap is still a hit. Rejecting the password is the
	// safe direction, and the bytes that would confirm it again are the ones we
	// deliberately refused to read.
	t.Run("over-cap body with the match before the cap", func(t *testing.T) {
		client, _ := stubClient(http.StatusOK, rangeBody(suffixPassword+":9659365")+oversizedRange())
		if err := screener.NewHIBP(client).Screen(context.Background(), pwPassword); !errors.Is(err, port.ErrPasswordBreached) {
			t.Errorf("Screen = %v, want ErrPasswordBreached", err)
		}
	})
}

// oversizedRange renders a well-formed range response comfortably larger than
// the adapter's 4 MiB read cap, holding no line that matches suffixPassword.
func oversizedRange() string {
	const line = suffixSomeoneElse + ":3\r\n"
	return strings.Repeat(line, 5<<20/len(line)+1)
}

// TestHIBPHonoursContextCancellation: the caller's deadline must bound the call,
// not only the client's own timeout.
func TestHIBPHonoursContextCancellation(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := screener.NewHIBP(client).Screen(ctx, pwPassword)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Screen = %v, want it to surface context.Canceled", err)
	}
}

func TestNewHIBPPanicsOnNilClient(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewHIBP(nil) did not panic; the timeout belongs to the injected client")
		}
	}()
	_ = screener.NewHIBP(nil)
}
