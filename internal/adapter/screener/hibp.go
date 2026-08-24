package screener

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"authentication/internal/port"
)

// hibpRangeURL is the k-anonymity range endpoint. It needs no API key (the
// breached-*account* API does; that one is not used here).
const hibpRangeURL = "https://api.pwnedpasswords.com/range/"

// maxRangeBytes caps the response read. A prefix bucket is ~800 suffixes of ~40
// bytes, and padding can push it to a few thousand; 4 MiB is orders of magnitude
// above that and exists only so a hostile or broken endpoint cannot stream
// unbounded data into this process.
const maxRangeBytes = 4 << 20

var _ port.PasswordScreener = (*HIBP)(nil)

// HIBP screens candidate passwords against Have I Been Pwned's Pwned Passwords
// corpus using the k-anonymity range API (ADR 0019).
//
// The password never leaves the process. What is sent is the first 5 hex
// characters of its SHA-1; the endpoint answers with every suffix sharing that
// prefix — hundreds of thousands of candidates — and the remaining 35 characters
// are matched locally. The prefix therefore identifies a bucket, never a
// password.
//
// SHA-1 here is a lookup index into a public dataset, chosen by HIBP, not a
// security primitive. It is unrelated to how passwords are stored
// (ADR 0007 owns that) and its collision weakness is irrelevant to a
// membership test.
type HIBP struct {
	client *http.Client
}

// NewHIBP builds a screener over the given client. The client is injected rather
// than constructed here so its timeout is set at the wiring site and visible
// there, and so tests can supply a stub transport instead of reaching the
// network.
func NewHIBP(client *http.Client) *HIBP {
	if client == nil {
		panic("screener: NewHIBP requires a non-nil *http.Client")
	}
	return &HIBP{client: client}
}

// Screen reports ErrPasswordBreached when the password appears in the corpus,
// nil when it does not, and a wrapped error when the check could not be
// completed at all — a transport failure, a non-200, or a truncated body. Per
// the port contract the caller decides what an incomplete check means; see
// FailOpen for the policy this project wires in.
//
// The context is honoured, so a caller's deadline bounds the call regardless of
// the client's own timeout.
func (h *HIBP) Screen(ctx context.Context, plaintext string) error {
	prefix, suffix := hibpDigest(plaintext)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hibpRangeURL+prefix, nil)
	if err != nil {
		return fmt.Errorf("screener: build hibp request: %w", err)
	}
	// Padding makes every response a uniform-ish size, so an observer of the
	// encrypted stream cannot infer which prefix was asked for from its length.
	req.Header.Set("Add-Padding", "true")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("screener: hibp request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRangeBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("screener: hibp returned status %d", resp.StatusCode)
	}
	return scanRange(resp.Body, suffix)
}

// hibpDigest splits the uppercase hex SHA-1 of plaintext into the 5-character
// prefix that is sent and the 35-character suffix that is matched locally.
//
// It is the one place the split happens, so the "only 5 characters leave" rule
// has a single point of failure rather than one per call site.
func hibpDigest(plaintext string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(plaintext))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	return full[:5], full[5:]
}

// scanRange looks for suffix among the "SUFFIX:COUNT" lines of a range response.
func scanRange(body io.Reader, suffix string) error {
	sc := bufio.NewScanner(io.LimitReader(body, maxRangeBytes))
	for sc.Scan() {
		line, count, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue // not a suffix line; ignore rather than fail the whole check
		}
		if !strings.EqualFold(line, suffix) {
			continue
		}
		// Padding entries are real-looking suffixes with a count of 0 (that is
		// how the caller is meant to tell them apart). Treating one as a hit
		// would reject a password on the strength of deliberate noise.
		if strings.TrimSpace(count) == "0" {
			continue
		}
		return port.ErrPasswordBreached
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("screener: read hibp response: %w", err)
	}
	return nil
}
