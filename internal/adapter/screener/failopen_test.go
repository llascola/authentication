package screener_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"authentication/internal/adapter/screener"
	"authentication/internal/port"
)

// fakeScreener returns whatever it is told to.
type fakeScreener struct{ err error }

func (f fakeScreener) Screen(context.Context, string) error { return f.err }

func TestFailOpenPassesVerdictsThrough(t *testing.T) {
	cases := map[string]error{
		"clean password": nil,
		"breached":       port.ErrPasswordBreached,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			f := screener.FailOpen{Inner: fakeScreener{err: want}}
			if got := f.Screen(context.Background(), "pw"); !errors.Is(got, want) {
				t.Errorf("Screen = %v, want %v", got, want)
			}
		})
	}
}

// TestFailOpenAllowsWhenTheCheckCouldNotRun is the decision itself: an
// unreachable corpus accepts the password rather than failing the request.
func TestFailOpenAllowsWhenTheCheckCouldNotRun(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	f := screener.FailOpen{Inner: fakeScreener{err: errors.New("dial tcp: connection refused")}, Log: log}

	if err := f.Screen(context.Background(), "correct horse battery staple"); err != nil {
		t.Errorf("Screen = %v, want nil (fail open)", err)
	}
	if !strings.Contains(buf.String(), "WARN") {
		t.Error("a skipped screen was not logged at WARN; a silent downgrade is the thing to avoid")
	}
}

// TestFailOpenNeverLogsThePassword: the wrapper sees plaintext, so this is worth
// pinning rather than assuming.
func TestFailOpenNeverLogsThePassword(t *testing.T) {
	const secret = "hunter2-the-actual-password"
	var buf bytes.Buffer
	f := screener.FailOpen{
		Inner: fakeScreener{err: errors.New("boom")},
		Log:   slog.New(slog.NewTextHandler(&buf, nil)),
	}

	if err := f.Screen(context.Background(), secret); err != nil {
		t.Fatalf("Screen: %v", err)
	}
	if strings.Contains(buf.String(), secret) {
		t.Error("the password appeared in the log")
	}
}

func TestFailOpenToleratesNilLogger(t *testing.T) {
	f := screener.FailOpen{Inner: fakeScreener{err: errors.New("boom")}}
	if err := f.Screen(context.Background(), "pw"); err != nil {
		t.Errorf("Screen = %v, want nil", err)
	}
}
