package mailer_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"authentication/internal/adapter/mailer"
	"authentication/internal/domain"
)

func mustEmail(t *testing.T, raw string) domain.Email {
	t.Helper()
	e, err := domain.NewEmail(raw)
	if err != nil {
		t.Fatalf("NewEmail(%q): %v", raw, err)
	}
	return e
}

func TestLogMailerLogsRecipientAndToken(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	m := mailer.NewLogMailer(log)
	to := mustEmail(t, "user@example.com")

	if err := m.SendEmailVerification(context.Background(), to, "verify-token-abc"); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	if err := m.SendPasswordReset(context.Background(), to, "reset-token-xyz"); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"user@example.com", "verify-token-abc", "reset-token-xyz"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q\ngot: %s", want, out)
		}
	}
}
