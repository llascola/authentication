package mailer_test

import (
	"context"
	"strings"
	"testing"

	"authentication/internal/adapter/mailer"
	"authentication/internal/domain"
)

const (
	goodAddr   = "smtp.example.com:587"
	goodFrom   = "no-reply@example.com"
	verifyBase = "https://app.example.com/verify"
	resetBase  = "https://app.example.com/reset"
)

func mkEmail(t *testing.T, raw string) domain.Email {
	t.Helper()
	e, err := domain.NewEmail(raw)
	if err != nil {
		t.Fatalf("NewEmail(%q): %v", raw, err)
	}
	return e
}

// capture builds an SmtpMailer with its transport swapped for a fake that
// records the last message, so tests assert assembly without a network.
type capture struct {
	from, to string
	msg      string
	calls    int
}

func newCaptured(t *testing.T) (*mailer.SmtpMailer, *capture) {
	t.Helper()
	m, err := mailer.NewSmtpMailer(goodAddr, "user", "pass", goodFrom, verifyBase, resetBase)
	if err != nil {
		t.Fatalf("NewSmtpMailer: %v", err)
	}
	cap := &capture{}
	m.SetTransportForTest(func(_ context.Context, from, to string, msg []byte) error {
		cap.from, cap.to, cap.msg = from, to, string(msg)
		cap.calls++
		return nil
	})
	return m, cap
}

func TestNewSmtpMailerRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name                      string
		addr, from, verify, reset string
	}{
		{"addr without port", "smtp.example.com", goodFrom, verifyBase, resetBase},
		{"empty addr", "", goodFrom, verifyBase, resetBase},
		{"bad from", goodAddr, "not-an-email", verifyBase, resetBase},
		{"verify not https", goodAddr, goodFrom, "http://app.example.com/verify", resetBase},
		{"reset not https", goodAddr, goodFrom, verifyBase, "http://app.example.com/reset"},
		{"verify no host", goodAddr, goodFrom, "https:///verify", resetBase},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mailer.NewSmtpMailer(tc.addr, "u", "p", tc.from, tc.verify, tc.reset); err == nil {
				t.Errorf("NewSmtpMailer(%+v) = nil error, want error", tc)
			}
		})
	}
}

func TestSendEmailVerificationAssemblesLink(t *testing.T) {
	m, cap := newCaptured(t)
	const token = "ab+cd/ef" // exercises query escaping of + and /

	if err := m.SendEmailVerification(context.Background(), mkEmail(t, "user@example.com"), token); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	if cap.calls != 1 {
		t.Fatalf("transport called %d times, want 1", cap.calls)
	}
	if cap.from != goodFrom {
		t.Errorf("from = %q, want %q", cap.from, goodFrom)
	}
	if cap.to != "user@example.com" {
		t.Errorf("to = %q, want user@example.com", cap.to)
	}
	// Link uses the verify base and carries the token, query-escaped.
	wantLink := verifyBase + "?token=ab%2Bcd%2Fef"
	if !strings.Contains(cap.msg, wantLink) {
		t.Errorf("body missing verify link %q; got:\n%s", wantLink, cap.msg)
	}
	if strings.Contains(cap.msg, resetBase) {
		t.Errorf("verification mail must not use the reset base")
	}
	assertMessageShape(t, cap.msg, "user@example.com", "Subject: Verify your email")
}

// A From carrying a display name is valid in the header but must never reach
// MAIL FROM, which takes a bare addr-spec: servers reject the mailbox form.
func TestDisplayNameFromSplitsHeaderAndEnvelope(t *testing.T) {
	const display = "Auth <no-reply@example.com>"
	m, err := mailer.NewSmtpMailer(goodAddr, "user", "pass", display, verifyBase, resetBase)
	if err != nil {
		t.Fatalf("NewSmtpMailer: %v", err)
	}
	cap := &capture{}
	m.SetTransportForTest(func(_ context.Context, from, to string, msg []byte) error {
		cap.from, cap.to, cap.msg = from, to, string(msg)
		cap.calls++
		return nil
	})

	if err := m.SendEmailVerification(context.Background(), mkEmail(t, "user@example.com"), "tok"); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	if cap.from != goodFrom {
		t.Errorf("envelope from = %q, want bare address %q", cap.from, goodFrom)
	}
	if !strings.Contains(cap.msg, "From: "+display+"\r\n") {
		t.Errorf("From header = missing %q; got:\n%s", display, cap.msg)
	}
}

func TestSendPasswordResetAssemblesLink(t *testing.T) {
	m, cap := newCaptured(t)
	const token = "raw-reset-token"

	if err := m.SendPasswordReset(context.Background(), mkEmail(t, "user@example.com"), token); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	wantLink := resetBase + "?token=raw-reset-token"
	if !strings.Contains(cap.msg, wantLink) {
		t.Errorf("body missing reset link %q; got:\n%s", wantLink, cap.msg)
	}
	if strings.Contains(cap.msg, verifyBase) {
		t.Errorf("reset mail must not use the verify base")
	}
	assertMessageShape(t, cap.msg, "user@example.com", "Subject: Reset your password")
}

// assertMessageShape checks the rendered message is a CRLF-terminated RFC-5322
// message with the expected recipient and subject header.
func assertMessageShape(t *testing.T, msg, to, subjectHeader string) {
	t.Helper()
	if !strings.Contains(msg, "To: "+to+"\r\n") {
		t.Errorf("missing To header for %q", to)
	}
	if !strings.Contains(msg, subjectHeader+"\r\n") {
		t.Errorf("missing header %q", subjectHeader)
	}
	if !strings.Contains(msg, "\r\n\r\n") {
		t.Error("message has no header/body separator")
	}
	if strings.Contains(msg, "\n\n") && !strings.Contains(msg, "\r\n\r\n") {
		t.Error("message uses bare LF, want CRLF")
	}
}
