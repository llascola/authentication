//go:build integration

// This test exercises the real STARTTLS transport of SmtpMailer against a live
// Mailpit instance. It is gated behind the `integration` build tag so the normal
// `make check` gate never runs it, and it skips unless the Mailpit endpoints are
// provided. Run it with `make test-integration`, which provisions Mailpit (with
// a self-signed STARTTLS cert) in Docker and sets the env vars below.
package mailer_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"authentication/internal/adapter/mailer"
	"authentication/internal/domain"
)

func TestSmtpMailerIntegrationMailpit(t *testing.T) {
	smtpAddr := os.Getenv("MAILPIT_SMTP_ADDR")
	apiURL := strings.TrimRight(os.Getenv("MAILPIT_API_URL"), "/")
	if smtpAddr == "" || apiURL == "" {
		t.Skip("set MAILPIT_SMTP_ADDR and MAILPIT_API_URL to run (see `make test-integration`)")
	}

	clearMailpit(t, apiURL)

	// Trust Mailpit's self-signed STARTTLS cert. Test-only; production pins the
	// ServerName with a TLS 1.2 floor and no InsecureSkipVerify.
	m, err := mailer.NewSmtpMailer(
		smtpAddr, "user", "pass", "no-reply@example.com",
		"https://app.example.com/verify", "https://app.example.com/reset",
		mailer.WithTLSConfig(&tls.Config{ServerName: "localhost", InsecureSkipVerify: true}), //nolint:gosec // self-signed test cert
	)
	if err != nil {
		t.Fatalf("NewSmtpMailer: %v", err)
	}

	email, err := domain.NewEmail("user@example.com")
	if err != nil {
		t.Fatalf("NewEmail: %v", err)
	}
	const token = "integration-raw-token"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.SendPasswordReset(ctx, email, token); err != nil {
		t.Fatalf("SendPasswordReset over real SMTP: %v", err)
	}

	raw := fetchLatestRaw(t, apiURL)
	wantLink := "https://app.example.com/reset?token=integration-raw-token"
	if !strings.Contains(raw, wantLink) {
		t.Errorf("delivered message missing reset link %q; raw source:\n%s", wantLink, raw)
	}
	if !strings.Contains(raw, "To: user@example.com") {
		t.Errorf("delivered message missing recipient; raw source:\n%s", raw)
	}
	if !strings.Contains(raw, "Subject: Reset your password") {
		t.Errorf("delivered message missing subject; raw source:\n%s", raw)
	}
}

func clearMailpit(t *testing.T, apiURL string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, apiURL+"/api/v1/messages", nil)
	if err != nil {
		t.Fatalf("build delete request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("clear mailpit: %v", err)
	}
	_ = resp.Body.Close()
}

// fetchLatestRaw returns the raw source of the most recent message, retrying
// briefly since delivery and indexing are asynchronous.
func fetchLatestRaw(t *testing.T, apiURL string) string {
	t.Helper()
	var id string
	for i := 0; i < 20; i++ {
		id = latestMessageID(t, apiURL)
		if id != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no message arrived in Mailpit")
	}

	resp, err := http.Get(apiURL + "/api/v1/message/" + id + "/raw")
	if err != nil {
		t.Fatalf("fetch raw message: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read raw message: %v", err)
	}
	return string(body)
}

func latestMessageID(t *testing.T, apiURL string) string {
	t.Helper()
	resp, err := http.Get(apiURL + "/api/v1/messages")
	if err != nil {
		t.Fatalf("list messages: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	if len(out.Messages) == 0 {
		return ""
	}
	return out.Messages[0].ID
}
