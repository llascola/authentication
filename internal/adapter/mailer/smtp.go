package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"authentication/internal/domain"
	"authentication/internal/port"
)

var _ port.Mailer = (*SmtpMailer)(nil)

// SmtpMailer is the production port.Mailer. It assembles the verification/reset
// link from a configured base URL plus the raw token, then delivers it over
// authenticated SMTP with STARTTLS. Unlike the dev-only LogMailer it logs
// neither the token nor the assembled link, honouring the port.Mailer contract.
//
// The application layer still passes only the raw token to port.Mailer; wrapping
// that token in a frontend URL is a delivery concern and lives here, so
// internal/app gains no knowledge of frontend routes (ADR 0016).
type SmtpMailer struct {
	addr      string // host:port of the SMTP server
	host      string // host alone, for TLS ServerName + PLAIN auth realm
	auth      smtp.Auth
	from      string   // header + envelope From
	verifyURL *url.URL // base for email-verification links
	resetURL  *url.URL // base for password-reset links

	// send is the transport. Real construction wires it to deliverSTARTTLS;
	// tests swap it (see export_test.go) to capture messages without a network.
	send sendFn
}

// sendFn delivers an already-rendered RFC-5322 message. from/to are envelope
// addresses; msg is the full message including headers.
type sendFn func(ctx context.Context, from, to string, msg []byte) error

// NewSmtpMailer validates its configuration up front (New* discipline): a
// misconfigured mailer fails here, at wiring time, not at first send. addr is
// host:port; verifyBase/resetBase are the https frontend URLs the token is
// appended to as ?token=... A non-https base is rejected — the link carries a
// secret and must never travel in cleartext.
func NewSmtpMailer(addr, username, password, from, verifyBase, resetBase string) (*SmtpMailer, error) {
	host, port, ok := strings.Cut(addr, ":")
	if !ok || host == "" || port == "" {
		return nil, fmt.Errorf("mailer: addr %q must be host:port", addr)
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return nil, fmt.Errorf("mailer: from address %q: %w", from, err)
	}
	verifyURL, err := parseHTTPSBase(verifyBase)
	if err != nil {
		return nil, fmt.Errorf("mailer: verify base: %w", err)
	}
	resetURL, err := parseHTTPSBase(resetBase)
	if err != nil {
		return nil, fmt.Errorf("mailer: reset base: %w", err)
	}

	m := &SmtpMailer{
		addr:      addr,
		host:      host,
		auth:      smtp.PlainAuth("", username, password, host),
		from:      from,
		verifyURL: verifyURL,
		resetURL:  resetURL,
	}
	m.send = m.deliverSTARTTLS
	return m, nil
}

// SendEmailVerification mails a verification link for to. The raw token appears
// only in the link inside the body; it is never logged.
func (m *SmtpMailer) SendEmailVerification(ctx context.Context, to domain.Email, rawToken string) error {
	link := withToken(m.verifyURL, rawToken)
	body := "Confirm your email address by opening this link:\n\n" + link +
		"\n\nThe link expires shortly. If you did not create an account, ignore this message."
	return m.deliver(ctx, to.String(), "Verify your email", body)
}

// SendPasswordReset mails a reset link for to. As above, the token lives only in
// the link and is never logged.
func (m *SmtpMailer) SendPasswordReset(ctx context.Context, to domain.Email, rawToken string) error {
	link := withToken(m.resetURL, rawToken)
	body := "Reset your password by opening this link:\n\n" + link +
		"\n\nThe link expires shortly. If you did not request a reset, ignore this message."
	return m.deliver(ctx, to.String(), "Reset your password", body)
}

func (m *SmtpMailer) deliver(ctx context.Context, to, subject, body string) error {
	return m.send(ctx, m.from, to, buildMessage(m.from, to, subject, body))
}

// deliverSTARTTLS is the real transport: dial (honouring ctx), upgrade to TLS
// via STARTTLS, authenticate, and send. It refuses to proceed if the server
// does not advertise STARTTLS, so credentials and the token never cross a
// cleartext link.
func (m *SmtpMailer) deliverSTARTTLS(ctx context.Context, from, to string, msg []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", m.addr, err)
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mailer: smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); !ok {
		return fmt.Errorf("mailer: server %s does not support STARTTLS", m.addr)
	}
	if err := c.StartTLS(&tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("mailer: starttls: %w", err)
	}
	if ok, _ := c.Extension("AUTH"); ok {
		if err := c.Auth(m.auth); err != nil {
			return fmt.Errorf("mailer: auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("mailer: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("mailer: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mailer: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("mailer: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: close body: %w", err)
	}
	return c.Quit()
}

// withToken appends ?token=<raw> to a copy of base. The base is copied so a
// concurrent send can never observe a mutated shared URL.
func withToken(base *url.URL, raw string) string {
	u := *base
	q := u.Query()
	q.Set("token", raw)
	u.RawQuery = q.Encode()
	return u.String()
}

// buildMessage renders a minimal RFC-5322 text/plain message with CRLF line
// endings, as SMTP requires.
func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return []byte(b.String())
}

func parseHTTPSBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("must be https, got %q", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host in %q", raw)
	}
	return u, nil
}
