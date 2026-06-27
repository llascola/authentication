package port_test

import (
	"context"
	"testing"

	"authentication/internal/domain"
	"authentication/internal/port"
)

var _ port.Mailer = (*recordingMailer)(nil)

type sentMail struct {
	kind     string
	to       domain.Email
	rawToken string
}

type recordingMailer struct {
	sent []sentMail
}

func (m *recordingMailer) SendEmailVerification(_ context.Context, to domain.Email, rawToken string) error {
	m.sent = append(m.sent, sentMail{"verify", to, rawToken})
	return nil
}

func (m *recordingMailer) SendPasswordReset(_ context.Context, to domain.Email, rawToken string) error {
	m.sent = append(m.sent, sentMail{"reset", to, rawToken})
	return nil
}

func TestRecordingMailerCapturesSends(t *testing.T) {
	var m port.Mailer = &recordingMailer{}
	if err := m.SendEmailVerification(context.Background(), domain.Email{}, "tok-1"); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	if err := m.SendPasswordReset(context.Background(), domain.Email{}, "tok-2"); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	rec := m.(*recordingMailer)
	if len(rec.sent) != 2 {
		t.Fatalf("recorded %d sends, want 2", len(rec.sent))
	}
}
