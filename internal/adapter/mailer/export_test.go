package mailer

import "context"

// SetTransportForTest swaps the SMTP transport with a capturing fake so tests
// can assert message assembly without opening a network connection. Test-only.
func (m *SmtpMailer) SetTransportForTest(f func(ctx context.Context, from, to string, msg []byte) error) {
	m.send = f
}
