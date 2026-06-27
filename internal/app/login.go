package app

import (
	"context"
	"sync"
	"time"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// LoginService authenticates email + password and issues an AAL1 session.
type LoginService struct {
	users         port.UserRepository
	creds         port.PasswordCredentialRepository
	sessions      port.SessionRepository
	authenticator port.Authenticator
	tokenGen      port.TokenGenerator
	hasher        port.PasswordHasher
	normalizer    port.Normalizer
	clock         port.Clock
	idleTTL       time.Duration
	absTTL        time.Duration

	dummyOnce sync.Once
	dummyCred *domain.PasswordCredential
}

// NewLoginService wires the dependencies Login needs. idleTTL/absTTL come from
// config (T21); the domain enforces idleTTL <= absTTL when a session is built.
func NewLoginService(
	users port.UserRepository,
	creds port.PasswordCredentialRepository,
	sessions port.SessionRepository,
	authenticator port.Authenticator,
	tokenGen port.TokenGenerator,
	hasher port.PasswordHasher,
	normalizer port.Normalizer,
	clock port.Clock,
	idleTTL, absTTL time.Duration,
) *LoginService {
	return &LoginService{
		users: users, creds: creds, sessions: sessions,
		authenticator: authenticator, tokenGen: tokenGen, hasher: hasher,
		normalizer: normalizer, clock: clock, idleTTL: idleTTL, absTTL: absTTL,
	}
}

// Login verifies credentials and, on success, returns a raw session token for
// the caller to set as a cookie. Every failure mode — unknown email, missing
// credential, wrong password, locked, inactive — returns ErrAuthFailed, so none
// is distinguishable.
//
// Timing: when the account or credential is missing, the password is still
// compared against a dummy hash of the configured cost, so response time does
// not reveal whether the email is registered. A wrong password on a real
// account records a failed-login attempt (which trips the domain lockout after
// the threshold); the lock is never disclosed.
func (s *LoginService) Login(ctx context.Context, rawEmail, plaintext string, device domain.DeviceInfo) (string, error) {
	now := s.clock.Now()
	norm := s.normalizer.Normalize(plaintext)

	var (
		user     *domain.User
		cred     *domain.PasswordCredential
		realCred bool
	)
	if email, err := domain.NewEmail(rawEmail); err == nil {
		if u, err := s.users.FindByEmail(ctx, email); err == nil {
			user = u
			if c, err := s.creds.FindByUserID(ctx, u.ID()); err == nil {
				cred = c
				realCred = true
			}
		}
	}
	if cred == nil {
		cred = s.dummy(ctx) // equalize timing for the missing-account path
	}

	// cred can still be nil only if the dummy hash could not be built (an infra
	// fault); treat that as a failure rather than verifying against nil.
	verifyErr := ErrAuthFailed
	if cred != nil {
		verifyErr = s.authenticator.Verify(ctx, cred, []byte(norm))
	}

	// Record a failed attempt for a real account with a wrong password, even if
	// already locked (the domain extends the lock — desired against an attacker).
	if realCred && verifyErr != nil {
		user.RecordFailedLogin(now)
		if err := s.users.Update(ctx, user); err != nil {
			return "", err
		}
	}

	loginable := user != nil && user.Status() == domain.StatusActive && !user.IsLocked(now)
	if !realCred || !loginable || verifyErr != nil {
		return "", ErrAuthFailed
	}

	user.RecordSuccessfulLogin(now)
	if err := s.users.Update(ctx, user); err != nil {
		return "", err
	}

	gt, err := s.tokenGen.Generate(ctx)
	if err != nil {
		return "", err
	}
	sess, err := domain.NewSession(now, user.ID(), gt.Hash, domain.AAL1,
		[]domain.AuthMethod{domain.AuthMethodPassword}, device, s.idleTTL, s.absTTL)
	if err != nil {
		return "", err
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return "", err
	}
	return gt.Raw, nil
}

// dummy lazily builds a throwaway credential with a real bcrypt hash at the
// configured cost. Verifying against it makes the no-such-account path spend the
// same time as a real password check. It is never stored.
func (s *LoginService) dummy(ctx context.Context) *domain.PasswordCredential {
	s.dummyOnce.Do(func() {
		hashBytes, err := s.hasher.Hash(ctx, "dummy-timing-equalizer")
		if err != nil {
			return
		}
		ph, err := domain.NewPasswordHash(hashBytes)
		if err != nil {
			return
		}
		s.dummyCred, _ = domain.NewPasswordCredential(s.clock.Now(), domain.NewUserID(), ph)
	})
	return s.dummyCred
}
