package port_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// Compile-time assertions: the fakes below satisfy each repository interface.
var (
	_ port.UserRepository               = (*fakeUserRepo)(nil)
	_ port.PasswordCredentialRepository = (*fakeCredRepo)(nil)
	_ port.SessionRepository            = (*fakeSessionRepo)(nil)
	_ port.VerificationTokenRepository  = (*fakeTokenRepo)(nil)
)

type fakeUserRepo struct{}

func (*fakeUserRepo) Create(context.Context, *domain.User) error { return nil }
func (*fakeUserRepo) Update(context.Context, *domain.User) error { return nil }
func (*fakeUserRepo) FindByID(context.Context, domain.UserID) (*domain.User, error) {
	return nil, port.ErrUserNotFound
}
func (*fakeUserRepo) FindByEmail(context.Context, domain.Email) (*domain.User, error) {
	return nil, port.ErrUserNotFound
}

type fakeCredRepo struct{}

func (*fakeCredRepo) Create(context.Context, *domain.PasswordCredential) error { return nil }
func (*fakeCredRepo) Update(context.Context, *domain.PasswordCredential) error { return nil }
func (*fakeCredRepo) FindByUserID(context.Context, domain.UserID) (*domain.PasswordCredential, error) {
	return nil, port.ErrCredentialNotFound
}

type fakeSessionRepo struct{}

func (*fakeSessionRepo) Create(context.Context, *domain.Session) error { return nil }
func (*fakeSessionRepo) Update(context.Context, *domain.Session) error { return nil }
func (*fakeSessionRepo) FindByTokenHash(context.Context, domain.TokenHash) (*domain.Session, error) {
	return nil, port.ErrSessionNotFound
}
func (*fakeSessionRepo) RevokeAllForUser(context.Context, domain.UserID, time.Time, string) error {
	return nil
}

type fakeTokenRepo struct{}

func (*fakeTokenRepo) Create(context.Context, *domain.VerificationToken) error { return nil }
func (*fakeTokenRepo) Update(context.Context, *domain.VerificationToken) error { return nil }
func (*fakeTokenRepo) FindByTokenHash(context.Context, domain.TokenHash) (*domain.VerificationToken, error) {
	return nil, port.ErrTokenNotFound
}

func TestRepositorySentinelsAreDistinctNonNilAndPrefixed(t *testing.T) {
	sentinels := map[string]error{
		"ErrUserNotFound":       port.ErrUserNotFound,
		"ErrEmailTaken":         port.ErrEmailTaken,
		"ErrCredentialNotFound": port.ErrCredentialNotFound,
		"ErrSessionNotFound":    port.ErrSessionNotFound,
		"ErrTokenNotFound":      port.ErrTokenNotFound,
	}

	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s is nil", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "port: ") {
			t.Errorf("%s message %q lacks `port: ` prefix", name, err.Error())
		}
	}

	// Distinctness: no sentinel matches another under errors.Is.
	for name, a := range sentinels {
		for otherName, b := range sentinels {
			if name == otherName {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("%s and %s are not distinct", name, otherName)
			}
		}
	}
}
