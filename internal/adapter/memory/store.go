// Package memory is a map-backed, mutex-guarded implementation of the four
// repository ports. It is the persistence behind the whole password slice and
// is safe for concurrent use.
//
// Two invariants make it a faithful stand-in for a real database:
//
//   - Serialized read-modify-write (ADR 0008): every method takes one mutex for
//     its whole duration.
//   - Stored copies, never caller pointers: aggregates are deep-copied via the
//     domain Reconstitute* constructors on the way in and out, so a caller can
//     never mutate stored state through a retained pointer, and two readers
//     never share a mutable aggregate.
//
// A single global mutex is intentional for the slice; per-key locking is a
// later optimization.
package memory

import (
	"context"
	"encoding/hex"
	"sync"
	"time"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// Store holds the shared maps and the single mutex. Obtain the typed
// repositories through its accessor methods; they all serialize on this mutex.
type Store struct {
	mu       sync.Mutex
	users    map[domain.UserID]*domain.User
	byEmail  map[string]domain.UserID // unique index: email -> user id
	creds    map[domain.UserID]*domain.PasswordCredential
	sessions map[string]*domain.Session           // key: hex(TokenHash)
	tokens   map[string]*domain.VerificationToken // key: hex(TokenHash)
}

// NewStore returns an empty store ready for use.
func NewStore() *Store {
	return &Store{
		users:    make(map[domain.UserID]*domain.User),
		byEmail:  make(map[string]domain.UserID),
		creds:    make(map[domain.UserID]*domain.PasswordCredential),
		sessions: make(map[string]*domain.Session),
		tokens:   make(map[string]*domain.VerificationToken),
	}
}

// Repository accessors. Each returns a typed view over the same *Store; the
// split exists only because one Go type cannot host four methods named Create.
func (s *Store) Users() *UserRepo               { return &UserRepo{s} }
func (s *Store) Credentials() *CredentialRepo   { return &CredentialRepo{s} }
func (s *Store) Sessions() *SessionRepo         { return &SessionRepo{s} }
func (s *Store) Tokens() *VerificationTokenRepo { return &VerificationTokenRepo{s} }

func tokenKey(h domain.TokenHash) string { return hex.EncodeToString(h.Bytes()) }

// ---------------------------------------------------------------------------
// UserRepo
// ---------------------------------------------------------------------------

type UserRepo struct{ s *Store }

var _ port.UserRepository = (*UserRepo)(nil)

func (r *UserRepo) Create(_ context.Context, u *domain.User) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	email := u.Email().String()
	if _, taken := r.s.byEmail[email]; taken {
		return port.ErrEmailTaken
	}
	r.s.users[u.ID()] = copyUser(u)
	r.s.byEmail[email] = u.ID()
	return nil
}

func (r *UserRepo) Update(_ context.Context, u *domain.User) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.users[u.ID()]
	if !ok {
		return port.ErrUserNotFound
	}
	// Keep the email index consistent if the address changed.
	if old := existing.Email().String(); old != u.Email().String() {
		if owner, taken := r.s.byEmail[u.Email().String()]; taken && owner != u.ID() {
			return port.ErrEmailTaken
		}
		delete(r.s.byEmail, old)
		r.s.byEmail[u.Email().String()] = u.ID()
	}
	r.s.users[u.ID()] = copyUser(u)
	return nil
}

func (r *UserRepo) FindByID(_ context.Context, id domain.UserID) (*domain.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	u, ok := r.s.users[id]
	if !ok {
		return nil, port.ErrUserNotFound
	}
	return copyUser(u), nil
}

func (r *UserRepo) FindByEmail(_ context.Context, email domain.Email) (*domain.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	id, ok := r.s.byEmail[email.String()]
	if !ok {
		return nil, port.ErrUserNotFound
	}
	return copyUser(r.s.users[id]), nil
}

// ---------------------------------------------------------------------------
// CredentialRepo
// ---------------------------------------------------------------------------

type CredentialRepo struct{ s *Store }

var _ port.PasswordCredentialRepository = (*CredentialRepo)(nil)

func (r *CredentialRepo) Create(_ context.Context, c *domain.PasswordCredential) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, exists := r.s.creds[c.UserID()]; exists {
		return port.ErrCredentialExists // one password credential per user
	}
	r.s.creds[c.UserID()] = copyCredential(c)
	return nil
}

func (r *CredentialRepo) Update(_ context.Context, c *domain.PasswordCredential) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.creds[c.UserID()]; !ok {
		return port.ErrCredentialNotFound
	}
	r.s.creds[c.UserID()] = copyCredential(c)
	return nil
}

func (r *CredentialRepo) FindByUserID(_ context.Context, id domain.UserID) (*domain.PasswordCredential, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c, ok := r.s.creds[id]
	if !ok {
		return nil, port.ErrCredentialNotFound
	}
	return copyCredential(c), nil
}

// ---------------------------------------------------------------------------
// SessionRepo
// ---------------------------------------------------------------------------

type SessionRepo struct{ s *Store }

var _ port.SessionRepository = (*SessionRepo)(nil)

func (r *SessionRepo) Create(_ context.Context, s *domain.Session) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.sessions[tokenKey(s.TokenHash())] = copySession(s)
	return nil
}

func (r *SessionRepo) Update(_ context.Context, s *domain.Session) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := tokenKey(s.TokenHash())
	if _, ok := r.s.sessions[key]; !ok {
		return port.ErrSessionNotFound
	}
	r.s.sessions[key] = copySession(s)
	return nil
}

func (r *SessionRepo) FindByTokenHash(_ context.Context, h domain.TokenHash) (*domain.Session, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.sessions[tokenKey(h)]
	if !ok {
		return nil, port.ErrSessionNotFound
	}
	return copySession(s), nil
}

// RevokeAllForUser revokes every currently-active session for the user in one
// serialized pass. Already revoked/expired sessions are left untouched.
func (r *SessionRepo) RevokeAllForUser(_ context.Context, id domain.UserID, now time.Time, reason string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for key, s := range r.s.sessions {
		if s.UserID() != id || s.Status() != domain.SessionActive {
			continue
		}
		// Operate on a copy, then store it, to preserve the no-shared-pointer rule.
		cp := copySession(s)
		if err := cp.Revoke(now, reason); err != nil {
			continue // not active anymore; skip
		}
		r.s.sessions[key] = cp
	}
	return nil
}

// ---------------------------------------------------------------------------
// VerificationTokenRepo
// ---------------------------------------------------------------------------

type VerificationTokenRepo struct{ s *Store }

var _ port.VerificationTokenRepository = (*VerificationTokenRepo)(nil)

// Create stores the token after invalidating any prior unconsumed token for the
// same (userID, purpose) — the in-process equivalent of ADR 0009's partial
// unique index: only the most recently minted token for a purpose stays valid.
func (r *VerificationTokenRepo) Create(_ context.Context, t *domain.VerificationToken) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for key, existing := range r.s.tokens {
		if existing.UserID() != t.UserID() || existing.Purpose() != t.Purpose() {
			continue
		}
		if existing.IsConsumed() {
			continue
		}
		// Invalidate the prior token by consuming it at the new token's birth.
		cp := copyToken(existing)
		if err := cp.Consume(t.CreatedAt()); err != nil {
			continue
		}
		r.s.tokens[key] = cp
	}
	r.s.tokens[tokenKey(t.TokenHash())] = copyToken(t)
	return nil
}

func (r *VerificationTokenRepo) Update(_ context.Context, t *domain.VerificationToken) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := tokenKey(t.TokenHash())
	if _, ok := r.s.tokens[key]; !ok {
		return port.ErrTokenNotFound
	}
	r.s.tokens[key] = copyToken(t)
	return nil
}

func (r *VerificationTokenRepo) FindByTokenHash(_ context.Context, h domain.TokenHash) (*domain.VerificationToken, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	t, ok := r.s.tokens[tokenKey(h)]
	if !ok {
		return nil, port.ErrTokenNotFound
	}
	return copyToken(t), nil
}

// ---------------------------------------------------------------------------
// Deep-copy helpers — reconstitute a detached clone from public getters so no
// internal aggregate pointer is ever shared across the store boundary.
// ---------------------------------------------------------------------------

func ptrIf[T any](v T, ok bool) *T {
	if !ok {
		return nil
	}
	return &v
}

func copyUser(u *domain.User) *domain.User {
	phone, hasPhone := u.Phone()
	lockedUntil, locked := u.LockedUntil()
	return domain.ReconstituteUser(
		u.ID(),
		u.Email(),
		u.EmailVerified(),
		ptrIf(phone, hasPhone),
		u.PhoneVerified(),
		u.Status(),
		u.Roles(),
		u.MFAEnabled(),
		u.FailedAttempts(),
		ptrIf(lockedUntil, locked),
		u.CreatedAt(),
		u.UpdatedAt(),
	)
}

func copyCredential(c *domain.PasswordCredential) *domain.PasswordCredential {
	return domain.ReconstitutePasswordCredential(
		c.ID(),
		c.UserID(),
		c.Hash(),
		c.CreatedAt(),
		c.UpdatedAt(),
	)
}

func copySession(s *domain.Session) *domain.Session {
	revokedAt, revoked := s.RevokedAt()
	return domain.ReconstituteSession(
		s.ID(),
		s.UserID(),
		s.TokenHash(),
		s.Status(),
		s.AuthLevel(),
		s.AMR(),
		s.Device(),
		s.IssuedAt(),
		s.AbsoluteExpiry(),
		s.IdleExpiry(),
		s.IdleTTL(),
		s.LastSeenAt(),
		ptrIf(revokedAt, revoked),
		s.Reason(),
	)
}

func copyToken(t *domain.VerificationToken) *domain.VerificationToken {
	consumedAt, consumed := t.ConsumedAt()
	return domain.ReconstituteVerificationToken(
		t.ID(),
		t.UserID(),
		t.Purpose(),
		t.TokenHash(),
		t.CreatedAt(),
		t.ExpiresAt(),
		ptrIf(consumedAt, consumed),
	)
}
