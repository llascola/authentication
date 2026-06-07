// Package domain holds the core business entities and rules of the auth
// server. It is dependency-free (stdlib + uuid only) and knows nothing about
// transport, storage, or specific authentication mechanisms.
//
// The User aggregate models an *identity*, deliberately decoupled from any
// single authentication method. Credentials (password, OAuth links, OTP, ...)
// are separate entities that reference a User by ID, so the same identity can
// own many auth methods at once.
package domain

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Domain errors. Callers compare with errors.Is; wrap with %w to add context.
var (
	ErrEmailRequired        = errors.New("domain: email is required")
	ErrInvalidEmail         = errors.New("domain: invalid email")
	ErrInvalidPhone         = errors.New("domain: invalid phone number")
	ErrInvalidUserID        = errors.New("domain: invalid user id")
	ErrInvalidRole          = errors.New("domain: invalid role")
	ErrInvalidStatus        = errors.New("domain: invalid status")
	ErrStatusTransition     = errors.New("domain: illegal status transition")
	ErrEmailAlreadyVerified = errors.New("domain: email already verified")
	ErrPhoneAlreadyVerified = errors.New("domain: phone already verified")
	ErrPhoneNotSet          = errors.New("domain: phone not set")
	ErrRoleNotAssigned      = errors.New("domain: role not assigned")
	ErrNoConfirmedFactor    = errors.New("domain: cannot enable mfa without a confirmed second factor")
)

// Lockout policy. Fixed window: maxFailedLogins consecutive failures lock the
// account for lockoutDuration, after which it auto-unlocks. A successful login
// resets the counter.
const (
	maxFailedLogins = 5
	lockoutDuration = 15 * time.Minute
)

// ---------------------------------------------------------------------------
// UserID
// ---------------------------------------------------------------------------

// UserID is the opaque, globally-unique identity key. It is the only required
// identifier of a User, allowing identities that have no email-backed login.
type UserID uuid.UUID

// NewUserID returns a fresh random (v4) identity key.
func NewUserID() UserID { return UserID(uuid.New()) }

// ParseUserID parses the canonical string form of a UserID.
func ParseUserID(s string) (UserID, error) {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return UserID{}, fmt.Errorf("%w: %q", ErrInvalidUserID, s)
	}
	return UserID(id), nil
}

func (id UserID) String() string { return uuid.UUID(id).String() }

// IsZero reports whether the id is the zero value (unset).
func (id UserID) IsZero() bool { return uuid.UUID(id) == uuid.Nil }

// ---------------------------------------------------------------------------
// Email (value object)
// ---------------------------------------------------------------------------

// Email is a validated, normalised email address. The zero value is invalid;
// construct only through NewEmail.
type Email struct {
	value string
}

// NewEmail validates and normalises (trim + lowercase) an email address.
func NewEmail(raw string) (Email, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return Email{}, ErrEmailRequired
	}
	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Address != v {
		return Email{}, fmt.Errorf("%w: %q", ErrInvalidEmail, raw)
	}
	return Email{value: v}, nil
}

func (e Email) String() string { return e.value }

// IsZero reports whether the email is unset.
func (e Email) IsZero() bool { return e.value == "" }

// ---------------------------------------------------------------------------
// Phone (value object, optional)
// ---------------------------------------------------------------------------

// e164 is the ITU-T E.164 format: '+' then 1-15 digits, first digit non-zero.
var e164 = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// Phone is a validated E.164 phone number, used for SMS/OTP flows.
type Phone struct {
	value string
}

// NewPhone validates a phone number in E.164 form (e.g. "+14155552671").
func NewPhone(raw string) (Phone, error) {
	v := strings.TrimSpace(raw)
	if !e164.MatchString(v) {
		return Phone{}, fmt.Errorf("%w: %q", ErrInvalidPhone, raw)
	}
	return Phone{value: v}, nil
}

func (p Phone) String() string { return p.value }
func (p Phone) IsZero() bool   { return p.value == "" }

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// Status is the account lifecycle state.
type Status uint8

const (
	// StatusPending: created but not yet verified/activated.
	StatusPending Status = iota
	// StatusActive: usable account.
	StatusActive
	// StatusSuspended: temporarily blocked, can be reactivated.
	StatusSuspended
	// StatusDeactivated: terminal, account closed.
	StatusDeactivated
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusActive:
		return "active"
	case StatusSuspended:
		return "suspended"
	case StatusDeactivated:
		return "deactivated"
	default:
		return "unknown"
	}
}

// Valid reports whether s is a defined status.
func (s Status) Valid() bool { return s <= StatusDeactivated }

// allowedTransitions maps each status to the states it may move to.
var allowedTransitions = map[Status][]Status{
	StatusPending:     {StatusActive, StatusDeactivated},
	StatusActive:      {StatusSuspended, StatusDeactivated},
	StatusSuspended:   {StatusActive, StatusDeactivated},
	StatusDeactivated: {}, // terminal
}

func (s Status) canTransitionTo(next Status) bool {
	return slices.Contains(allowedTransitions[s], next)
}

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

// Role is a coarse-grained authorization grant attached to a User.
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleUser, RoleAdmin:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// User (aggregate root)
// ---------------------------------------------------------------------------

// User is the identity aggregate. Fields are private so every mutation goes
// through a method that preserves invariants; the type makes illegal states
// hard to represent. Read access is via getters.
type User struct {
	id            UserID
	email         Email
	emailVerified bool
	phone         *Phone // optional
	phoneVerified bool
	status        Status
	roles         []Role

	mfaEnabled bool

	// Lockout state. failedAttempts counts consecutive failed logins; lockedUntil
	// is the auto-expiring lock deadline (nil = not locked). Distinct from
	// Status: a locked account is still StatusActive — lockout is temporary and
	// self-clearing, suspension is an explicit admin action.
	failedAttempts int
	lockedUntil    *time.Time

	createdAt time.Time
	updatedAt time.Time
}

// NewUser creates a fresh, pending identity from a validated email. If no roles
// are given it defaults to {RoleUser}. Use VerifyEmail / Activate to progress
// the lifecycle. now is the creation instant; callers pass UTC.
func NewUser(now time.Time, email Email, roles ...Role) (*User, error) {
	if email.IsZero() {
		return nil, ErrEmailRequired
	}
	rs, err := normaliseRoles(roles)
	if err != nil {
		return nil, err
	}

	return &User{
		id:        NewUserID(),
		email:     email,
		status:    StatusPending,
		roles:     rs,
		createdAt: now,
		updatedAt: now,
	}, nil
}

// Reconstitute rebuilds a User from persisted state without running creation
// invariants. It is intended solely for the repository/persistence layer when
// hydrating an already-valid aggregate from storage.
func Reconstitute(
	id UserID,
	email Email,
	emailVerified bool,
	phone *Phone,
	phoneVerified bool,
	status Status,
	roles []Role,
	mfaEnabled bool,
	failedAttempts int,
	lockedUntil *time.Time,
	createdAt, updatedAt time.Time,
) *User {
	return &User{
		id:             id,
		email:          email,
		emailVerified:  emailVerified,
		phone:          clonePtr(phone),
		phoneVerified:  phoneVerified,
		status:         status,
		roles:          slices.Clone(roles),
		mfaEnabled:     mfaEnabled,
		failedAttempts: failedAttempts,
		lockedUntil:    clonePtr(lockedUntil),
		createdAt:      createdAt,
		updatedAt:      updatedAt,
	}
}

// --- getters ---------------------------------------------------------------

func (u *User) ID() UserID           { return u.id }
func (u *User) Email() Email         { return u.email }
func (u *User) EmailVerified() bool  { return u.emailVerified }
func (u *User) PhoneVerified() bool  { return u.phoneVerified }
func (u *User) Status() Status       { return u.status }
func (u *User) MFAEnabled() bool     { return u.mfaEnabled }
func (u *User) FailedAttempts() int  { return u.failedAttempts }
func (u *User) CreatedAt() time.Time { return u.createdAt }
func (u *User) UpdatedAt() time.Time { return u.updatedAt }

// LockedUntil returns the lock deadline and whether a lock is set. A set lock
// may still be in the past (auto-expired); use IsLocked to test against a clock.
func (u *User) LockedUntil() (time.Time, bool) {
	if u.lockedUntil == nil {
		return time.Time{}, false
	}
	return *u.lockedUntil, true
}

// Phone returns the phone and whether one is set.
func (u *User) Phone() (Phone, bool) {
	if u.phone == nil {
		return Phone{}, false
	}
	return *u.phone, true
}

// Roles returns a copy of the user's roles; the internal slice is not exposed.
func (u *User) Roles() []Role { return slices.Clone(u.roles) }

// HasRole reports whether the user holds role r.
func (u *User) HasRole(r Role) bool { return slices.Contains(u.roles, r) }

// --- behaviour -------------------------------------------------------------

// ChangeEmail replaces the email and resets verification.
func (u *User) ChangeEmail(now time.Time, email Email) error {
	if email.IsZero() {
		return ErrEmailRequired
	}
	u.email = email
	u.emailVerified = false
	u.touch(now)
	return nil
}

// VerifyEmail marks the email as verified. A pending account is promoted to
// active as a side effect of first verification.
func (u *User) VerifyEmail(now time.Time) error {
	if u.emailVerified {
		return ErrEmailAlreadyVerified
	}
	u.emailVerified = true
	if u.status == StatusPending {
		u.status = StatusActive
	}
	u.touch(now)
	return nil
}

// SetPhone attaches or replaces the phone number and resets its verification.
func (u *User) SetPhone(now time.Time, phone Phone) error {
	if phone.IsZero() {
		return ErrInvalidPhone
	}
	p := phone
	u.phone = &p
	u.phoneVerified = false
	u.touch(now)
	return nil
}

// VerifyPhone marks the attached phone as verified.
func (u *User) VerifyPhone(now time.Time) error {
	if u.phone == nil {
		return ErrPhoneNotSet
	}
	if u.phoneVerified {
		return ErrPhoneAlreadyVerified
	}
	u.phoneVerified = true
	u.touch(now)
	return nil
}

// Activate transitions the account to active.
func (u *User) Activate(now time.Time) error { return u.transition(now, StatusActive) }

// Suspend transitions the account to suspended.
func (u *User) Suspend(now time.Time) error { return u.transition(now, StatusSuspended) }

// Deactivate transitions the account to its terminal deactivated state.
func (u *User) Deactivate(now time.Time) error { return u.transition(now, StatusDeactivated) }

// AddRole grants a role; assigning an already-held role is a no-op.
func (u *User) AddRole(now time.Time, r Role) error {
	if !r.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidRole, r)
	}
	if u.HasRole(r) {
		return nil
	}
	u.roles = append(u.roles, r)
	u.touch(now)
	return nil
}

// RemoveRole revokes a role.
func (u *User) RemoveRole(now time.Time, r Role) error {
	idx := slices.Index(u.roles, r)
	if idx < 0 {
		return fmt.Errorf("%w: %q", ErrRoleNotAssigned, r)
	}
	u.roles = slices.Delete(u.roles, idx, idx+1)
	u.touch(now)
	return nil
}

// --- lockout ---------------------------------------------------------------

// IsLocked reports whether the account is currently locked at now. The lock
// auto-expires: a deadline in the past reads as unlocked without any mutation.
func (u *User) IsLocked(now time.Time) bool {
	return u.lockedUntil != nil && now.Before(*u.lockedUntil)
}

// RecordFailedLogin increments the consecutive-failure counter and locks the
// account once it reaches the threshold, resetting the counter so the next
// window starts clean. Callers (the login use-case) treat a locked account the
// same as bad credentials, never disclosing the lock, to avoid user enumeration.
func (u *User) RecordFailedLogin(now time.Time) {
	u.failedAttempts++
	if u.failedAttempts >= maxFailedLogins {
		until := now.Add(lockoutDuration)
		u.lockedUntil = &until
		u.failedAttempts = 0
	}
	u.touch(now)
}

// RecordSuccessfulLogin clears the failure counter and any lock. Call on every
// successful authentication.
func (u *User) RecordSuccessfulLogin(now time.Time) {
	u.failedAttempts = 0
	u.lockedUntil = nil
	u.touch(now)
}

// --- mfa -------------------------------------------------------------------

// EnableMFA marks the account as requiring a second factor at login. The caller
// must prove the user already owns a confirmed second factor (e.g. a confirmed
// OTPCredential), passed as hasConfirmedFactor — credentials live in a separate
// aggregate, so the application gathers that fact and the domain enforces the
// rule. Enabling without a usable factor would lock the user out, so it is
// rejected. Idempotent: enabling an already-enabled account is a no-op.
//
// NOTE: enabling MFA does not retroactively raise existing AAL1 sessions; any
// "force step-up of live sessions" policy is a session/application concern.
func (u *User) EnableMFA(now time.Time, hasConfirmedFactor bool) error {
	if u.mfaEnabled {
		return nil
	}
	if !hasConfirmedFactor {
		return ErrNoConfirmedFactor
	}
	u.mfaEnabled = true
	u.touch(now)
	return nil
}

// DisableMFA turns off the second-factor requirement. Idempotent.
func (u *User) DisableMFA(now time.Time) {
	if !u.mfaEnabled {
		return
	}
	u.mfaEnabled = false
	u.touch(now)
}

// --- internals -------------------------------------------------------------

func (u *User) transition(now time.Time, next Status) error {
	if !next.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, next)
	}
	if u.status == next {
		return nil
	}
	if !u.status.canTransitionTo(next) {
		return fmt.Errorf("%w: %s -> %s", ErrStatusTransition, u.status, next)
	}
	u.status = next
	u.touch(now)
	return nil
}

func (u *User) touch(now time.Time) { u.updatedAt = now }

// clonePtr returns a pointer to a fresh copy of *p (nil stays nil). Reconstitute
// uses it so an aggregate never aliases a caller-owned pointer: hydrating must
// take full ownership of optional fields, mirroring the slices.Clone of roles.
func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

// normaliseRoles validates, de-duplicates, and defaults the role set.
func normaliseRoles(roles []Role) ([]Role, error) {
	if len(roles) == 0 {
		return []Role{RoleUser}, nil
	}
	out := make([]Role, 0, len(roles))
	for _, r := range roles {
		if !r.Valid() {
			return nil, fmt.Errorf("%w: %q", ErrInvalidRole, r)
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, nil
}
