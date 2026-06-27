package domain

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Session errors.
var (
	ErrInvalidSessionID  = errors.New("domain: invalid session id")
	ErrEmptyTokenHash    = errors.New("domain: token hash is empty")
	ErrInvalidAuthLevel  = errors.New("domain: invalid auth level")
	ErrInvalidTTL        = errors.New("domain: invalid session ttl")
	ErrInvalidIP         = errors.New("domain: invalid ip address")
	ErrSessionRevoked    = errors.New("domain: session revoked")
	ErrSessionExpired    = errors.New("domain: session expired")
	ErrSessionNotActive  = errors.New("domain: session not active")
	ErrSessionNotExpired = errors.New("domain: session not past a deadline")
	ErrAALNotRaised      = errors.New("domain: auth level cannot be lowered")
	ErrInvalidAuthMethod = errors.New("domain: invalid auth method")
	ErrNoAuthMethod      = errors.New("domain: session requires at least one auth method")
)

// ---------------------------------------------------------------------------
// SessionID
// ---------------------------------------------------------------------------

// SessionID is the opaque identity of a session record (not the secret token).
type SessionID uuid.UUID

func NewSessionID() SessionID { return SessionID(uuid.New()) }

func ParseSessionID(s string) (SessionID, error) {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return SessionID{}, fmt.Errorf("%w: %q", ErrInvalidSessionID, s)
	}
	return SessionID(id), nil
}

func (id SessionID) String() string { return uuid.UUID(id).String() }
func (id SessionID) IsZero() bool   { return uuid.UUID(id) == uuid.Nil }

// ---------------------------------------------------------------------------
// TokenHash (value object)
// ---------------------------------------------------------------------------

// TokenHash is the stored hash of a session's opaque bearer token. The raw
// token is shown to the client once and never persisted; the server keeps only
// this hash, so a store leak does not expose usable tokens.
type TokenHash struct {
	value []byte
}

func NewTokenHash(hash []byte) (TokenHash, error) {
	if len(hash) == 0 {
		return TokenHash{}, ErrEmptyTokenHash
	}
	return TokenHash{value: append([]byte(nil), hash...)}, nil
}

// Bytes returns a copy; the internal slice is not exposed.
func (h TokenHash) Bytes() []byte { return append([]byte(nil), h.value...) }
func (h TokenHash) IsZero() bool  { return len(h.value) == 0 }

// Equal reports whether h and other hold the same bytes, in constant time for
// equal-length inputs. Use for any comparison of secret-derived material
// (recovery-code hashes, session token hashes) to avoid leaking a match
// position or prefix via timing. A length mismatch returns false early; lengths
// are not secret for fixed-size hashes.
func (h TokenHash) Equal(other TokenHash) bool {
	return subtle.ConstantTimeCompare(h.value, other.value) == 1
}

// ---------------------------------------------------------------------------
// AuthLevel (NIST AAL)
// ---------------------------------------------------------------------------

// AuthLevel is the authenticator assurance level reached by the session. It is
// a pure AuthN signal: a future AuthZ layer may require a minimum level
// (step-up) for sensitive actions. The zero value is invalid.
type AuthLevel uint8

const (
	// AAL1: a single factor proven (e.g. password).
	AAL1 AuthLevel = iota + 1
	// AAL2: two distinct factors proven (e.g. password + TOTP).
	AAL2
)

func (l AuthLevel) Valid() bool { return l == AAL1 || l == AAL2 }

func (l AuthLevel) String() string {
	switch l {
	case AAL1:
		return "aal1"
	case AAL2:
		return "aal2"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// AuthMethod (amr)
// ---------------------------------------------------------------------------

// AuthMethod identifies a single factor used to authenticate a session (the
// OIDC "amr" claim, RFC 8176). AuthLevel records the assurance *tier* reached;
// amr records *which* methods produced it — kept for audit and for finer policy
// (e.g. a step-up rule demanding a specific method, not just a level).
type AuthMethod string

const (
	AuthMethodPassword AuthMethod = "pwd"
	AuthMethodOTP      AuthMethod = "otp"
	AuthMethodOAuth    AuthMethod = "oauth"
	AuthMethodWebAuthn AuthMethod = "webauthn"
)

func (m AuthMethod) Valid() bool {
	switch m {
	case AuthMethodPassword, AuthMethodOTP, AuthMethodOAuth, AuthMethodWebAuthn:
		return true
	default:
		return false
	}
}

// normaliseAuthMethods validates and de-duplicates a method set, preserving
// first-seen order. It rejects an empty set and any invalid method.
func normaliseAuthMethods(methods []AuthMethod) ([]AuthMethod, error) {
	if len(methods) == 0 {
		return nil, ErrNoAuthMethod
	}
	out := make([]AuthMethod, 0, len(methods))
	for _, m := range methods {
		if !m.Valid() {
			return nil, fmt.Errorf("%w: %q", ErrInvalidAuthMethod, m)
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// DeviceInfo (value object)
// ---------------------------------------------------------------------------

// DeviceInfo captures where a session originated, for session listing and
// anomaly detection. All fields are optional (a caller may not know them); the
// domain stores them without interpretation.
type DeviceInfo struct {
	ip        netip.Addr // zero = unknown
	userAgent string
	label     string
}

// NewDeviceInfo builds device metadata. ip may be empty (unknown); when present
// it must be a valid IP. userAgent/label are free-form and trimmed.
func NewDeviceInfo(ip, userAgent, label string) (DeviceInfo, error) {
	d := DeviceInfo{
		userAgent: strings.TrimSpace(userAgent),
		label:     strings.TrimSpace(label),
	}
	if ip = strings.TrimSpace(ip); ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return DeviceInfo{}, fmt.Errorf("%w: %q", ErrInvalidIP, ip)
		}
		d.ip = addr
	}
	return d, nil
}

func (d DeviceInfo) IP() netip.Addr    { return d.ip }
func (d DeviceInfo) UserAgent() string { return d.userAgent }
func (d DeviceInfo) Label() string     { return d.label }

// ---------------------------------------------------------------------------
// SessionStatus
// ---------------------------------------------------------------------------

// SessionStatus is the stored lifecycle state. Expiry is time-derived; the
// Expired state is a persisted snapshot (e.g. set by a sweeper) so revoked and
// expired sessions can be told apart in the store.
type SessionStatus uint8

const (
	SessionActive SessionStatus = iota
	SessionRevoked
	SessionExpired
)

func (s SessionStatus) String() string {
	switch s {
	case SessionActive:
		return "active"
	case SessionRevoked:
		return "revoked"
	case SessionExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// Session (aggregate root)
// ---------------------------------------------------------------------------

// Session is the stateful, opaque authenticated-state aggregate. The client
// holds a bearer token whose hash is stored here; the server controls the
// lifecycle (idle + absolute expiry, revocation, step-up).
//
// It carries identity and AuthN assurance only — never authorization decisions.
// Roles are read live from the User, not snapshotted here, so they never go
// stale inside an un-revoked session.
type Session struct {
	id        SessionID
	userID    UserID
	tokenHash TokenHash
	status    SessionStatus
	authLevel AuthLevel
	amr       []AuthMethod // methods that produced authLevel (set semantics)
	device    DeviceInfo

	issuedAt   time.Time
	absExpiry  time.Time     // hard cap, never moves
	idleExpiry time.Time     // slides on Touch
	idleTTL    time.Duration // window re-applied on each Touch
	lastSeenAt time.Time

	revokedAt *time.Time
	reason    string
}

// NewSession issues a fresh active session. idleTTL is the inactivity window;
// absoluteTTL is the hard lifetime cap. Both must be positive and idleTTL must
// not exceed absoluteTTL.
func NewSession(
	now time.Time,
	userID UserID,
	tokenHash TokenHash,
	authLevel AuthLevel,
	methods []AuthMethod,
	device DeviceInfo,
	idleTTL, absoluteTTL time.Duration,
) (*Session, error) {
	if userID.IsZero() {
		return nil, ErrInvalidUserID
	}
	if tokenHash.IsZero() {
		return nil, ErrEmptyTokenHash
	}
	if !authLevel.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidAuthLevel, authLevel)
	}
	amr, err := normaliseAuthMethods(methods)
	if err != nil {
		return nil, err
	}
	if idleTTL <= 0 || absoluteTTL <= 0 || idleTTL > absoluteTTL {
		return nil, ErrInvalidTTL
	}

	absExpiry := now.Add(absoluteTTL)
	return &Session{
		id:         NewSessionID(),
		userID:     userID,
		tokenHash:  tokenHash,
		status:     SessionActive,
		authLevel:  authLevel,
		amr:        amr,
		device:     device,
		issuedAt:   now,
		absExpiry:  absExpiry,
		idleExpiry: minTime(now.Add(idleTTL), absExpiry),
		idleTTL:    idleTTL,
		lastSeenAt: now,
	}, nil
}

// ReconstituteSession rebuilds a Session from persisted state without invariants.
// Repository/persistence layer only.
func ReconstituteSession(
	id SessionID,
	userID UserID,
	tokenHash TokenHash,
	status SessionStatus,
	authLevel AuthLevel,
	amr []AuthMethod,
	device DeviceInfo,
	issuedAt, absExpiry, idleExpiry time.Time,
	idleTTL time.Duration,
	lastSeenAt time.Time,
	revokedAt *time.Time,
	reason string,
) *Session {
	return &Session{
		id:         id,
		userID:     userID,
		tokenHash:  tokenHash,
		status:     status,
		authLevel:  authLevel,
		amr:        slices.Clone(amr),
		device:     device,
		issuedAt:   issuedAt,
		absExpiry:  absExpiry,
		idleExpiry: idleExpiry,
		idleTTL:    idleTTL,
		lastSeenAt: lastSeenAt,
		revokedAt:  clonePtr(revokedAt),
		reason:     reason,
	}
}

// --- getters ---------------------------------------------------------------

func (s *Session) ID() SessionID         { return s.id }
func (s *Session) UserID() UserID        { return s.userID }
func (s *Session) TokenHash() TokenHash  { return s.tokenHash }
func (s *Session) Status() SessionStatus { return s.status }
func (s *Session) AuthLevel() AuthLevel  { return s.authLevel }
func (s *Session) Device() DeviceInfo    { return s.device }

// AMR returns a copy of the authentication methods used; the internal slice is
// not exposed.
func (s *Session) AMR() []AuthMethod { return slices.Clone(s.amr) }

// UsedMethod reports whether method m was used to authenticate this session.
func (s *Session) UsedMethod(m AuthMethod) bool { return slices.Contains(s.amr, m) }
func (s *Session) IssuedAt() time.Time          { return s.issuedAt }
func (s *Session) AbsoluteExpiry() time.Time    { return s.absExpiry }
func (s *Session) IdleExpiry() time.Time        { return s.idleExpiry }
func (s *Session) IdleTTL() time.Duration       { return s.idleTTL }
func (s *Session) LastSeenAt() time.Time        { return s.lastSeenAt }
func (s *Session) Reason() string               { return s.reason }

// RevokedAt returns the revocation time and whether the session was revoked.
func (s *Session) RevokedAt() (time.Time, bool) {
	if s.revokedAt == nil {
		return time.Time{}, false
	}
	return *s.revokedAt, true
}

// --- queries ---------------------------------------------------------------

// IsExpired reports whether the session has passed either deadline at now.
//
// idleExpiry is always <= absExpiry for a session built here (capped via minTime
// at construction and on every Touch), so the idle check alone normally decides
// expiry. The absExpiry check is defensive: it still fires if Reconstitute is
// handed corrupt persisted state where idleExpiry was stored beyond absExpiry.
func (s *Session) IsExpired(now time.Time) bool {
	return now.After(s.absExpiry) || now.After(s.idleExpiry)
}

// IsActive reports whether the session may be used at now: stored-active and
// not past either deadline.
func (s *Session) IsActive(now time.Time) bool {
	return s.status == SessionActive && !s.IsExpired(now)
}

// --- behaviour -------------------------------------------------------------

// Touch records activity: it refreshes lastSeenAt and slides the idle deadline
// (bounded by the absolute cap). It fails on a revoked or expired session.
func (s *Session) Touch(now time.Time) error {
	if s.status == SessionRevoked {
		return ErrSessionRevoked
	}
	if s.status == SessionExpired || s.IsExpired(now) {
		return ErrSessionExpired
	}
	s.lastSeenAt = now
	s.idleExpiry = minTime(now.Add(s.idleTTL), s.absExpiry)
	return nil
}

// Revoke terminates an active session with an audit reason.
func (s *Session) Revoke(now time.Time, reason string) error {
	if s.status != SessionActive {
		return ErrSessionNotActive
	}
	s.status = SessionRevoked
	s.revokedAt = &now
	s.reason = strings.TrimSpace(reason)
	return nil
}

// Expire marks a session expired once past a deadline. Intended for a sweeper
// that persists the derived state. It returns ErrSessionNotActive when the
// session is not in the active state (already revoked/expired), and
// ErrSessionNotExpired when it is active but has not yet passed a deadline —
// the two cases are distinct so a caller can tell "already gone" from "too early".
func (s *Session) Expire(now time.Time) error {
	if s.status != SessionActive {
		return ErrSessionNotActive
	}
	if !s.IsExpired(now) {
		return ErrSessionNotExpired
	}
	s.status = SessionExpired
	return nil
}

// StepUp raises the session's assurance level (e.g. aal1 -> aal2 after MFA) and
// records the method that proved it. A step-up always presents a new factor, so
// the method is required and appended to the amr set (deduplicated). The level
// only ever raises: equal level keeps the level but still records the method,
// lower level is rejected. Fails on a non-active session or invalid inputs.
//
// StepUp records assurance only, not activity: it deliberately does not slide
// the idle deadline or lastSeenAt. A caller that wants the step-up to also count
// as activity calls Touch separately.
func (s *Session) StepUp(now time.Time, level AuthLevel, method AuthMethod) error {
	if !level.Valid() {
		return fmt.Errorf("%w: %d", ErrInvalidAuthLevel, level)
	}
	if !method.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidAuthMethod, method)
	}
	if !s.IsActive(now) {
		return ErrSessionNotActive
	}
	if level < s.authLevel {
		return ErrAALNotRaised
	}
	if !slices.Contains(s.amr, method) {
		s.amr = append(s.amr, method)
	}
	s.authLevel = level
	return nil
}

// --- internals -------------------------------------------------------------

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
