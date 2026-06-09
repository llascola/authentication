// Package domain holds the core business entities and rules of the auth
// server. It is dependency-free (stdlib + google/uuid only) and knows nothing
// about transport, storage, or specific authentication mechanisms. Nothing in
// this package may import internal/port, internal/app, or any adapter; the
// dependency arrow always points inward, toward domain.
//
// # Aggregates
//
// Each aggregate is a consistency boundary with a single root entity. Roots
// reference one another by ID only — never by embedding — so an aggregate can
// be loaded, mutated, and persisted in isolation.
//
//   - User: the identity aggregate, deliberately decoupled from any single
//     authentication method. Owns email/phone, status lifecycle, roles,
//     lockout, and the MFA-enabled flag.
//   - Credential: a sealed interface with one concrete type per kind
//     (PasswordCredential, OAuthCredential, OTPCredential, WebAuthnCredential).
//     Each references its User by ID, so one identity can hold many methods.
//   - Session: the stateful, opaque authenticated-state root. Holds the token
//     hash, assurance level (AAL1/AAL2), AMR, device info, and idle/absolute
//     expiry.
//   - VerificationToken: single-use, time-bounded proof for a given Purpose
//     (email verify, password reset, ...), stored hashed.
//   - RecoveryCodeSet: a bounded set of single-use recovery codes, stored
//     hashed.
//   - PasswordPolicy: a Unicode-aware plaintext validator built with
//     functional options.
//
// # Conventions
//
// Constructors come in two flavours. New* builds a fresh aggregate: it
// validates every argument and stamps timestamps. Reconstitute* hydrates an
// already-valid aggregate from storage: it trusts its inputs and runs no
// validation. Adapters loading from a database call Reconstitute*; application
// code creating new state calls New*.
//
// Time is always injected. Every constructor and mutator that needs the clock
// takes an explicit now time.Time argument; the domain never calls time.Now
// itself, which keeps it deterministic and testable.
//
// Aggregate fields are private. Every mutation goes through a method that
// preserves invariants, making illegal states hard to represent. Getters that
// return slices or byte values hand back a defensive copy (slices.Clone or an
// append-to-nil), so callers cannot mutate aggregate internals.
//
// Errors are exported sentinels named Err* and compared with errors.Is.
// Wrap with %w to add context. Validators that can report several problems at
// once (e.g. PasswordPolicy) aggregate violations with errors.Join.
//
// # Concurrency
//
// Aggregates are not safe for concurrent use. Infrastructure must serialise
// read-modify-write on a single aggregate (e.g. row lock or optimistic retry);
// the domain assumes one in-flight mutation at a time.
package domain
