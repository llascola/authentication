package domain

// ConfirmedSecondFactor reports whether c is a usable, confirmed second factor
// for MFA. It is the single source of truth for "which credentials let a user
// turn MFA on", so the rule never fragments across the application/UI layers.
//
//   - OTP: counts only once Confirm has proven possession via a valid code. An
//     unconfirmed OTP is a secret nobody has proven they hold; enabling MFA off
//     it would risk locking the user out, so it does not count.
//   - WebAuthn: the registration ceremony itself proves possession (the
//     authenticator signs a challenge), so a stored credential always counts.
//   - password / oauth: first factors, never a second factor.
//
// The sealed Credential interface makes the switch a closed set: a new
// credential kind added later falls through to the safe default (false) until a
// human makes a deliberate decision here, so a new kind can never silently
// enable MFA.
func ConfirmedSecondFactor(c Credential) bool {
	switch f := c.(type) {
	case *OTPCredential:
		return f.Confirmed()
	case *WebAuthnCredential:
		return true
	default:
		return false
	}
}
