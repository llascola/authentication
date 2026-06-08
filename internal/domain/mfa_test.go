package domain_test

import (
	"testing"

	"authentication/internal/domain"
)

func TestConfirmedSecondFactor(t *testing.T) {
	uid := mustUserID(t)

	otpUnconfirmed, err := domain.NewOTPCredential(timeFixed(), uid, mustTOTPSecret(t, []byte("seed")), 0)
	if err != nil {
		t.Fatal(err)
	}

	otpConfirmed, err := domain.NewOTPCredential(timeFixed(), uid, mustTOTPSecret(t, []byte("seed")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = otpConfirmed.Confirm(timeFixed()); err != nil {
		t.Fatal(err)
	}

	webauthn, err := domain.NewWebAuthnCredential(timeFixed(), uid, mustWebAuthnID(t, []byte("h")), mustPublicKey(t, []byte("pk")), 0)
	if err != nil {
		t.Fatal(err)
	}

	password, err := domain.NewPasswordCredential(timeFixed(), uid, mustPasswordHash(t, []byte("h")))
	if err != nil {
		t.Fatal(err)
	}

	oauth, err := domain.NewOAuthCredential(timeFixed(), uid, domain.ProviderGoogle, "sub-1")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		cred domain.Credential
		want bool
	}{
		{"unconfirmed otp does not count", otpUnconfirmed, false},
		{"confirmed otp counts", otpConfirmed, true},
		{"webauthn always counts", webauthn, true},
		{"password never counts", password, false},
		{"oauth never counts", oauth, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ConfirmedSecondFactor(tc.cred); got != tc.want {
				t.Errorf("ConfirmedSecondFactor(%s) = %v, want %v", tc.cred.Type(), got, tc.want)
			}
		})
	}
}
