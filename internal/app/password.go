package app

import (
	"context"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// passwordPipeline is the single validate→screen→hash path shared by Register,
// ChangePassword, and ResetPassword. It turns a raw plaintext into a stored
// domain.PasswordHash and never lets the plaintext touch a domain entity.
type passwordPipeline struct {
	normalizer port.Normalizer
	policy     domain.PasswordPolicy
	screener   port.PasswordScreener
	hasher     port.PasswordHasher
}

// process normalizes (NFC), policy-validates, breach-screens, and hashes the
// plaintext. The order matters: validation and screening run on the same
// normalized form that gets hashed, so a password can never pass the checks in
// one encoding and be stored under another. Any step's error is returned as-is
// — these concern the submitted password's quality, not account existence, so
// they are not enumeration-sensitive.
func (p passwordPipeline) process(ctx context.Context, plaintext string) (domain.PasswordHash, error) {
	norm := p.normalizer.Normalize(plaintext)
	if err := p.policy.Validate(norm); err != nil {
		return domain.PasswordHash{}, err
	}
	if err := p.screener.Screen(ctx, norm); err != nil {
		return domain.PasswordHash{}, err
	}
	hashBytes, err := p.hasher.Hash(ctx, norm)
	if err != nil {
		return domain.PasswordHash{}, err
	}
	return domain.NewPasswordHash(hashBytes)
}
