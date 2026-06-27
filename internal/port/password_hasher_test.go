package port_test

import (
	"context"
	"testing"

	"authentication/internal/port"
)

var _ port.PasswordHasher = (*fakeHasher)(nil)

type fakeHasher struct{}

func (*fakeHasher) Hash(context.Context, string) ([]byte, error) {
	return []byte("hashed"), nil
}

func TestPasswordHasherStubReturnsBytes(t *testing.T) {
	var h port.PasswordHasher = &fakeHasher{}
	got, err := h.Hash(context.Background(), "pw")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("Hash returned empty bytes")
	}
}
