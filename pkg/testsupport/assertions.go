package testsupport

import (
	"errors"
	"testing"
)

// RequireErrIs asserts error presence and optional error identity in one helper.
func RequireErrIs(t testing.TB, err error, wantErr bool, errIs error) bool {
	t.Helper()
	if wantErr {
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if errIs != nil && !errors.Is(err, errIs) {
			t.Fatalf("expected error to match %v, got %v", errIs, err)
		}
		return true
	}
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	return false
}
