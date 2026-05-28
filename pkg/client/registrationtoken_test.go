package client

import (
	"context"
	"strings"
	"testing"
)

func TestFormatExpiresAt(t *testing.T) {
	tests := map[string]struct {
		input         string
		want          string
		wantErrSubstr string
	}{
		"zero_seconds_bumped_to_one": {
			input: "2026-05-30T14:30:00Z",
			want:  "2026-05-30T14:30:01Z",
		},
		"non_zero_seconds_unchanged": {
			input: "2026-05-30T14:30:05Z",
			want:  "2026-05-30T14:30:05Z",
		},
		"positive_timezone_offset_normalized_to_utc": {
			input: "2026-05-30T16:30:00+02:00",
			want:  "2026-05-30T14:30:01Z",
		},
		"negative_timezone_offset_normalized_to_utc": {
			input: "2026-05-30T09:30:00-05:00",
			want:  "2026-05-30T14:30:01Z",
		},
		"already_utc_non_zero_seconds": {
			input: "2026-01-02T15:04:05Z",
			want:  "2026-01-02T15:04:05Z",
		},
		"nanoseconds_stripped": {
			input: "2026-05-30T14:30:05.999999999Z",
			want:  "2026-05-30T14:30:05Z",
		},
		"invalid_input": {
			input:         "not-a-timestamp",
			wantErrSubstr: "invalid RFC3339 timestamp",
		},
		"empty_input": {
			input:         "",
			wantErrSubstr: "invalid RFC3339 timestamp",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := FormatExpiresAt(tt.input)
			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("FormatExpiresAt(%q) returned nil error, want error containing %q", tt.input, tt.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Fatalf("FormatExpiresAt(%q) error = %q, want message containing %q", tt.input, err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FormatExpiresAt(%q) returned unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("FormatExpiresAt(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRegistrationTokenWriteRequestValidate(t *testing.T) {
	tests := map[string]struct {
		wantErrSubstr string
		req           RegistrationTokenWriteRequest
	}{
		"max_use_zero": {
			req: RegistrationTokenWriteRequest{
				Name:      "token-name",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    0,
			},
			wantErrSubstr: "max_use must be in the range of 1 to 1000",
		},
		"max_use_one": {
			req: RegistrationTokenWriteRequest{
				Name:      "token-name",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    1,
			},
		},
		"max_use_thousand": {
			req: RegistrationTokenWriteRequest{
				Name:      "token-name",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    1000,
			},
		},
		"max_use_thousand_one": {
			req: RegistrationTokenWriteRequest{
				Name:      "token-name",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    1001,
			},
			wantErrSubstr: "max_use must be in the range of 1 to 1000",
		},
		"empty_name": {
			req: RegistrationTokenWriteRequest{
				Name:      "",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    1,
			},
			wantErrSubstr: "registration token name cannot be empty",
		},
		"past_expires_at": {
			req: RegistrationTokenWriteRequest{
				Name:      "token-name",
				ExpiresAt: "2020-01-01T00:00:01Z",
				MaxUse:    1,
			},
			wantErrSubstr: "expires_at must be in the future",
		},
		"empty_expires_at": {
			req: RegistrationTokenWriteRequest{
				Name:      "token-name",
				ExpiresAt: "",
				MaxUse:    1,
			},
			wantErrSubstr: "registration token expires_at cannot be empty",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Validate() returned nil error, want error containing %q", tt.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Fatalf("Validate() error = %q, want message containing %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestUpdateRegistrationTokenValidatesBeforeAPICall(t *testing.T) {
	tests := map[string]struct {
		wantErrSubstr string
		req           RegistrationTokenWriteRequest
	}{
		"empty_name_rejected": {
			req: RegistrationTokenWriteRequest{
				Name:      "",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    1,
			},
			wantErrSubstr: "invalid update registration token request",
		},
		"max_use_zero_rejected": {
			req: RegistrationTokenWriteRequest{
				Name:      "my-token",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    0,
			},
			wantErrSubstr: "invalid update registration token request",
		},
		"max_use_over_limit_rejected": {
			req: RegistrationTokenWriteRequest{
				Name:      "my-token",
				ExpiresAt: "2030-01-01T00:00:01Z",
				MaxUse:    1001,
			},
			wantErrSubstr: "invalid update registration token request",
		},
	}

	// EaaClient with no HTTP client — if Validate() did not run first the test
	// would panic reaching SendAPIRequest, confirming validation is a pre-check.
	nilClient := &EaaClient{}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := UpdateRegistrationToken(context.Background(), nilClient, "some-uuid", &tt.req)
			if err == nil {
				t.Fatalf("UpdateRegistrationToken() returned nil error, want error containing %q", tt.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Fatalf("UpdateRegistrationToken() error = %q, want message containing %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}
