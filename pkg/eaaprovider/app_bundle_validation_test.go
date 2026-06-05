package eaaprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAppBundle(t *testing.T) {
	tests := map[string]struct {
		val       interface{}
		wantErr   bool
		wantWarns int
	}{
		"valid_uuid": {
			val: "abcdef12-3456-7890-abcd-ef1234567890",
		},
		"valid_non_empty_string": {
			val: "some-bundle-id",
		},
		"invalid_empty_string": {
			val:     "",
			wantErr: true,
		},
		"invalid_nil": {
			val:     nil,
			wantErr: true,
		},
		"whitespace_passes_current_validation": {
			// whitespace is a non-empty string, so it passes the current validation
			val: "   ",
		},
		"invalid_non_string_int": {
			val:     123,
			wantErr: true,
		},
		"invalid_non_string_bool": {
			val:     true,
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateAppBundle(tc.val, "app_bundle")
			assert.Empty(t, warns)
			if tc.wantErr {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}
