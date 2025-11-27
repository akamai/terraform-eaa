package client

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

// TestValidationFunctionsExistence tests that the validation functions exist and can be imported
func TestValidationFunctionsExistence(t *testing.T) {
	t.Run("ValidateSAMLNestedBlocks exists", func(t *testing.T) {
		// This test just ensures the function exists and can be imported
		// We're not testing functionality here, just that the function is available
		assert.NotNil(t, ValidateSAMLNestedBlocks, "ValidateSAMLNestedBlocks function should exist")
	})
	
	t.Run("ValidateOIDCNestedBlocks exists", func(t *testing.T) {
		// This test just ensures the function exists and can be imported  
		// We're not testing functionality here, just that the function is available
		assert.NotNil(t, ValidateOIDCNestedBlocks, "ValidateOIDCNestedBlocks function should exist")
	})
}

// TestValidateStringInSlice tests ValidateStringInSlice utility
func TestValidateStringInSlice(t *testing.T) {
	tests := []struct {
		name        string
		val         string
		key         string
		validValues []string
		wantWarns   int
		wantErrs    int
		errMsg      string
	}{
		{
			name:        "valid value in slice",
			val:         "value1",
			key:         "test_field",
			validValues: []string{"value1", "value2", "value3"},
			wantWarns:   0,
			wantErrs:    0,
		},
		{
			name:        "value not in slice",
			val:         "invalid",
			key:         "test_field",
			validValues: []string{"value1", "value2", "value3"},
			wantWarns:   0,
			wantErrs:    1,
			errMsg:      "must be one of",
		},
		{
			name:        "empty value with empty valid values",
			val:         "",
			key:         "test_field",
			validValues: []string{},
			wantWarns:   0,
			wantErrs:    1,
		},
		{
			name:        "empty value with non-empty valid values",
			val:         "",
			key:         "test_field",
			validValues: []string{"value1", "value2"},
			wantWarns:   0,
			wantErrs:    1,
		},
		{
			name:        "case sensitive matching",
			val:         "VALUE1",
			key:         "test_field",
			validValues: []string{"value1", "value2"},
			wantWarns:   0,
			wantErrs:    1,
		},
		{
			name:        "single valid value",
			val:         "value1",
			key:         "test_field",
			validValues: []string{"value1"},
			wantWarns:   0,
			wantErrs:    0,
		},
		{
			name:        "value at beginning of slice",
			val:         "value1",
			key:         "test_field",
			validValues: []string{"value1", "value2", "value3"},
			wantWarns:   0,
			wantErrs:    0,
		},
		{
			name:        "value at end of slice",
			val:         "value3",
			key:         "test_field",
			validValues: []string{"value1", "value2", "value3"},
			wantWarns:   0,
			wantErrs:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns, errs := ValidateStringInSlice(tt.val, tt.key, tt.validValues)
			assert.Len(t, warns, tt.wantWarns)
			assert.Len(t, errs, tt.wantErrs)
			if tt.wantErrs > 0 && tt.errMsg != "" {
				assert.Contains(t, errs[0].Error(), tt.errMsg)
			}
		})
	}
}

// TestValidateIntegerField tests ValidateIntegerField utility
func TestValidateIntegerField(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := &EaaClient{Logger: logger}

	tests := []struct {
		name      string
		value     interface{}
		fieldName string
		min       int
		max       int
		want      int
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid integer in range",
			value:     5,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      5,
			wantErr:   false,
		},
		{
			name:      "valid integer at minimum",
			value:     1,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      1,
			wantErr:   false,
		},
		{
			name:      "valid integer at maximum",
			value:     10,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      10,
			wantErr:   false,
		},
		{
			name:      "integer below minimum",
			value:     0,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be in the range",
		},
		{
			name:      "integer above maximum",
			value:     11,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be in the range",
		},
		{
			name:      "invalid type - string",
			value:     "5",
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be an integer",
		},
		{
			name:      "invalid type - float",
			value:     5.5,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be an integer",
		},
		{
			name:      "invalid type - bool",
			value:     true,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be an integer",
		},
		{
			name:      "invalid type - nil",
			value:     nil,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be an integer",
		},
		{
			name:      "zero value with min > 0",
			value:     0,
			fieldName: "test_field",
			min:       1,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be in the range",
		},
		{
			name:      "zero value with min = 0",
			value:     0,
			fieldName: "test_field",
			min:       0,
			max:       10,
			want:      0,
			wantErr:   false,
		},
		{
			name:      "negative value with min = 0",
			value:     -1,
			fieldName: "test_field",
			min:       0,
			max:       10,
			want:      0,
			wantErr:   true,
			errMsg:    "must be in the range",
		},
		{
			name:      "large range",
			value:     500,
			fieldName: "test_field",
			min:       1,
			max:       1000,
			want:      500,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateIntegerField(tt.value, tt.fieldName, tt.min, tt.max, client)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Equal(t, 0, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}