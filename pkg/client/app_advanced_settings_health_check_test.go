package client

import (
	"testing"
)

// TestParseAdvancedSettingsWithInvalidHealthCheckType tests that ParseAdvancedSettingsWithDefaults
// returns an error when health_check_type contains an invalid numeric value from the API.
// This tests the error path at the read (JSON parsing) level.
func TestParseAdvancedSettingsWithInvalidHealthCheckType(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid_numeric_value",
			input: `{"health_check_type": "99"}`,
		},
		{
			name:  "invalid_string_value",
			input: `{"health_check_type": "invalid_type"}`,
		},
		{
			name:  "negative_value",
			input: `{"health_check_type": "-1"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAdvancedSettingsWithDefaults(tt.input)
			if err == nil {
				t.Errorf("ParseAdvancedSettingsWithDefaults with input %s returned nil error, want non-nil error", tt.input)
			}
		})
	}
}

// TestAdvancedSettingsFromBlockWithInvalidHealthCheckType tests that advancedSettingsFromBlock
// returns an error when health_check_type contains an invalid value. This tests the error path
// at the block (Terraform config) parsing level.
func TestAdvancedSettingsFromBlockWithInvalidHealthCheckType(t *testing.T) {
	tests := []struct {
		block map[string]interface{}
		name  string
	}{
		{
			name: "invalid_health_check_type_value",
			block: map[string]interface{}{
				"health_check_type": "InvalidType",
			},
		},
		{
			name: "numeric_out_of_range",
			block: map[string]interface{}{
				"health_check_type": "999",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := advancedSettingsFromBlock(tt.block)
			if err == nil {
				t.Errorf("advancedSettingsFromBlock with %v returned nil error, want non-nil error", tt.block)
			}
		})
	}
}

// TestAdvancedSettingsFromBlockWithValidHealthCheckType tests that advancedSettingsFromBlock
// correctly converts valid health_check_type values and does not error.
func TestAdvancedSettingsFromBlockWithValidHealthCheckType(t *testing.T) {
	validTypes := map[string]string{
		"Default": "0",
		"HTTP":    "1",
		"HTTPS":   "2",
		"TLS":     "3",
		"SSLv3":   "4",
		"TCP":     "5",
		"None":    "6",
	}

	for typeName, expectedNumeric := range validTypes {
		t.Run(typeName, func(t *testing.T) {
			block := map[string]interface{}{
				"health_check_type": typeName,
			}

			advSettings, err := advancedSettingsFromBlock(block)
			if err != nil {
				t.Fatalf("advancedSettingsFromBlock returned error for valid type %s: %v", typeName, err)
			}

			if advSettings.HealthCheckType != expectedNumeric {
				t.Errorf("HealthCheckType = %s, want %s", advSettings.HealthCheckType, expectedNumeric)
			}
		})
	}
}

// TestParseAdvancedSettingsWithValidHealthCheckType tests that ParseAdvancedSettingsWithDefaults
// correctly handles valid health check type numeric values without error.
func TestParseAdvancedSettingsWithValidHealthCheckType(t *testing.T) {
	validCases := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "default", input: `{"health_check_type": "0"}`, expected: "0"},
		{name: "http", input: `{"health_check_type": "1"}`, expected: "1"},
		{name: "https", input: `{"health_check_type": "2"}`, expected: "2"},
		{name: "tls", input: `{"health_check_type": "3"}`, expected: "3"},
		{name: "sslv3", input: `{"health_check_type": "4"}`, expected: "4"},
		{name: "tcp", input: `{"health_check_type": "5"}`, expected: "5"},
		{name: "none", input: `{"health_check_type": "6"}`, expected: "6"},
		{name: "empty", input: `{"health_check_type": ""}`, expected: ""},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			advSettings, err := ParseAdvancedSettingsWithDefaults(tc.input)
			if err != nil {
				t.Fatalf("ParseAdvancedSettingsWithDefaults returned error for valid input %s: %v", tc.input, err)
			}

			if advSettings.HealthCheckType != tc.expected {
				t.Errorf("HealthCheckType = %s, want %s", advSettings.HealthCheckType, tc.expected)
			}
		})
	}
}

// TestMapHealthCheckTypeToNumericWithInvalidValues tests that MapHealthCheckTypeToNumeric
// returns an error for invalid health check type values.
func TestMapHealthCheckTypeToNumericWithInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid_type", input: "InvalidType"},
		{name: "wrong_case", input: "http"}, // Should be "HTTP"
		{name: "partial_match", input: "Def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MapHealthCheckTypeToNumeric(tt.input)
			if err == nil {
				t.Errorf("MapHealthCheckTypeToNumeric(%s) returned nil error, want non-nil error", tt.input)
			}
		})
	}
}

// TestMapHealthCheckTypeToNumericWithValidValues tests that MapHealthCheckTypeToNumeric
// correctly converts valid health check type values without error.
func TestMapHealthCheckTypeToNumericWithValidValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "default", input: "Default", expected: "0"},
		{name: "http", input: "HTTP", expected: "1"},
		{name: "https", input: "HTTPS", expected: "2"},
		{name: "tls", input: "TLS", expected: "3"},
		{name: "sslv3", input: "SSLv3", expected: "4"},
		{name: "tcp", input: "TCP", expected: "5"},
		{name: "none", input: "None", expected: "6"},
		{name: "empty", input: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := MapHealthCheckTypeToNumeric(tt.input)
			if err != nil {
				t.Fatalf("MapHealthCheckTypeToNumeric(%s) returned error: %v", tt.input, err)
			}

			if result != tt.expected {
				t.Errorf("MapHealthCheckTypeToNumeric(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

// TestMapHealthCheckTypeToDescriptiveWithInvalidValues tests that MapHealthCheckTypeToDescriptive
// returns an error for invalid numeric health check type values.
func TestMapHealthCheckTypeToDescriptiveWithInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid_number", input: "99"},
		{name: "non_numeric", input: "invalid"},
		{name: "negative", input: "-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MapHealthCheckTypeToDescriptive(tt.input)
			if err == nil {
				t.Errorf("MapHealthCheckTypeToDescriptive(%s) returned nil error, want non-nil error", tt.input)
			}
		})
	}
}

// TestMapHealthCheckTypeToDescriptiveWithValidValues tests that MapHealthCheckTypeToDescriptive
// correctly converts valid numeric health check type values without error.
func TestMapHealthCheckTypeToDescriptiveWithValidValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "default", input: "0", expected: "Default"},
		{name: "http", input: "1", expected: "HTTP"},
		{name: "https", input: "2", expected: "HTTPS"},
		{name: "tls", input: "3", expected: "TLS"},
		{name: "sslv3", input: "4", expected: "SSLv3"},
		{name: "tcp", input: "5", expected: "TCP"},
		{name: "none", input: "6", expected: "None"},
		{name: "empty", input: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := MapHealthCheckTypeToDescriptive(tt.input)
			if err != nil {
				t.Fatalf("MapHealthCheckTypeToDescriptive(%s) returned error: %v", tt.input, err)
			}

			if result != tt.expected {
				t.Errorf("MapHealthCheckTypeToDescriptive(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}
