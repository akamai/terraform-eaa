package eaaprovider

import (
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// TestMapAdvancedSettingsFromResponseWithInvalidHealthCheckType tests that
// mapAdvancedSettingsFromResponse returns an error when the API returns an
// invalid health_check_type value. This is the error path that runs on
// every terraform plan/apply/refresh during the read phase.
func TestMapAdvancedSettingsFromResponseWithInvalidHealthCheckType(t *testing.T) {
	tests := []struct {
		name           string
		healthCheckVal string
	}{
		{
			name:           "invalid_numeric_99",
			healthCheckVal: "99",
		},
		{
			name:           "invalid_negative",
			healthCheckVal: "-1",
		},
		{
			name:           "invalid_non_numeric",
			healthCheckVal: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a resource schema
			resourceSchema := map[string]*schema.Schema{
				"uuid_url": {
					Type:     schema.TypeString,
					Computed: true,
				},
				"name": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"app_type": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"host": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"advanced_settings": {
					Type:     schema.TypeMap,
					Optional: true,
				},
			}

			// Create test resource data
			d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
				"uuid_url": "test-app-id",
				"name":     "test-app",
				"app_type": "http",
				"host":     "test.example.com",
				"advanced_settings": map[string]interface{}{
					"health_check_type": "Default", // Add a valid value to the state
				},
			})

			// Create an application response with invalid health_check_type
			appResp := &client.ApplicationResponse{
				UUIDURL: "test-app-id",
				Name:    "test-app",
				AdvancedSettings: client.AdvancedSettingsComplete{
					AllowCORS:           "false",
					HealthCheckType:     tt.healthCheckVal, // Invalid value
					HealthCheckFall:     "3",
					HealthCheckRise:     "2",
					HealthCheckTimeout:  "50000",
					HealthCheckInterval: "30000",
				},
			}

			// Call mapAdvancedSettingsFromResponse
			diags := mapAdvancedSettingsFromResponse(d, appResp)

			// Verify that we get an error diagnostic
			if !diags.HasError() {
				t.Errorf("mapAdvancedSettingsFromResponse with invalid health_check_type %q returned no errors, want error", tt.healthCheckVal)
			}

			// Check that the error message mentions health_check_type
			if len(diags) == 0 {
				t.Fatal("Expected at least one diagnostic error")
			}

			errorMsg := diags[0].Summary
			if errorMsg != "failed to map health_check_type from API value" && !contains(diags[0].Summary, "health_check_type") {
				t.Errorf("Error message = %q, want message containing 'health_check_type'", errorMsg)
			}
		})
	}
}

// TestMapAdvancedSettingsFromResponseWithValidHealthCheckType tests that
// mapAdvancedSettingsFromResponse correctly handles valid health_check_type values.
func TestMapAdvancedSettingsFromResponseWithValidHealthCheckType(t *testing.T) {
	tests := []struct {
		name           string
		healthCheckVal string
		expectedResult string
	}{
		{name: "default", healthCheckVal: "0", expectedResult: "Default"},
		{name: "http", healthCheckVal: "1", expectedResult: "HTTP"},
		{name: "https", healthCheckVal: "2", expectedResult: "HTTPS"},
		{name: "tls", healthCheckVal: "3", expectedResult: "TLS"},
		{name: "sslv3", healthCheckVal: "4", expectedResult: "SSLv3"},
		{name: "tcp", healthCheckVal: "5", expectedResult: "TCP"},
		{name: "none", healthCheckVal: "6", expectedResult: "None"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a resource schema
			resourceSchema := map[string]*schema.Schema{
				"uuid_url": {
					Type:     schema.TypeString,
					Computed: true,
				},
				"name": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"app_type": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"host": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"advanced_settings": {
					Type:     schema.TypeMap,
					Optional: true,
				},
			}

			// Create test resource data with some prior state
			d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
				"uuid_url": "test-app-id",
				"name":     "test-app",
				"app_type": "http",
				"host":     "test.example.com",
				"advanced_settings": map[string]interface{}{
					"health_check_type": "Default", // Include in prior state
				},
			})

			// Create an application response with valid health_check_type
			appResp := &client.ApplicationResponse{
				UUIDURL: "test-app-id",
				Name:    "test-app",
				AdvancedSettings: client.AdvancedSettingsComplete{
					AllowCORS:           "false",
					HealthCheckType:     tt.healthCheckVal,
					HealthCheckFall:     "3",
					HealthCheckRise:     "2",
					HealthCheckTimeout:  "50000",
					HealthCheckInterval: "30000",
				},
			}

			// Call mapAdvancedSettingsFromResponse
			diags := mapAdvancedSettingsFromResponse(d, appResp)

			// Verify no errors
			if diags.HasError() {
				t.Errorf("mapAdvancedSettingsFromResponse with valid health_check_type %q returned errors: %v", tt.healthCheckVal, diags)
			}

			// Verify the state was set correctly
			advSettingsRaw := d.Get("advanced_settings")
			advSettings, ok := advSettingsRaw.(map[string]interface{})
			if !ok {
				t.Fatalf("advanced_settings type = %T, want map[string]interface{}", advSettingsRaw)
			}

			if got := advSettings["health_check_type"]; got != tt.expectedResult {
				t.Errorf("health_check_type = %q, want %q", got, tt.expectedResult)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substring string) bool {
	for i := 0; i <= len(s)-len(substring); i++ {
		if s[i:i+len(substring)] == substring {
			return true
		}
	}
	return false
}
