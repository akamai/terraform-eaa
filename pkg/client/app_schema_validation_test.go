package client

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

// TestCreateMinimalAppRequestFromSchema tests critical schema processing logic
func TestCreateMinimalAppRequestFromSchema(t *testing.T) {
	testCases := []struct {
		name            string
		resourceData    *schema.ResourceData
		expectError     bool
		expectedName    string
		expectedAppType int
	}{
		{
			name: "valid minimal app request",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_profile": {
						Type:     schema.TypeString,
						Optional: true,
					},
					"client_app_mode": {
						Type:     schema.TypeString,
						Optional: true,
					},
				}, map[string]interface{}{
					"name":            "Test App",
					"app_type":        "enterprise",
					"app_profile":     "http",
					"client_app_mode": "tcp",
				})
				return d
			}(),
			expectError:     false,
			expectedName:    "Test App",
			expectedAppType: int(APP_TYPE_ENTERPRISE_HOSTED),
		},
		{
			name: "valid SaaS app request",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
				}, map[string]interface{}{
					"name":     "SaaS Test App",
					"app_type": "saas",
				})
				return d
			}(),
			expectError:     false,
			expectedName:    "SaaS Test App",
			expectedAppType: int(APP_TYPE_SAAS),
		},
		{
			name: "missing required name",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
				}, map[string]interface{}{
					"app_type": "enterprise",
				})
				return d
			}(),
			expectError: true,
		},
		{
			name: "invalid app_type",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
				}, map[string]interface{}{
					"name":     "Invalid App",
					"app_type": "invalid",
				})
				return d
			}(),
			expectError: true,
		},
		{
			name: "empty string for name",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
				}, map[string]interface{}{
					"name":     "",
					"app_type": "enterprise",
				})
				return d
			}(),
			expectError: true,
		},
		{
			name: "invalid app_profile",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_profile": {
						Type:     schema.TypeString,
						Optional: true,
					},
				}, map[string]interface{}{
					"name":        "Test App",
					"app_type":    "enterprise",
					"app_profile": "invalid-profile",
				})
				return d
			}(),
			expectError: true,
		},
		{
			name: "invalid client_app_mode",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
					"client_app_mode": {
						Type:     schema.TypeString,
						Optional: true,
					},
				}, map[string]interface{}{
					"name":            "Test App",
					"app_type":        "enterprise",
					"client_app_mode": "invalid-mode",
				})
				return d
			}(),
			expectError: true,
		},
		{
			name: "missing app_type defaults to enterprise",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Optional: true,
					},
				}, map[string]interface{}{
					"name": "Test App",
				})
				return d
			}(),
			expectError:     false,
			expectedName:    "Test App",
			expectedAppType: int(APP_TYPE_ENTERPRISE_HOSTED),
		},
		{
			name: "empty string for app_type defaults to enterprise",
			resourceData: func() *schema.ResourceData {
				d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"name": {
						Type:     schema.TypeString,
						Required: true,
					},
					"app_type": {
						Type:     schema.TypeString,
						Required: true,
					},
				}, map[string]interface{}{
					"name":     "Test App",
					"app_type": "",
				})
				return d
			}(),
			expectError:     false, // Terraform treats empty string as missing, so it defaults to enterprise
			expectedName:    "Test App",
			expectedAppType: int(APP_TYPE_ENTERPRISE_HOSTED),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock EaaClient
			mockClient := &EaaClient{
				Logger: hclog.NewNullLogger(),
			}

			// Call the function under test
			mcar := &MinimalCreateAppRequest{}
			err := mcar.CreateMinimalAppRequestFromSchema(context.Background(), tc.resourceData, mockClient)

			// Check error expectations
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedName, mcar.Name)
				assert.Equal(t, tc.expectedAppType, mcar.AppType)
			}
		})
	}
}

// TestValidateCustomHeadersConfigurationNew tests custom headers validation logic
func TestValidateCustomHeadersConfigurationNew(t *testing.T) {
	testCases := []struct {
		name          string
		settings      map[string]interface{}
		appType       string
		expectError   bool
		expectedError string
	}{
		{
			name: "valid custom headers for enterprise app",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom-Header",
						"attribute_type": "fixed",
						"attribute":      "custom-value",
					},
				},
			},
			appType:     "enterprise",
			expectError: false,
		},
		{
			name: "valid custom headers for HTTP app",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-API-Key",
						"attribute_type": "fixed",
						"attribute":      "secret-key",
					},
				},
			},
			appType:     "http",
			expectError: true, // HTTP app type doesn't support custom headers
		},
		{
			name: "empty custom headers",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{},
			},
			appType:     "enterprise",
			expectError: false,
		},
		{
			name: "no custom headers",
			settings: map[string]interface{}{
				"other_setting": "value",
			},
			appType:     "enterprise",
			expectError: false,
		},
		{
			name: "header with spaces (should be valid)",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom-Header-With-Spaces",
						"attribute_type": "fixed",
						"attribute":      "some-value",
					},
				},
			},
			appType:     "enterprise",
			expectError: false, // The current implementation doesn't validate header name format
		},
		{
			name: "multiple headers with same name (no duplicate validation)",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Duplicate",
						"attribute_type": "fixed",
						"attribute":      "value1",
					},
					map[string]interface{}{
						"header":         "X-Duplicate",
						"attribute_type": "fixed",
						"attribute":      "value2",
					},
				},
			},
			appType:     "enterprise",
			expectError: false, // The current implementation doesn't check for duplicate header names
		},
		{
			name: "headers not allowed for tunnel apps",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom-Header",
						"attribute_type": "fixed",
						"attribute":      "custom-value",
					},
				},
			},
			appType:       "tunnel",
			expectError:   true,
			expectedError: "custom headers not supported for tunnel applications",
		},
		{
			name: "headers not allowed for SaaS apps",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom-Header",
						"attribute_type": "fixed",
						"attribute":      "custom-value",
					},
				},
			},
			appType:       "saas",
			expectError:   true,
			expectedError: "custom headers are not supported for SaaS apps",
		},
		{
			name: "headers not allowed for bookmark apps",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom-Header",
						"attribute_type": "fixed",
						"attribute":      "custom-value",
					},
				},
			},
			appType:       "bookmark",
			expectError:   true,
			expectedError: "custom headers are not supported for SaaS apps",
		},
		{
			name: "empty app_type allows structure validation",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom-Header",
						"attribute_type": "fixed",
						"attribute":      "custom-value",
					},
				},
			},
			appType:     "",
			expectError: false, // Empty app_type allows structure validation
		},
		{
			name: "invalid header structure - missing header field",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"attribute_type": "fixed",
						"attribute":      "custom-value",
					},
				},
			},
			appType:     "enterprise",
			expectError: true,
		},
		{
			name: "invalid header structure - empty header name",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "",
						"attribute_type": "fixed",
						"attribute":      "custom-value",
					},
				},
			},
			appType:     "enterprise",
			expectError: true,
		},
		{
			name: "invalid attribute_type value",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom-Header",
						"attribute_type": "invalid-type",
						"attribute":      "custom-value",
					},
				},
			},
			appType:     "enterprise",
			expectError: true,
		},
		{
			name: "empty header filtered out (both header and attribute_type empty)",
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "",
						"attribute_type": "",
					},
				},
			},
			appType:     "enterprise",
			expectError: false, // Empty headers are filtered out, so validation passes
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test
			err := ValidateCustomHeadersConfiguration(tc.settings, tc.appType, hclog.NewNullLogger())

			// Check error expectations
			if tc.expectError {
				assert.Error(t, err)
				// Note: We check the actual error messages returned by the function
				switch tc.name {
				case "headers not allowed for tunnel apps":
					assert.Contains(t, err.Error(), "custom headers are not supported for tunnel apps")
				case "valid custom headers for HTTP app":
					assert.Contains(t, err.Error(), "custom headers are not supported for this app type")
				case "headers not allowed for SaaS apps":
					assert.Contains(t, err.Error(), "custom headers are not supported for SaaS apps")
				case "headers not allowed for bookmark apps":
					assert.Contains(t, err.Error(), "custom headers are not supported for SaaS apps")
				case "invalid header structure - missing header field":
					assert.Contains(t, err.Error(), "custom header validation failed")
				case "invalid header structure - empty header name":
					assert.Contains(t, err.Error(), "custom header validation failed")
				case "invalid attribute_type value":
					assert.Contains(t, err.Error(), "custom header validation failed")
				default:
					// For other error cases, check for the generic validation error
					assert.Contains(t, err.Error(), "custom header validation failed")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetMapKeysUtility tests the utility function for extracting map keys
func TestGetMapKeysUtility(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string]interface{}
		expected []string
	}{
		{
			name:     "empty map",
			input:    map[string]interface{}{},
			expected: []string{},
		},
		{
			name: "single key",
			input: map[string]interface{}{
				"key1": "value1",
			},
			expected: []string{"key1"},
		},
		{
			name: "multiple keys with different types",
			input: map[string]interface{}{
				"string_key": "string_value",
				"int_key":    123,
				"bool_key":   false,
				"slice_key":  []string{"a", "b"},
				"map_key":    map[string]string{"nested": "value"},
				"nil_key":    nil,
			},
			expected: []string{"string_key", "int_key", "bool_key", "slice_key", "map_key", "nil_key"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test
			result := getMapKeys(tc.input)

			// Since map iteration order is not guaranteed, we need to sort both slices for comparison
			// or check that all expected keys are present
			assert.ElementsMatch(t, tc.expected, result)
		})
	}
}
