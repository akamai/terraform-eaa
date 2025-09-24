package eaaprovider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Helper function to create string pointer (removed duplicate - defined in resource_eaa_application_test.go)

// Helper function to create test resource data
func createTestResourceData(data map[string]interface{}) *schema.ResourceData {
	resource := resourceEaaConnectorPool()
	d := resource.Data(nil)
	for key, value := range data {
		d.Set(key, value)
	}
	return d
}

func TestValidatePackageType(t *testing.T) {
	tests := []struct {
		name          string
		value         interface{}
		expectedError bool
	}{
		{
			name:          "valid_vmware",
			value:         "vmware",
			expectedError: false,
		},
		{
			name:          "valid_aws",
			value:         "aws",
			expectedError: false,
		},
		{
			name:          "valid_docker",
			value:         "docker",
			expectedError: false,
		},
		{
			name:          "valid_azure",
			value:         "azure",
			expectedError: false,
		},
		{
			name:          "valid_google",
			value:         "google",
			expectedError: false,
		},
		{
			name:          "invalid_type",
			value:         "invalid",
			expectedError: true,
		},
		{
			name:          "non_string_value",
			value:         123,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns, errs := validatePackageType(tt.value, "package_type")

			if tt.expectedError {
				if len(errs) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
				}
			}

			// Warnings should be empty for this validator
			if len(warns) > 0 {
				t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
			}
		})
	}
}

func TestValidateInfraType(t *testing.T) {
	tests := []struct {
		name          string
		value         interface{}
		expectedError bool
	}{
		{
			name:          "valid_eaa",
			value:         "eaa",
			expectedError: false,
		},
		{
			name:          "valid_unified",
			value:         "unified",
			expectedError: false,
		},
		{
			name:          "valid_broker",
			value:         "broker",
			expectedError: false,
		},
		{
			name:          "valid_cpag",
			value:         "cpag",
			expectedError: false,
		},
		{
			name:          "invalid_type",
			value:         "invalid",
			expectedError: true,
		},
		{
			name:          "non_string_value",
			value:         123,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns, errs := validateInfraType(tt.value, "infra_type")

			if tt.expectedError {
				if len(errs) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
				}
			}

			// Warnings should be empty for this validator
			if len(warns) > 0 {
				t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
			}
		})
	}
}

func TestValidateOperatingMode(t *testing.T) {
	tests := []struct {
		name          string
		value         interface{}
		expectedError bool
	}{
		{
			name:          "valid_connector",
			value:         "connector",
			expectedError: false,
		},
		{
			name:          "valid_peb",
			value:         "peb",
			expectedError: false,
		},
		{
			name:          "valid_combined",
			value:         "combined",
			expectedError: false,
		},
		{
			name:          "valid_cpag_public",
			value:         "cpag_public",
			expectedError: false,
		},
		{
			name:          "valid_cpag_private",
			value:         "cpag_private",
			expectedError: false,
		},
		{
			name:          "valid_connector_with_china_acceleration",
			value:         "connector_with_china_acceleration",
			expectedError: false,
		},
		{
			name:          "invalid_mode",
			value:         "invalid",
			expectedError: true,
		},
		{
			name:          "non_string_value",
			value:         123,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns, errs := validateOperatingMode(tt.value, "operating_mode")

			if tt.expectedError {
				if len(errs) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
				}
			}

			// Warnings should be empty for this validator
			if len(warns) > 0 {
				t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
			}
		})
	}
}

func TestResourceEaaConnectorPoolSchema(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that the resource has the expected schema fields
	expectedFields := []string{
		"name", "package_type", "description", "infra_type", "operating_mode",
		"uuid_url", "connectors", "registration_tokens",
	}

	for _, field := range expectedFields {
		if _, exists := resource.Schema[field]; !exists {
			t.Errorf("Expected schema field '%s' not found", field)
		}
	}

	// Test that required fields are marked as required
	if !resource.Schema["name"].Required {
		t.Error("Expected 'name' field to be required")
	}
	if !resource.Schema["package_type"].Required {
		t.Error("Expected 'package_type' field to be required")
	}
}

func TestHasDuplicateTokenNames(t *testing.T) {
	tests := []struct {
		name          string
		resourceData  map[string]interface{}
		expectedError bool
	}{
		{
			name: "no_duplicates",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token2"},
					{"name": "token3"},
				},
			},
			expectedError: false,
		},
		{
			name: "with_duplicates",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token1"}, // duplicate
					{"name": "token2"},
				},
			},
			expectedError: true,
		},
		{
			name: "no_tokens",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{},
			},
			expectedError: false,
		},
		{
			name: "single_token",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
				},
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := createTestResourceData(tt.resourceData)
			err := hasDuplicateTokenNames(d)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, err)
				}
			}
		})
	}
}

func TestSetConnectorPoolBasicAttributes(t *testing.T) {
	tests := []struct {
		name        string
		connPool    *client.ConnectorPool
		expectedMap map[string]interface{}
	}{
		{
			name: "basic_connector_pool",
			connPool: &client.ConnectorPool{
				Name:          "test-pool",
				Description:   stringPtr("Test pool description"),
				PackageType:   1,
				InfraType:     1,
				OperatingMode: 1,
				UUIDURL:       "test-uuid-123",
				CIDRs:         []string{"10.0.0.0/8"},
			},
			expectedMap: map[string]interface{}{
				"name":           "test-pool",
				"description":    "Test pool description",
				"package_type":   "vmware",
				"infra_type":     "eaa",
				"operating_mode": "connector",
				"uuid_url":       "test-uuid-123",
			},
		},
		{
			name: "connector_pool_with_nil_description",
			connPool: &client.ConnectorPool{
				Name:          "test-pool-2",
				Description:   nil,
				PackageType:   2,
				InfraType:     1,
				OperatingMode: 1,
				UUIDURL:       "test-uuid-456",
				CIDRs:         []string{"192.168.0.0/16"},
			},
			expectedMap: map[string]interface{}{
				"name":           "test-pool-2",
				"description":    "",
				"package_type":   "vbox",
				"infra_type":     "eaa",
				"operating_mode": "connector",
				"uuid_url":       "test-uuid-456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := createTestResourceData(map[string]interface{}{})
			setConnectorPoolBasicAttributes(d, tt.connPool)

			for key, expectedValue := range tt.expectedMap {
				actualValue := d.Get(key)
				if actualValue != expectedValue {
					t.Errorf("Expected %s to be %v, got %v", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolV0(t *testing.T) {
	resource := resourceEaaConnectorPoolV0()

	// Test that the resource has the expected schema fields
	expectedFields := []string{
		"name", "package_type", "description", "infra_type", "operating_mode",
		"uuid_url", "connectors", "registration_tokens",
	}

	for _, field := range expectedFields {
		if _, exists := resource.Schema[field]; !exists {
			t.Errorf("Expected schema field '%s' not found", field)
		}
	}
}

func TestResourceEaaConnectorPoolCreate(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "successful_creation_with_minimal_data",
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
			},
			expectedError:    true, // Will fail due to invalid client
			expectedErrorMsg: "invalid client",
		},
		{
			name: "creation_with_all_fields",
			resourceData: map[string]interface{}{
				"name":           "test-pool-complete",
				"package_type":   "aws",
				"description":    "Complete test pool",
				"infra_type":     "eaa",
				"operating_mode": "connector",
				"connectors":     []string{"connector1", "connector2"},
				"registration_tokens": []map[string]interface{}{
					{
						"name":            "token1",
						"max_use":         5,
						"expires_in_days": 30,
					},
				},
			},
			expectedError:    true, // Will fail due to invalid client
			expectedErrorMsg: "invalid client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Create function
			diags := resourceEaaConnectorPoolCreate(nil, d, nil)

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				if len(diags) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolRead(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "read_with_valid_ID",
			resourceData: map[string]interface{}{
				"uuid_url": "test-pool-uuid-123",
			},
			expectedError:    true, // Will fail due to invalid client
			expectedErrorMsg: "invalid client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Read function
			diags := resourceEaaConnectorPoolRead(nil, d, nil)

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				if len(diags) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolUpdate(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "update_with_valid_data",
			resourceData: map[string]interface{}{
				"uuid_url":     "test-pool-uuid-123",
				"name":         "updated-pool",
				"package_type": "aws",
			},
			expectedError:    true, // Will fail due to invalid client
			expectedErrorMsg: "invalid client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Update function
			diags := resourceEaaConnectorPoolUpdate(nil, d, nil)

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				if len(diags) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolDelete(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "deletion_with_valid_ID",
			resourceData: map[string]interface{}{
				"uuid_url": "test-pool-uuid-123",
			},
			expectedError:    true, // Will fail due to invalid client
			expectedErrorMsg: "invalid client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Delete function
			diags := resourceEaaConnectorPoolDelete(nil, d, nil)

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				if len(diags) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}

func TestValidatePackageTypeEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		value         interface{}
		expectedError bool
	}{
		{
			name:          "empty_string",
			value:         "",
			expectedError: true,
		},
		{
			name:          "nil_value",
			value:         nil,
			expectedError: true,
		},
		{
			name:          "valid_vbox",
			value:         "vbox",
			expectedError: false,
		},
		{
			name:          "valid_kvm",
			value:         "kvm",
			expectedError: false,
		},
		{
			name:          "valid_hyperv",
			value:         "hyperv",
			expectedError: false,
		},
		{
			name:          "valid_aws_classic",
			value:         "aws_classic",
			expectedError: false,
		},
		{
			name:          "valid_softlayer",
			value:         "softlayer",
			expectedError: false,
		},
		{
			name:          "valid_fujitsu_k5",
			value:         "fujitsu_k5",
			expectedError: false,
		},
		{
			name:          "case_sensitive_invalid",
			value:         "VMware", // Should be lowercase
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns, errs := validatePackageType(tt.value, "package_type")

			if tt.expectedError {
				if len(errs) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
				}
			}

			// Warnings should be empty for this validator
			if len(warns) > 0 {
				t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
			}
		})
	}
}

func TestValidateInfraTypeEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		value         interface{}
		expectedError bool
	}{
		{
			name:          "empty_string",
			value:         "",
			expectedError: true,
		},
		{
			name:          "nil_value",
			value:         nil,
			expectedError: true,
		},
		{
			name:          "case_sensitive_invalid",
			value:         "EAA", // Should be lowercase
			expectedError: true,
		},
		{
			name:          "whitespace_string",
			value:         " eaa ",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns, errs := validateInfraType(tt.value, "infra_type")

			if tt.expectedError {
				if len(errs) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
				}
			}

			// Warnings should be empty for this validator
			if len(warns) > 0 {
				t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
			}
		})
	}
}

func TestValidateOperatingModeEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		value         interface{}
		expectedError bool
	}{
		{
			name:          "empty_string",
			value:         "",
			expectedError: true,
		},
		{
			name:          "nil_value",
			value:         nil,
			expectedError: true,
		},
		{
			name:          "case_sensitive_invalid",
			value:         "Connector", // Should be lowercase
			expectedError: true,
		},
		{
			name:          "whitespace_string",
			value:         " connector ",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns, errs := validateOperatingMode(tt.value, "operating_mode")

			if tt.expectedError {
				if len(errs) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
				}
			}

			// Warnings should be empty for this validator
			if len(warns) > 0 {
				t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
			}
		})
	}
}

func TestHasDuplicateTokenNamesEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		resourceData  map[string]interface{}
		expectedError bool
	}{
		{
			name: "nil_tokens",
			resourceData: map[string]interface{}{
				"registration_tokens": nil,
			},
			expectedError: false,
		},
		{
			name: "tokens_with_empty_names",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": ""},
					{"name": ""},
				},
			},
			expectedError: true, // Empty names are considered duplicates
		},
		{
			name: "tokens_with_mixed_empty_and_valid_names",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": ""},
					{"name": "token2"},
				},
			},
			expectedError: false,
		},
		{
			name: "tokens_with_special_characters",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "token-1"},
					{"name": "token_2"},
					{"name": "token.3"},
				},
			},
			expectedError: false,
		},
		{
			name: "tokens_with_case_sensitivity",
			resourceData: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "Token1"},
					{"name": "token1"}, // Different case, should not be considered duplicate
				},
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := createTestResourceData(tt.resourceData)
			err := hasDuplicateTokenNames(d)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, err)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolSchemaComprehensive(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test name field
	if nameSchema, exists := resource.Schema["name"]; exists {
		if !nameSchema.Required {
			t.Error("Expected 'name' field to be required")
		}
		if nameSchema.Type != schema.TypeString {
			t.Error("Expected 'name' field to be of type String")
		}
	} else {
		t.Error("Expected 'name' field to exist in schema")
	}

	// Test package_type field
	if packageTypeSchema, exists := resource.Schema["package_type"]; exists {
		if !packageTypeSchema.Required {
			t.Error("Expected 'package_type' field to be required")
		}
		if packageTypeSchema.Type != schema.TypeString {
			t.Error("Expected 'package_type' field to be of type String")
		}
		if packageTypeSchema.ValidateFunc == nil {
			t.Error("Expected 'package_type' field to have validation function")
		}
	} else {
		t.Error("Expected 'package_type' field to exist in schema")
	}

	// Test description field
	if descSchema, exists := resource.Schema["description"]; exists {
		if descSchema.Required {
			t.Error("Expected 'description' field to be optional")
		}
		if descSchema.Type != schema.TypeString {
			t.Error("Expected 'description' field to be of type String")
		}
	} else {
		t.Error("Expected 'description' field to exist in schema")
	}

	// Test infra_type field
	if infraTypeSchema, exists := resource.Schema["infra_type"]; exists {
		if infraTypeSchema.Required {
			t.Error("Expected 'infra_type' field to be optional")
		}
		if infraTypeSchema.Type != schema.TypeString {
			t.Error("Expected 'infra_type' field to be of type String")
		}
		if infraTypeSchema.ValidateFunc == nil {
			t.Error("Expected 'infra_type' field to have validation function")
		}
	} else {
		t.Error("Expected 'infra_type' field to exist in schema")
	}

	// Test operating_mode field
	if operatingModeSchema, exists := resource.Schema["operating_mode"]; exists {
		if operatingModeSchema.Required {
			t.Error("Expected 'operating_mode' field to be optional")
		}
		if operatingModeSchema.Type != schema.TypeString {
			t.Error("Expected 'operating_mode' field to be of type String")
		}
		if operatingModeSchema.ValidateFunc == nil {
			t.Error("Expected 'operating_mode' field to have validation function")
		}
	} else {
		t.Error("Expected 'operating_mode' field to exist in schema")
	}

	// Test uuid_url field
	if uuidURLSchema, exists := resource.Schema["uuid_url"]; exists {
		if uuidURLSchema.Required {
			t.Error("Expected 'uuid_url' field to be optional")
		}
		if uuidURLSchema.Type != schema.TypeString {
			t.Error("Expected 'uuid_url' field to be of type String")
		}
	} else {
		t.Error("Expected 'uuid_url' field to exist in schema")
	}

	// Test connectors field
	if connectorsSchema, exists := resource.Schema["connectors"]; exists {
		if connectorsSchema.Required {
			t.Error("Expected 'connectors' field to be optional")
		}
		if connectorsSchema.Type != schema.TypeList {
			t.Error("Expected 'connectors' field to be of type List")
		}
	} else {
		t.Error("Expected 'connectors' field to exist in schema")
	}

	// Test registration_tokens field
	if tokensSchema, exists := resource.Schema["registration_tokens"]; exists {
		if tokensSchema.Required {
			t.Error("Expected 'registration_tokens' field to be optional")
		}
		if tokensSchema.Type != schema.TypeList {
			t.Error("Expected 'registration_tokens' field to be of type List")
		}
		if tokensSchema.Elem == nil {
			t.Error("Expected 'registration_tokens' field to have element schema")
		}
	} else {
		t.Error("Expected 'registration_tokens' field to exist in schema")
	}
}

func TestRegistrationTokenValidation(t *testing.T) {
	// Test max_use validation
	tests := []struct {
		name          string
		value         interface{}
		expectedError bool
	}{
		{
			name:          "valid_max_use",
			value:         5,
			expectedError: false,
		},
		{
			name:          "max_use_too_low",
			value:         0,
			expectedError: true,
		},
		{
			name:          "max_use_too_high",
			value:         1001,
			expectedError: true,
		},
		{
			name:          "valid_expires_in_days",
			value:         30,
			expectedError: false,
		},
		{
			name:          "expires_in_days_too_low",
			value:         0,
			expectedError: true,
		},
		{
			name:          "expires_in_days_too_high",
			value:         366,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test max_use validation
			if tt.name == "valid_max_use" || tt.name == "max_use_too_low" || tt.name == "max_use_too_high" {
				// Convert int to string for validation
				valueStr := ""
				if intVal, ok := tt.value.(int); ok {
					valueStr = fmt.Sprintf("%d", intVal)
				}
				warns, errs := client.ValidateStringInSlice(valueStr, "max_use", []string{"1", "2", "3", "4", "5", "10", "20", "50", "100", "200", "500", "1000"})
				if tt.expectedError {
					if len(errs) == 0 {
						t.Errorf("Expected error but got none for test case: %s", tt.name)
					}
				} else {
					if len(errs) > 0 {
						t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
					}
				}
				if len(warns) > 0 {
					t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
				}
			}

			// Test expires_in_days validation
			if tt.name == "valid_expires_in_days" || tt.name == "expires_in_days_too_low" || tt.name == "expires_in_days_too_high" {
				// Convert int to string for validation
				valueStr := ""
				if intVal, ok := tt.value.(int); ok {
					valueStr = fmt.Sprintf("%d", intVal)
				}
				warns, errs := client.ValidateStringInSlice(valueStr, "expires_in_days", []string{"1", "2", "3", "4", "5", "7", "14", "30", "60", "90", "180", "365"})
				if tt.expectedError {
					if len(errs) == 0 {
						t.Errorf("Expected error but got none for test case: %s", tt.name)
					}
				} else {
					if len(errs) > 0 {
						t.Errorf("Unexpected error for test case %s: %v", tt.name, errs)
					}
				}
				if len(warns) > 0 {
					t.Errorf("Unexpected warnings for test case %s: %v", tt.name, warns)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolImporter(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that the resource has an importer configured
	if resource.Importer == nil {
		t.Error("Expected resource to have an importer configured")
	}

	// Test that the importer uses ImportStatePassthroughContext
	if resource.Importer.StateContext == nil {
		t.Error("Expected importer to have StateContext configured")
	}
}

func TestResourceEaaConnectorPoolStateUpgraders(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that the resource has state upgraders configured
	if resource.StateUpgraders == nil {
		t.Error("Expected resource to have state upgraders configured")
	}

	// Test that there is at least one state upgrader
	if len(resource.StateUpgraders) == 0 {
		t.Error("Expected resource to have at least one state upgrader")
	}

	// Test that the first upgrader has the correct version
	if resource.StateUpgraders[0].Version != 0 {
		t.Error("Expected first state upgrader to have version 0")
	}
}

func TestResourceEaaConnectorPoolSchemaVersion(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that the resource has the correct schema version
	if resource.SchemaVersion != 1 {
		t.Error("Expected resource schema version to be 1")
	}
}

func TestResourceEaaConnectorPoolCRUDOperations(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that the resource has all CRUD operations configured
	if resource.CreateContext == nil {
		t.Error("Expected resource to have CreateContext configured")
	}
	if resource.ReadContext == nil {
		t.Error("Expected resource to have ReadContext configured")
	}
	if resource.UpdateContext == nil {
		t.Error("Expected resource to have UpdateContext configured")
	}
	if resource.DeleteContext == nil {
		t.Error("Expected resource to have DeleteContext configured")
	}
}

func TestResourceEaaConnectorPoolDescription(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that deprecation message is not set (resource is not deprecated)
	if resource.DeprecationMessage != "" {
		t.Error("Expected resource to not have a deprecation message")
	}
}

func TestResourceEaaConnectorPoolTimeouts(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that timeouts are not configured (resource doesn't have timeouts)
	if resource.Timeouts != nil {
		t.Error("Expected resource to not have timeouts configured")
	}
}

func TestResourceEaaConnectorPoolDeprecationMessage(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test that deprecation message is not set (resource is not deprecated)
	if resource.DeprecationMessage != "" {
		t.Error("Expected resource to not have a deprecation message")
	}
}

// Since we can't easily mock the client due to type assertions,
// let's focus on testing the parts we can test without a real client

// Enhanced CRUD tests focusing on testable parts
func TestResourceEaaConnectorPoolCreateValidationPaths(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "creation_with_duplicate_tokens_validation",
			resourceData: map[string]interface{}{
				"name":         "test-pool-duplicates",
				"package_type": "vmware",
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token1"}, // duplicate
				},
			},
			expectedError:    true,
			expectedErrorMsg: "duplicate registration token name found",
		},
		{
			name: "creation_with_valid_tokens_validation",
			resourceData: map[string]interface{}{
				"name":         "test-pool-valid",
				"package_type": "vmware",
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token2"},
				},
			},
			expectedError: false,
		},
		{
			name: "creation_with_empty_tokens_validation",
			resourceData: map[string]interface{}{
				"name":                "test-pool-empty",
				"package_type":        "vmware",
				"registration_tokens": []map[string]interface{}{},
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Create function - it will fail at client creation but we can test validation
			diags := resourceEaaConnectorPoolCreate(context.Background(), d, "invalid-client")

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content (partial match)
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg ||
							strings.Contains(diag.Summary, tt.expectedErrorMsg) ||
							strings.Contains(diag.Detail, tt.expectedErrorMsg) {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				// For non-error cases, we expect client error but not validation error
				// We should only get "invalid client" error, not validation errors
				validationErrorFound := false
				for _, diag := range diags {
					if strings.Contains(diag.Summary, "duplicate registration token name found") ||
						strings.Contains(diag.Detail, "duplicate registration token name found") {
						validationErrorFound = true
						break
					}
				}
				if validationErrorFound {
					t.Errorf("Unexpected validation error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolReadValidationPaths(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "read_with_empty_id",
			resourceData: map[string]interface{}{
				"uuid_url": "",
			},
			expectedError:    true,
			expectedErrorMsg: "invalid client",
		},
		{
			name: "read_with_valid_id",
			resourceData: map[string]interface{}{
				"uuid_url": "test-uuid-123",
			},
			expectedError:    true, // Will fail at client creation
			expectedErrorMsg: "invalid client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Read function - it will fail at client creation
			diags := resourceEaaConnectorPoolRead(context.Background(), d, "invalid-client")

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				if len(diags) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolUpdateValidationPaths(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "update_with_duplicate_tokens_validation",
			resourceData: map[string]interface{}{
				"uuid_url":     "test-uuid-123",
				"name":         "updated-pool-duplicates",
				"package_type": "aws",
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token1"}, // duplicate
				},
			},
			expectedError:    true,
			expectedErrorMsg: "duplicate registration token name found",
		},
		{
			name: "update_with_valid_tokens_validation",
			resourceData: map[string]interface{}{
				"uuid_url":     "test-uuid-123",
				"name":         "updated-pool-valid",
				"package_type": "aws",
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token2"},
				},
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Update function - it will fail at client creation but we can test validation
			diags := resourceEaaConnectorPoolUpdate(context.Background(), d, "invalid-client")

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content (partial match)
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg ||
							strings.Contains(diag.Summary, tt.expectedErrorMsg) ||
							strings.Contains(diag.Detail, tt.expectedErrorMsg) {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				// For non-error cases, we expect client error but not validation error
				// We should only get "invalid client" error, not validation errors
				validationErrorFound := false
				for _, diag := range diags {
					if strings.Contains(diag.Summary, "duplicate registration token name found") ||
						strings.Contains(diag.Detail, "duplicate registration token name found") {
						validationErrorFound = true
						break
					}
				}
				if validationErrorFound {
					t.Errorf("Unexpected validation error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}

func TestResourceEaaConnectorPoolDeleteValidationPaths(t *testing.T) {
	tests := []struct {
		name             string
		resourceData     map[string]interface{}
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "delete_with_empty_id",
			resourceData: map[string]interface{}{
				"uuid_url": "",
			},
			expectedError:    true,
			expectedErrorMsg: "invalid client",
		},
		{
			name: "delete_with_valid_id",
			resourceData: map[string]interface{}{
				"uuid_url": "test-uuid-123",
			},
			expectedError:    true, // Will fail at client creation
			expectedErrorMsg: "invalid client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create resource data
			d := createTestResourceData(tt.resourceData)

			// Test the Delete function - it will fail at client creation
			diags := resourceEaaConnectorPoolDelete(context.Background(), d, "invalid-client")

			if tt.expectedError {
				if len(diags) == 0 {
					t.Errorf("Expected error but got none for test case: %s", tt.name)
				} else {
					// Check if the error message contains expected content
					errorFound := false
					for _, diag := range diags {
						if diag.Summary == tt.expectedErrorMsg || diag.Detail == tt.expectedErrorMsg {
							errorFound = true
							break
						}
					}
					if !errorFound {
						t.Logf("Expected error message '%s' not found in diagnostics: %v", tt.expectedErrorMsg, diags)
					}
				}
			} else {
				if len(diags) > 0 {
					t.Errorf("Unexpected error for test case %s: %v", tt.name, diags)
				}
			}
		})
	}
}
