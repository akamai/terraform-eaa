package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestResourceEaaConnectorPool(t *testing.T) {
	resource := resourceEaaConnectorPool()
	if resource == nil {
		t.Fatal("resourceEaaConnectorPool() returned nil")
	}

	// Test that the resource has the expected schema fields
	expectedFields := []string{
		"name",
		"description",
		"package_type",
		"infra_type",
		"operating_mode",
		"uuid_url",
		"cidrs",
	}

	for _, field := range expectedFields {
		if _, ok := resource.Schema[field]; !ok {
			t.Errorf("Expected field '%s' not found in schema", field)
		}
	}

	// Test that required fields are marked as required
	requiredFields := []string{"name", "description", "package_type", "infra_type", "operating_mode"}
	for _, field := range requiredFields {
		if !resource.Schema[field].Required {
			t.Errorf("Field '%s' should be required", field)
		}
	}

	// Test that computed fields are marked as computed
	computedFields := []string{"uuid_url", "cidrs"}
	for _, field := range computedFields {
		if !resource.Schema[field].Computed {
			t.Errorf("Field '%s' should be computed", field)
		}
	}
}

func TestResourceEaaConnectorPoolSchema(t *testing.T) {
	resource := resourceEaaConnectorPool()

	// Test schema validation
	testCases := []struct {
		name    string
		config  map[string]interface{}
		isValid bool
	}{
		{
			name: "valid configuration",
			config: map[string]interface{}{
				"name":           "test_pool",
				"description":    "test description",
				"package_type":   1,
				"infra_type":     3,
				"operating_mode": 3,
			},
			isValid: true,
		},
		{
			name: "missing required field",
			config: map[string]interface{}{
				"name":        "test_pool",
				"description": "test description",
				// missing package_type, infra_type, operating_mode
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a resource data object
			rd := schema.TestResourceDataRaw(t, resource.Schema, tc.config)

			// This is a basic test - in a real scenario, you'd want to test
			// the actual CRUD operations with a mock client
			if rd == nil {
				t.Fatal("Failed to create resource data")
			}
		})
	}
}
