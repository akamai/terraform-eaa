package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestResourceEaaRegistrationToken(t *testing.T) {
	resource := resourceEaaRegistrationToken()
	if resource == nil {
		t.Fatal("resourceEaaRegistrationToken() returned nil")
	}

	// Test that the resource has the expected CRUD operations
	if resource.CreateContext == nil {
		t.Error("CreateContext is nil")
	}
	if resource.ReadContext == nil {
		t.Error("ReadContext is nil")
	}
	if resource.UpdateContext == nil {
		t.Error("UpdateContext is nil")
	}
	if resource.DeleteContext == nil {
		t.Error("DeleteContext is nil")
	}

	// Test that the schema has the expected fields
	schema := resource.Schema
	expectedFields := []string{
		"name",
		"max_use",
		"expires_at",
		"connector_pool",
		"generate_embedded_img",
		"gid",
		"uuid_url",
		"token",
		"used_count",
		"token_suffix",
		"image_url",
		"modified_at",
		"agents",
	}

	for _, field := range expectedFields {
		if _, exists := schema[field]; !exists {
			t.Errorf("Schema missing expected field: %s", field)
		}
	}

	// Test that required fields are marked as required
	requiredFields := []string{"name", "max_use", "expires_at", "connector_pool", "gid"}
	for _, field := range requiredFields {
		if schema[field].Required != true {
			t.Errorf("Field %s should be required", field)
		}
	}

	// Test that computed fields are marked as computed
	computedFields := []string{"uuid_url", "token", "used_count", "token_suffix", "image_url", "modified_at", "agents"}
	for _, field := range computedFields {
		if schema[field].Computed != true {
			t.Errorf("Field %s should be computed", field)
		}
	}
} 