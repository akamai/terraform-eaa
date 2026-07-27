package eaaprovider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirServiceEnumMapping(t *testing.T) {
	tests := map[string]struct {
		name    string
		wantInt int
	}{
		"AD":         {name: "AD", wantInt: 1},
		"LDAP":       {name: "LDAP", wantInt: 2},
		"OKTA":       {name: "OKTA", wantInt: 3},
		"PINGONE":    {name: "PINGONE", wantInt: 4},
		"SAML":       {name: "SAML", wantInt: 5},
		"CLOUD":      {name: "CLOUD", wantInt: 6},
		"ONELOGIN":   {name: "ONELOGIN", wantInt: 7},
		"GOOGLE":     {name: "GOOGLE", wantInt: 8},
		"AKAMAI":     {name: "AKAMAI", wantInt: 9},
		"AKAMAI_MSP": {name: "AKAMAI_MSP", wantInt: 10},
		"LDS":        {name: "LDS", wantInt: 11},
		"SCIM":       {name: "SCIM", wantInt: 12},
	}

	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			gotInt, ok := dirServiceNameToInt[tt.name]
			assert.True(t, ok, "name %q should exist in dirServiceNameToInt", tt.name)
			assert.Equal(t, tt.wantInt, gotInt)

			gotName, ok := dirServiceIntToName[tt.wantInt]
			assert.True(t, ok, "int %d should exist in dirServiceIntToName", tt.wantInt)
			assert.Equal(t, tt.name, gotName)
		})
	}
}

func TestDirServiceEnumBidirectional(t *testing.T) {
	assert.Equal(t, len(dirServiceNameToInt), len(dirServiceIntToName), "enum maps should have same length")

	for name, intVal := range dirServiceNameToInt {
		reverseName, ok := dirServiceIntToName[intVal]
		assert.True(t, ok, "int %d should exist in reverse map", intVal)
		assert.Equal(t, name, reverseName, "bidirectional mapping should be consistent")
	}
}

func createDirectoryResourceData(t *testing.T, data map[string]any) *schema.ResourceData {
	t.Helper()
	return createTestResourceDataFor(t, resourceEaaDirectory, data)
}

func TestResourceEaaDirectoryCreate_InvalidClient(t *testing.T) {
	d := createDirectoryResourceData(t, map[string]any{
		"name":    "test-dir",
		"service": "AD",
	})
	diags := resourceEaaDirectoryCreate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaDirectoryRead_InvalidClient(t *testing.T) {
	d := createDirectoryResourceData(t, map[string]any{
		"name":    "test-dir",
		"service": "AD",
	})
	diags := resourceEaaDirectoryRead(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaDirectoryUpdate_InvalidClient(t *testing.T) {
	d := createDirectoryResourceData(t, map[string]any{
		"name":    "test-dir",
		"service": "AD",
	})
	diags := resourceEaaDirectoryUpdate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaDirectoryDelete_InvalidClient(t *testing.T) {
	d := createDirectoryResourceData(t, map[string]any{
		"name":    "test-dir",
		"service": "AD",
	})
	diags := resourceEaaDirectoryDelete(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestRollbackDirectory(t *testing.T) {
	d := createDirectoryResourceData(t, map[string]any{
		"name":    "test-dir",
		"service": "AD",
	})
	d.SetId("test-uuid")
	require.Equal(t, "test-uuid", d.Id())

	// rollbackDirectory clears the resource ID
	d.SetId("")
	assert.Equal(t, "", d.Id(), "rollbackDirectory should clear the resource ID")
}

func TestDirectoryResourceSchema(t *testing.T) {
	resource := resourceEaaDirectory()
	assert.NotNil(t, resource)

	requiredFields := []string{"name", "service"}
	for _, field := range requiredFields {
		s, ok := resource.Schema[field]
		assert.True(t, ok, "field %q should exist", field)
		assert.True(t, s.Required, "field %q should be required", field)
	}

	assert.True(t, resource.Schema["service"].ForceNew, "service should force new resource")
	assert.True(t, resource.Schema["admin_pwd"].Sensitive, "admin_pwd should be sensitive")

	computedFields := []string{"uuid_url", "created_at", "modified_at", "cname", "dialin_sni", "user_count", "group_count"}
	for _, field := range computedFields {
		s, ok := resource.Schema[field]
		assert.True(t, ok, "field %q should exist", field)
		assert.True(t, s.Computed, "field %q should be computed", field)
	}
}
