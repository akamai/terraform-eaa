package eaaprovider

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceDirectories — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceDirectories_SchemaBasics(t *testing.T) {
	ds := dataSourceDirectories()
	assertDataSourceBasics(t, ds, "directories", schema.TypeList)
	assert.True(t, ds.Schema["directories"].Computed, "directories must be computed")
}

func TestDataSourceDirectories_ElemFields(t *testing.T) {
	ds := dataSourceDirectories()
	elem, ok := ds.Schema["directories"].Elem.(*schema.Resource)
	require.True(t, ok, "directories Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":           {schema.TypeString, true},
		"uuid_url":       {schema.TypeString, true},
		"service":        {schema.TypeInt, true},
		"status":         {schema.TypeInt, true},
		"directory_type": {schema.TypeInt, true},
		"user_count":     {schema.TypeInt, true},
		"group_count":    {schema.TypeInt, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := elem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in directories elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

// ---------------------------------------------------------------------------
// dataSourceDirectoriesRead — behavioral tests
// ---------------------------------------------------------------------------

func TestDataSourceDirectoriesRead_Success(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/directories"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":           "Cloud Directory",
					"uuid_url":       "urn:dir:cloud-dir",
					"service":        6,
					"status":         1,
					"directory_type": 1,
					"user_count":     10,
					"group_count":    2,
				},
				{
					"name":           "Corporate LDAP",
					"uuid_url":       "urn:dir:corp-ldap",
					"service":        3,
					"status":         1,
					"directory_type": 2,
					"user_count":     500,
					"group_count":    25,
				},
			},
		},
	}

	d := createTestResourceDataFor(t, dataSourceDirectories, map[string]any{})
	diags := dataSourceDirectoriesRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics")
	assert.Equal(t, "eaa_directories", d.Id())

	dirs := d.Get("directories").([]interface{})
	require.Len(t, dirs, 2)

	first := dirs[0].(map[string]interface{})
	assert.Equal(t, "Cloud Directory", first["name"])
	assert.Equal(t, "urn:dir:cloud-dir", first["uuid_url"])
	assert.Equal(t, 6, first["service"])
	assert.Equal(t, 1, first["status"])
	assert.Equal(t, 1, first["directory_type"])
	assert.Equal(t, 10, first["user_count"])
	assert.Equal(t, 2, first["group_count"])

	second := dirs[1].(map[string]interface{})
	assert.Equal(t, "Corporate LDAP", second["name"])
	assert.Equal(t, "urn:dir:corp-ldap", second["uuid_url"])
}

func TestDataSourceDirectoriesRead_APIError(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/directories"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourceDirectories, map[string]any{})
	diags := dataSourceDirectoriesRead(context.Background(), d, mockClient)

	assert.NotEmpty(t, diags, "expected error diagnostics for 500 response")
}

func TestDataSourceDirectoriesRead_Empty(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/directories"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{},
		},
	}

	d := createTestResourceDataFor(t, dataSourceDirectories, map[string]any{})
	diags := dataSourceDirectoriesRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics for empty response")
	assert.Equal(t, "eaa_directories", d.Id())

	dirs := d.Get("directories").([]interface{})
	assert.Empty(t, dirs, "expected empty directories list")
}
