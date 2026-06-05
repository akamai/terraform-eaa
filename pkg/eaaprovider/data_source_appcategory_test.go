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
// dataSourceAppCategories — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceAppCategories_SchemaBasics(t *testing.T) {
	ds := dataSourceAppCategories()
	assertDataSourceBasics(t, ds, "appcategories", schema.TypeList)
	assert.True(t, ds.Schema["appcategories"].Computed, "appcategories must be computed")
}

func TestDataSourceAppCategories_ElemFields(t *testing.T) {
	ds := dataSourceAppCategories()
	elem, ok := ds.Schema["appcategories"].Elem.(*schema.Resource)
	require.True(t, ok, "appcategories Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":     {schema.TypeString, true},
		"uuid_url": {schema.TypeString, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := elem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in appcategories elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

// ---------------------------------------------------------------------------
// dataSourceAppCategoriesRead — behavioral tests
// ---------------------------------------------------------------------------

func TestDataSourceAppCategoriesRead_Success(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/appcategories"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":     "Web Applications",
					"uuid_url": "urn:cat:web-apps",
				},
				{
					"name":     "SaaS",
					"uuid_url": "urn:cat:saas",
				},
			},
		},
	}

	d := createTestResourceDataFor(t, dataSourceAppCategories, map[string]any{})
	diags := dataSourceAppCategoriesRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics")
	assert.Equal(t, "eaa_appcategories", d.Id())

	cats := d.Get("appcategories").([]interface{})
	require.Len(t, cats, 2)
	first := cats[0].(map[string]interface{})
	assert.Equal(t, "Web Applications", first["name"])
	assert.Equal(t, "urn:cat:web-apps", first["uuid_url"])
}

func TestDataSourceAppCategoriesRead_APIError(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/appcategories"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourceAppCategories, map[string]any{})
	diags := dataSourceAppCategoriesRead(context.Background(), d, mockClient)

	assert.NotEmpty(t, diags, "expected error diagnostics for 500 response")
}
