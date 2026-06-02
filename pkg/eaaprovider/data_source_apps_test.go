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
// dataSourceApps — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceApps_SchemaBasics(t *testing.T) {
	ds := dataSourceApps()
	assertDataSourceBasics(t, ds, "apps", schema.TypeList)
	assert.True(t, ds.Schema["apps"].Computed, "apps must be computed")
}

func TestDataSourceApps_ElemFields(t *testing.T) {
	ds := dataSourceApps()
	elem, ok := ds.Schema["apps"].Elem.(*schema.Resource)
	require.True(t, ok, "apps Elem must be *schema.Resource")

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
			require.True(t, exists, "field %q must exist in apps elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

// ---------------------------------------------------------------------------
// dataSourceAppsRead — behavioral tests
// ---------------------------------------------------------------------------

func TestDataSourceAppsRead_Success(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	// GetApps uses v3 API with pagination; mock the path pattern
	mockTransport.Responses["GET /crux/v3/mgmt-pop/apps"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":     "app-one",
					"uuid_url": "urn:app:app-1",
				},
				{
					"name":     "app-two",
					"uuid_url": "urn:app:app-2",
				},
			},
			"meta": map[string]interface{}{
				"next":        nil,
				"limit":       10,
				"offset":      0,
				"total_count": 2,
			},
		},
	}

	d := createTestResourceDataFor(t, dataSourceApps, map[string]any{})
	diags := dataSourceAppsRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics")
	assert.Equal(t, "eaa_apps", d.Id())

	apps := d.Get("apps").([]interface{})
	require.Len(t, apps, 2)
	first := apps[0].(map[string]interface{})
	assert.Equal(t, "app-one", first["name"])
	assert.Equal(t, "urn:app:app-1", first["uuid_url"])
}

func TestDataSourceAppsRead_APIError(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v3/mgmt-pop/apps"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourceApps, map[string]any{})
	diags := dataSourceAppsRead(context.Background(), d, mockClient)

	assert.NotEmpty(t, diags, "expected error diagnostics for 500 response")
}
