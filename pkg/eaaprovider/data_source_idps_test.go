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
// dataSourceIdps — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceIdps_SchemaBasics(t *testing.T) {
	ds := dataSourceIdps()
	assertDataSourceBasics(t, ds, "idps", schema.TypeList)
	assert.True(t, ds.Schema["idps"].Computed, "idps must be computed")
}

func TestDataSourceIdps_ElemFields(t *testing.T) {
	ds := dataSourceIdps()
	elem, ok := ds.Schema["idps"].Elem.(*schema.Resource)
	require.True(t, ok, "idps Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":        {schema.TypeString, true},
		"uuid_url":    {schema.TypeString, true},
		"directories": {schema.TypeList, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := elem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in idps elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

func TestDataSourceIdps_DirectoryElemFields(t *testing.T) {
	ds := dataSourceIdps()
	idpElem := ds.Schema["idps"].Elem.(*schema.Resource)
	dirElem, ok := idpElem.Schema["directories"].Elem.(*schema.Resource)
	require.True(t, ok, "directories Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":   {schema.TypeString, true},
		"uuid":   {schema.TypeString, true},
		"groups": {schema.TypeList, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := dirElem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in directories elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

func TestDataSourceIdps_GroupElemFields(t *testing.T) {
	ds := dataSourceIdps()
	idpElem := ds.Schema["idps"].Elem.(*schema.Resource)
	dirElem := idpElem.Schema["directories"].Elem.(*schema.Resource)
	groupElem, ok := dirElem.Schema["groups"].Elem.(*schema.Resource)
	require.True(t, ok, "groups Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":     {schema.TypeString, true},
		"uuid_url": {schema.TypeString, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := groupElem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in groups elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

// ---------------------------------------------------------------------------
// dataSourceIdpsRead — behavioral tests
// ---------------------------------------------------------------------------

func TestDataSourceIdpsRead_Success(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	// GetIDPS first fetches the IDP list
	mockTransport.Responses["GET /crux/v1/mgmt-pop/idp"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":     "Okta IDP",
					"uuid_url": "urn:idp:okta-1",
				},
			},
		},
	}

	// Then GetIDPDirectories is called for each IDP
	mockTransport.Responses["GET /crux/v1/mgmt-pop/idp/urn:idp:okta-1/directories"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":     "Cloud Directory",
					"uuid_url": "dir-uuid-1",
					"groups": []map[string]interface{}{
						{
							"name":     "Admins",
							"uuid_url": "urn:group:admins",
						},
					},
				},
			},
		},
	}

	d := createTestResourceDataFor(t, dataSourceIdps, map[string]any{})
	diags := dataSourceIdpsRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics")
	assert.Equal(t, "eaa_idps", d.Id())

	idps := d.Get("idps").([]interface{})
	require.Len(t, idps, 1)
	idp := idps[0].(map[string]interface{})
	assert.Equal(t, "Okta IDP", idp["name"])
	assert.Equal(t, "urn:idp:okta-1", idp["uuid_url"])
}

func TestDataSourceIdpsRead_APIError(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/idp"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourceIdps, map[string]any{})
	diags := dataSourceIdpsRead(context.Background(), d, mockClient)

	assert.NotEmpty(t, diags, "expected error diagnostics for 500 response")
}
