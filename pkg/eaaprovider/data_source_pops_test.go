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
// dataSourcePops — schema validation
// ---------------------------------------------------------------------------

func TestDataSourcePops_SchemaBasics(t *testing.T) {
	ds := dataSourcePops()
	assertDataSourceBasics(t, ds, "pops", schema.TypeList)
	assert.True(t, ds.Schema["pops"].Optional)
}

func TestDataSourcePops_ElemFields(t *testing.T) {
	ds := dataSourcePops()
	elem, ok := ds.Schema["pops"].Elem.(*schema.Resource)
	require.True(t, ok, "pops Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
	}{
		"region":                {schema.TypeString},
		"description":           {schema.TypeString},
		"facility":              {schema.TypeString},
		"name":                  {schema.TypeString},
		"pop_category":          {schema.TypeList},
		"pop_type":              {schema.TypeString},
		"related_failover_pop":  {schema.TypeString},
		"related_failover_name": {schema.TypeString},
		"uuid_url":              {schema.TypeString},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := elem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in pops elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
		})
	}
}

func TestDataSourcePops_RegionFieldRequired(t *testing.T) {
	ds := dataSourcePops()
	elem := ds.Schema["pops"].Elem.(*schema.Resource)
	assert.True(t, elem.Schema["region"].Required, "region must be required")
}

// ---------------------------------------------------------------------------
// dataSourcePopsRead — behavioral tests
// ---------------------------------------------------------------------------

func TestDataSourcePopsRead_Success(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	// GetPops uses global=true, so the URL has ?shared=true but no contractId params.
	// The mock transport matches on "METHOD /path" pattern.
	mockTransport.Responses["GET /crux/v1/mgmt-pop/pops"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"region":                    "US-East",
					"description":               "East coast POP",
					"facility":                  "IAD",
					"name":                      "pop-iad",
					"pop_category":              []string{"enterprise"},
					"pop_type":                  "primary",
					"related_failover_pop":      "urn:pop:sjc",
					"related_failover_pop_name": "pop-sjc",
					"uuid_url":                  "urn:pop:iad",
				},
			},
		},
	}

	d := createTestResourceDataFor(t, dataSourcePops, map[string]any{})
	diags := dataSourcePopsRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics")
	assert.Equal(t, "eaa_pops", d.Id())

	pops := d.Get("pops").([]interface{})
	require.Len(t, pops, 1)
	pop := pops[0].(map[string]interface{})
	assert.Equal(t, "pop-iad", pop["name"])
	assert.Equal(t, "US-East", pop["region"])
	assert.Equal(t, "urn:pop:iad", pop["uuid_url"])
}

func TestDataSourcePopsRead_APIError(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/pops"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourcePops, map[string]any{})
	diags := dataSourcePopsRead(context.Background(), d, mockClient)

	assert.NotEmpty(t, diags, "expected error diagnostics for 500 response")
}
