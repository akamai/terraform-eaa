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
// dataSourceAgents — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceAgents_SchemaBasics(t *testing.T) {
	ds := dataSourceAgents()
	assertDataSourceBasics(t, ds, "agents", schema.TypeList)
	assert.True(t, ds.Schema["agents"].Optional)
}

func TestDataSourceAgents_ElemFields(t *testing.T) {
	ds := dataSourceAgents()
	elem, ok := ds.Schema["agents"].Elem.(*schema.Resource)
	require.True(t, ok, "agents Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
	}{
		"name":                    {schema.TypeString},
		"reach":                   {schema.TypeInt},
		"state":                   {schema.TypeInt},
		"os_version":              {schema.TypeString},
		"public_ip":               {schema.TypeString},
		"private_ip":              {schema.TypeString},
		"type":                    {schema.TypeInt},
		"region":                  {schema.TypeString},
		"uuid":                    {schema.TypeString},
		"uuid_url":                {schema.TypeString},
		"connector_pool_uuid_url": {schema.TypeString},
		"connector_pool_name":     {schema.TypeString},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := elem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in agents elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
		})
	}
}

func TestDataSourceAgents_NameFieldRequired(t *testing.T) {
	ds := dataSourceAgents()
	elem := ds.Schema["agents"].Elem.(*schema.Resource)
	assert.True(t, elem.Schema["name"].Required, "name must be required")
}

// ---------------------------------------------------------------------------
// dataSourceAgentsRead — behavioral tests
// ---------------------------------------------------------------------------

func TestDataSourceAgentsRead_Success(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/agents"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":       "connector-1",
					"uuid":       "uuid-1",
					"uuid_url":   "urn:connector:uuid-1",
					"reach":      1,
					"state":      1,
					"os_version": "Ubuntu 22.04",
					"public_ip":  "1.2.3.4",
					"private_ip": "10.0.0.1",
					"agent_type": 1,
					"region":     "us-east-1",
					"connector_pool": map[string]interface{}{
						"uuid_url": "urn:pool:pool-1",
						"name":     "pool-1",
					},
				},
			},
		},
	}

	d := createTestResourceDataFor(t, dataSourceAgents, map[string]any{})
	diags := dataSourceAgentsRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics")
	assert.Equal(t, "eaa_agents", d.Id())

	agents := d.Get("agents").([]interface{})
	require.Len(t, agents, 1)
	agent := agents[0].(map[string]interface{})
	assert.Equal(t, "connector-1", agent["name"])
	assert.Equal(t, "urn:connector:uuid-1", agent["uuid_url"])
	assert.Equal(t, "urn:pool:pool-1", agent["connector_pool_uuid_url"])
}

func TestDataSourceAgentsRead_APIError(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/agents"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourceAgents, map[string]any{})
	diags := dataSourceAgentsRead(context.Background(), d, mockClient)

	assert.NotEmpty(t, diags, "expected error diagnostics for 500 response")
}
