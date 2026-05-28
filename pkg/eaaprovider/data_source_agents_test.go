package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceAgents — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceAgents_ReturnsNonNil(t *testing.T) {
	ds := dataSourceAgents()
	require.NotNil(t, ds)
}

func TestDataSourceAgents_HasReadContext(t *testing.T) {
	ds := dataSourceAgents()
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
}

func TestDataSourceAgents_AgentsFieldExists(t *testing.T) {
	ds := dataSourceAgents()
	_, ok := ds.Schema["agents"]
	assert.True(t, ok, "schema must contain 'agents' field")
}

func TestDataSourceAgents_AgentsFieldType(t *testing.T) {
	ds := dataSourceAgents()
	assert.Equal(t, schema.TypeList, ds.Schema["agents"].Type)
}

func TestDataSourceAgents_AgentsFieldOptional(t *testing.T) {
	ds := dataSourceAgents()
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
