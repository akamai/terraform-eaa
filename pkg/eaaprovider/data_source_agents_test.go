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
