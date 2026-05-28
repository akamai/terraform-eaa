package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourcePops — schema validation
// ---------------------------------------------------------------------------

func TestDataSourcePops_ReturnsNonNil(t *testing.T) {
	ds := dataSourcePops()
	require.NotNil(t, ds)
}

func TestDataSourcePops_HasReadContext(t *testing.T) {
	ds := dataSourcePops()
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
}

func TestDataSourcePops_PopsFieldExists(t *testing.T) {
	ds := dataSourcePops()
	_, ok := ds.Schema["pops"]
	assert.True(t, ok, "schema must contain 'pops' field")
}

func TestDataSourcePops_PopsFieldType(t *testing.T) {
	ds := dataSourcePops()
	assert.Equal(t, schema.TypeList, ds.Schema["pops"].Type)
}

func TestDataSourcePops_PopsFieldOptional(t *testing.T) {
	ds := dataSourcePops()
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
