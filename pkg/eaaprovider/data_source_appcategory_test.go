package eaaprovider

import (
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
