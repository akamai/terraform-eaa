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

func TestDataSourceAppCategories_ReturnsNonNil(t *testing.T) {
	ds := dataSourceAppCategories()
	require.NotNil(t, ds)
}

func TestDataSourceAppCategories_HasReadContext(t *testing.T) {
	ds := dataSourceAppCategories()
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
}

func TestDataSourceAppCategories_AppcategoriesFieldExists(t *testing.T) {
	ds := dataSourceAppCategories()
	_, ok := ds.Schema["appcategories"]
	assert.True(t, ok, "schema must contain 'appcategories' field")
}

func TestDataSourceAppCategories_AppcategoriesFieldType(t *testing.T) {
	ds := dataSourceAppCategories()
	assert.Equal(t, schema.TypeList, ds.Schema["appcategories"].Type)
}

func TestDataSourceAppCategories_AppcategoriesFieldComputed(t *testing.T) {
	ds := dataSourceAppCategories()
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
