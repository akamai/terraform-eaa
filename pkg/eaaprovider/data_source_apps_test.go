package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceApps — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceApps_ReturnsNonNil(t *testing.T) {
	ds := dataSourceApps()
	require.NotNil(t, ds)
}

func TestDataSourceApps_HasReadContext(t *testing.T) {
	ds := dataSourceApps()
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
}

func TestDataSourceApps_AppsFieldExists(t *testing.T) {
	ds := dataSourceApps()
	_, ok := ds.Schema["apps"]
	assert.True(t, ok, "schema must contain 'apps' field")
}

func TestDataSourceApps_AppsFieldComputed(t *testing.T) {
	ds := dataSourceApps()
	assert.True(t, ds.Schema["apps"].Computed, "apps must be computed")
	assert.Equal(t, schema.TypeList, ds.Schema["apps"].Type)
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
