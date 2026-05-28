package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceIdps — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceIdps_ReturnsNonNil(t *testing.T) {
	ds := dataSourceIdps()
	require.NotNil(t, ds)
}

func TestDataSourceIdps_HasReadContext(t *testing.T) {
	ds := dataSourceIdps()
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
}

func TestDataSourceIdps_IdpsFieldExists(t *testing.T) {
	ds := dataSourceIdps()
	_, ok := ds.Schema["idps"]
	assert.True(t, ok, "schema must contain 'idps' field")
}

func TestDataSourceIdps_IdpsFieldType(t *testing.T) {
	ds := dataSourceIdps()
	assert.Equal(t, schema.TypeList, ds.Schema["idps"].Type)
}

func TestDataSourceIdps_IdpsFieldComputed(t *testing.T) {
	ds := dataSourceIdps()
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
