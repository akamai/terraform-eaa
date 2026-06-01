package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertDataSourceBasics(t *testing.T, ds *schema.Resource, fieldName string, fieldType schema.ValueType) {
	t.Helper()
	require.NotNil(t, ds)
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
	f, ok := ds.Schema[fieldName]
	require.True(t, ok, "schema must contain %q field", fieldName)
	assert.Equal(t, fieldType, f.Type, "field %q type mismatch", fieldName)
}
