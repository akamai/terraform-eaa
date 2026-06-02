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

func requireErr(t *testing.T, err error, wantErr bool) bool {
	t.Helper()
	if wantErr {
		require.Error(t, err)
		return true
	}
	require.NoError(t, err)
	return false
}

func createTestResourceDataFor(t *testing.T, resourceFunc func() *schema.Resource, data map[string]any) *schema.ResourceData {
	t.Helper()
	resource := resourceFunc()
	d := resource.Data(nil)
	for key, value := range data {
		require.NoError(t, d.Set(key, value), "failed to set %q", key)
	}
	return d
}

func stringPtr(s string) *string {
	return &s
}

// validateFuncCase holds a single test case for schema.SchemaValidateFunc tests.
type validateFuncCase struct {
	val     any
	wantErr bool
}

// testValidateFunc runs table-driven tests for a schema.SchemaValidateFunc.
func testValidateFunc(t *testing.T, vf schema.SchemaValidateFunc, fieldName string, tests map[string]validateFuncCase) {
	t.Helper()
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := vf(tc.val, fieldName)
			assert.Empty(t, warns)
			if tc.wantErr {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}
