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

// validateFuncCase holds a single test case for schema.SchemaValidateFunc tests.
type validateFuncCase struct {
	val     interface{}
	wantErr bool
}

// testValidateFunc runs table-driven tests for a schema.SchemaValidateFunc,
// asserting no warnings and checking for expected errors.
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
