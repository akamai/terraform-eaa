package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceTLSCipherSuites — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceTLSCipherSuites_SchemaBasics(t *testing.T) {
	ds := dataSourceTLSCipherSuites()
	require.NotNil(t, ds)
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
}

func TestDataSourceTLSCipherSuites_TopLevelFields(t *testing.T) {
	ds := dataSourceTLSCipherSuites()

	tests := map[string]struct {
		expectedType schema.ValueType
		required     bool
		computed     bool
	}{
		"app_uuid_url":       {schema.TypeString, true, false},
		"cipher_suites":      {schema.TypeList, false, true},
		"cipher_suite_names": {schema.TypeList, false, true},
		"default_suite_name": {schema.TypeString, false, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := ds.Schema[fieldName]
			require.True(t, exists, "field %q must exist in schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.required, f.Required, "field %q required mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

func TestDataSourceTLSCipherSuites_CipherSuitesElemFields(t *testing.T) {
	ds := dataSourceTLSCipherSuites()
	elem, ok := ds.Schema["cipher_suites"].Elem.(*schema.Resource)
	require.True(t, ok, "cipher_suites Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":          {schema.TypeString, true},
		"default":       {schema.TypeBool, true},
		"selected":      {schema.TypeBool, true},
		"ssl_cipher":    {schema.TypeString, true},
		"ssl_protocols": {schema.TypeString, true},
		"weak_cipher":   {schema.TypeBool, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := elem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in cipher_suites elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

func TestDataSourceTLSCipherSuites_CipherSuiteNamesElemIsString(t *testing.T) {
	ds := dataSourceTLSCipherSuites()
	elem, ok := ds.Schema["cipher_suite_names"].Elem.(*schema.Schema)
	require.True(t, ok, "cipher_suite_names Elem must be *schema.Schema")
	assert.Equal(t, schema.TypeString, elem.Type)
}
