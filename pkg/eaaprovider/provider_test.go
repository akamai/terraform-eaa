package eaaprovider

import (
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Retain the existing init block for acceptance tests.
var testAccProviders map[string]func() (*schema.Provider, error)
var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider()
	testAccProviders = map[string]func() (*schema.Provider, error){
		"eaa": func() (*schema.Provider, error) {
			return testAccProvider, nil
		},
	}
}

// ---------------------------------------------------------------------------
// Provider schema
// ---------------------------------------------------------------------------

func TestProvider_SchemaContractID(t *testing.T) {
	p := Provider()
	s, ok := p.Schema["contractid"]
	require.True(t, ok, "contractid must exist in provider schema")
	assert.Equal(t, schema.TypeString, s.Type)
	assert.True(t, s.Required, "contractid must be required")
}

func TestProvider_SchemaAccountSwitchKey(t *testing.T) {
	p := Provider()
	s, ok := p.Schema["accountswitchkey"]
	require.True(t, ok, "accountswitchkey must exist in provider schema")
	assert.Equal(t, schema.TypeString, s.Type)
	assert.True(t, s.Optional, "accountswitchkey must be optional")
	assert.False(t, s.Required)
}

func TestProvider_SchemaEdgerc(t *testing.T) {
	p := Provider()
	s, ok := p.Schema["edgerc"]
	require.True(t, ok, "edgerc must exist in provider schema")
	assert.Equal(t, schema.TypeString, s.Type)
	assert.True(t, s.Optional, "edgerc must be optional")
	assert.False(t, s.Required)
}

// ---------------------------------------------------------------------------
// Provider resources
// ---------------------------------------------------------------------------

func TestProvider_Resources(t *testing.T) {
	p := Provider()
	expectedResources := []string{
		"eaa_application",
		"eaa_connector",
		"eaa_connector_pool",
	}
	for _, name := range expectedResources {
		_, ok := p.ResourcesMap[name]
		assert.True(t, ok, "resource %q must be registered", name)
	}
	assert.Len(t, p.ResourcesMap, len(expectedResources), "unexpected number of resources")
}

// ---------------------------------------------------------------------------
// Provider data sources
// ---------------------------------------------------------------------------

func TestProvider_DataSources(t *testing.T) {
	p := Provider()
	expectedDS := []string{
		"eaa_data_source_pops",
		"eaa_data_source_appcategories",
		"eaa_data_source_agents",
		"eaa_data_source_idps",
		"eaa_data_source_tls_cipher_suites",
		"eaa_connector_pools",
		"eaa_data_source_apps",
	}
	for _, name := range expectedDS {
		_, ok := p.DataSourcesMap[name]
		assert.True(t, ok, "data source %q must be registered", name)
	}
	assert.Len(t, p.DataSourcesMap, len(expectedDS), "unexpected number of data sources")
}

// ---------------------------------------------------------------------------
// Client helper
// ---------------------------------------------------------------------------

func TestClient_Valid(t *testing.T) {
	ec := &client.EaaClient{ContractID: "ctr-123"}
	got, err := Client(ec)
	require.NoError(t, err)
	assert.Same(t, ec, got)
}

func TestClient_InvalidMeta(t *testing.T) {
	_, err := Client("not a client")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client")
}

func TestClient_NilMeta(t *testing.T) {
	_, err := Client(nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Provider internal validate
// ---------------------------------------------------------------------------

func TestProvider_InternalValidation(t *testing.T) {
	p := Provider()
	err := p.InternalValidate()
	assert.NoError(t, err, "provider internal validation must pass")
}
