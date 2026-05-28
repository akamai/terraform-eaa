package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceEaaConnectorPools — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceEaaConnectorPools_ReturnsNonNil(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	require.NotNil(t, ds)
}

func TestDataSourceEaaConnectorPools_HasReadContext(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	assert.NotNil(t, ds.ReadContext, "ReadContext must be set")
}

func TestDataSourceEaaConnectorPools_ConnectorPoolsFieldExists(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	_, ok := ds.Schema["connector_pools"]
	assert.True(t, ok, "schema must contain 'connector_pools' field")
}

func TestDataSourceEaaConnectorPools_ConnectorPoolsFieldComputed(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	assert.True(t, ds.Schema["connector_pools"].Computed, "connector_pools must be computed")
	assert.Equal(t, schema.TypeList, ds.Schema["connector_pools"].Type)
}

func TestDataSourceEaaConnectorPools_PoolElemFields(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	elem, ok := ds.Schema["connector_pools"].Elem.(*schema.Resource)
	require.True(t, ok, "connector_pools Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":                {schema.TypeString, true},
		"description":         {schema.TypeString, true},
		"uuid_url":            {schema.TypeString, true},
		"package_type":        {schema.TypeString, true},
		"infra_type":          {schema.TypeString, true},
		"operating_mode":      {schema.TypeString, true},
		"created_at":          {schema.TypeString, true},
		"modified_at":         {schema.TypeString, true},
		"is_enabled":          {schema.TypeBool, true},
		"send_alerts":         {schema.TypeBool, true},
		"connectors":          {schema.TypeList, true},
		"apps":                {schema.TypeList, true},
		"registration_tokens": {schema.TypeList, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := elem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in connector_pools elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

func TestDataSourceEaaConnectorPools_ConnectorElemFields(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	poolElem := ds.Schema["connector_pools"].Elem.(*schema.Resource)
	connElem, ok := poolElem.Schema["connectors"].Elem.(*schema.Resource)
	require.True(t, ok, "connectors Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"name":             {schema.TypeString, true},
		"package":          {schema.TypeInt, true},
		"state":            {schema.TypeInt, true},
		"status":           {schema.TypeInt, true},
		"uuid_url":         {schema.TypeString, true},
		"created_at":       {schema.TypeString, true},
		"description":      {schema.TypeString, true},
		"load_status":      {schema.TypeString, true},
		"localization":     {schema.TypeString, true},
		"reach":            {schema.TypeInt, true},
		"agent_infra_type": {schema.TypeInt, true},
		"geo_location":     {schema.TypeString, true},
		"last_checkin":     {schema.TypeString, true},
		"is_enabled":       {schema.TypeBool, true},
		"modified_at":      {schema.TypeString, true},
		"resource_uri":     {schema.TypeString, true},
		"operating_mode":   {schema.TypeString, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := connElem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in connectors elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}

func TestDataSourceEaaConnectorPools_RegistrationTokenElemFields(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	poolElem := ds.Schema["connector_pools"].Elem.(*schema.Resource)
	tokenElem, ok := poolElem.Schema["registration_tokens"].Elem.(*schema.Resource)
	require.True(t, ok, "registration_tokens Elem must be *schema.Resource")

	tests := map[string]struct {
		expectedType schema.ValueType
		computed     bool
	}{
		"uuid_url":              {schema.TypeString, true},
		"name":                  {schema.TypeString, true},
		"max_use":               {schema.TypeInt, true},
		"connector_pool":        {schema.TypeString, true},
		"agents":                {schema.TypeList, true},
		"expires_at":            {schema.TypeString, true},
		"image_url":             {schema.TypeString, true},
		"token":                 {schema.TypeString, true},
		"used_count":            {schema.TypeInt, true},
		"token_suffix":          {schema.TypeString, true},
		"modified_at":           {schema.TypeString, true},
		"generate_embedded_img": {schema.TypeBool, true},
	}

	for fieldName, tc := range tests {
		t.Run(fieldName, func(t *testing.T) {
			f, exists := tokenElem.Schema[fieldName]
			require.True(t, exists, "field %q must exist in registration_tokens elem schema", fieldName)
			assert.Equal(t, tc.expectedType, f.Type, "field %q type mismatch", fieldName)
			assert.Equal(t, tc.computed, f.Computed, "field %q computed mismatch", fieldName)
		})
	}
}
