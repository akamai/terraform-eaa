package eaaprovider

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceEaaConnectorPools — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceEaaConnectorPools_SchemaBasics(t *testing.T) {
	ds := dataSourceEaaConnectorPools()
	assertDataSourceBasics(t, ds, "connector_pools", schema.TypeList)
	assert.True(t, ds.Schema["connector_pools"].Computed, "connector_pools must be computed")
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

// ---------------------------------------------------------------------------
// dataSourceEaaConnectorPoolsRead — behavioral tests
// ---------------------------------------------------------------------------

func TestDataSourceEaaConnectorPoolsRead_Success(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	// The data source calls SendAPIRequest directly with this path
	mockTransport.Responses["GET /crux/v1/mgmt-pop/connector-pools"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":           "pool-alpha",
					"uuid_url":       "urn:pool:alpha",
					"description":    "Test pool",
					"created_at":     "2024-01-01T00:00:00Z",
					"modified_at":    "2024-06-01T00:00:00Z",
					"is_enabled":     true,
					"send_alerts":    false,
					"package_type":   0,
					"infra_type":     0,
					"operating_mode": 0,
				},
			},
			"meta": map[string]interface{}{
				"next":        nil,
				"limit":       20,
				"offset":      0,
				"total_count": 1,
			},
		},
	}

	d := createTestResourceDataFor(t, dataSourceEaaConnectorPools, map[string]any{})
	diags := dataSourceEaaConnectorPoolsRead(context.Background(), d, mockClient)

	assert.Empty(t, diags, "expected no diagnostics")
	assert.Equal(t, "eaa_connector_pools", d.Id())

	pools := d.Get("connector_pools").([]interface{})
	require.Len(t, pools, 1)
	pool := pools[0].(map[string]interface{})
	assert.Equal(t, "pool-alpha", pool["name"])
	assert.Equal(t, "urn:pool:alpha", pool["uuid_url"])
	assert.Equal(t, true, pool["is_enabled"])
}

func TestDataSourceEaaConnectorPoolsRead_APIError(t *testing.T) {
	mockClient, mockTransport := createMockClient(t)

	mockTransport.Responses["GET /crux/v1/mgmt-pop/connector-pools"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourceEaaConnectorPools, map[string]any{})
	diags := dataSourceEaaConnectorPoolsRead(context.Background(), d, mockClient)

	assert.NotEmpty(t, diags, "expected error diagnostics for 500 response")
}
