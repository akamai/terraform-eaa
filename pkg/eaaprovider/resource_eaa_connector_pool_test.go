package eaaprovider

import (
	"context"
	"strings"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestResourceData(t *testing.T, data map[string]any) *schema.ResourceData {
	t.Helper()
	return createTestResourceDataFor(t, resourceEaaConnectorPool, data)
}

// ===========================================================================
// validatePackageType
// ===========================================================================

func TestValidatePackageType(t *testing.T) {
	testValidateFunc(t, validatePackageType, "package_type", map[string]validateFuncCase{
		"valid_vmware":      {val: string(client.ConnPackageTypeVmware)},
		"valid_vbox":        {val: string(client.ConnPackageTypeVbox)},
		"valid_aws":         {val: string(client.ConnPackageTypeAWS)},
		"valid_aws_classic": {val: string(client.ConnPackageTypeAWSClassic)},
		"valid_kvm":         {val: string(client.ConnPackageTypeKVM)},
		"valid_hyperv":      {val: string(client.ConnPackageTypeHyperv)},
		"valid_docker":      {val: string(client.ConnPackageTypeDocker)},
		"valid_azure":       {val: string(client.ConnPackageTypeAzure)},
		"valid_google":      {val: string(client.ConnPackageTypeGoogle)},
		"valid_softlayer":   {val: string(client.ConnPackageTypeSoftLayer)},
		"valid_fujitsu_k5":  {val: string(client.ConnPackageTypeFujitsu_k5)},
		"invalid_type":      {val: "invalid", wantErr: true},
		"invalid_casing":    {val: "VMware", wantErr: true},
		"empty_string":      {val: "", wantErr: true},
		"non_string":        {val: 123, wantErr: true},
		"nil_value":         {val: nil, wantErr: true},
	})
}

// ===========================================================================
// validateInfraType
// ===========================================================================

func TestValidateInfraType(t *testing.T) {
	testValidateFunc(t, validateInfraType, "infra_type", map[string]validateFuncCase{
		"valid_eaa":      {val: string(client.InfraTypeEAA)},
		"valid_unified":  {val: string(client.InfraTypeUnified)},
		"valid_broker":   {val: string(client.InfraTypeBroker)},
		"valid_cpag":     {val: string(client.InfraTypeCPAG)},
		"invalid_type":   {val: "invalid", wantErr: true},
		"invalid_casing": {val: "EAA", wantErr: true},
		"empty_string":   {val: "", wantErr: true},
		"whitespace":     {val: " eaa ", wantErr: true},
		"non_string":     {val: 123, wantErr: true},
		"nil_value":      {val: nil, wantErr: true},
	})
}

// ===========================================================================
// validateOperatingMode
// ===========================================================================

func TestValidateOperatingMode(t *testing.T) {
	testValidateFunc(t, validateOperatingMode, "operating_mode", map[string]validateFuncCase{
		"valid_connector":                  {val: string(client.OperatingModeConnector)},
		"valid_peb":                        {val: string(client.OperatingModePEB)},
		"valid_combined":                   {val: string(client.OperatingModeCombined)},
		"valid_cpag_public":                {val: string(client.OperatingModeCPAGPublic)},
		"valid_cpag_private":               {val: string(client.OperatingModeCPAGPrivate)},
		"valid_connector_with_china_accel": {val: string(client.OperatingModeConnectorWithChinaAccel)},
		"invalid_mode":                     {val: "invalid", wantErr: true},
		"invalid_casing":                   {val: "Connector", wantErr: true},
		"empty_string":                     {val: "", wantErr: true},
		"whitespace":                       {val: " connector ", wantErr: true},
		"non_string":                       {val: 123, wantErr: true},
		"nil_value":                        {val: nil, wantErr: true},
	})
}

// ===========================================================================
// validateRFC3339Timestamp
// ===========================================================================

func TestValidateRFC3339Timestamp(t *testing.T) {
	testValidateFunc(t, validateRFC3339Timestamp, "expires_at", map[string]validateFuncCase{
		"valid_utc":             {val: "2026-01-02T15:04:05Z"},
		"valid_offset":          {val: "2026-01-02T15:04:05+05:30"},
		"valid_fractional_secs": {val: "2026-01-02T15:04:05.123Z"},
		"invalid_date_only":     {val: "2026-01-02", wantErr: true},
		"invalid_format":        {val: "2026-01-02 15:04:05", wantErr: true},
		"empty_string":          {val: "", wantErr: true},
		"non_string":            {val: 12345, wantErr: true},
	})
}

// ===========================================================================
// suppressRFC3339Diff
// ===========================================================================

func TestSuppressRFC3339Diff(t *testing.T) {
	tests := map[string]struct {
		oldVal string
		newVal string
		want   bool
	}{
		"same_instant_different_tz": {
			oldVal: "2026-05-20T10:00:00Z",
			newVal: "2026-05-20T12:00:00+02:00",
			want:   true,
		},
		"different_times": {
			oldVal: "2026-05-20T10:00:01Z",
			newVal: "2026-05-20T10:00:02Z",
			want:   false,
		},
		"zero_seconds_suppressed": {
			oldVal: "2026-05-20T10:00:01Z",
			newVal: "2026-05-20T10:00:00Z",
			want:   true,
		},
		"malformed_input": {
			oldVal: "not-a-time",
			newVal: "2026-05-20T10:00:00Z",
			want:   false,
		},
		"fractional_seconds_equal": {
			oldVal: "2026-05-20T10:00:00.123Z",
			newVal: "2026-05-20T10:00:00.123+00:00",
			want:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := suppressRFC3339Diff("expires_at", tc.oldVal, tc.newVal, nil)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ===========================================================================
// hasDuplicateTokenNames
// ===========================================================================

func TestHasDuplicateTokenNames(t *testing.T) {
	tests := map[string]struct {
		data    map[string]interface{}
		wantErr bool
	}{
		"no_duplicates": {
			data: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token2"},
					{"name": "token3"},
				},
			},
			wantErr: false,
		},
		"with_duplicates": {
			data: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "token1"},
					{"name": "token1"},
				},
			},
			wantErr: true,
		},
		"empty_tokens": {
			data: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{},
			},
			wantErr: false,
		},
		"single_token": {
			data: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "only-one"},
				},
			},
			wantErr: false,
		},
		"case_sensitive": {
			data: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": "Token1"},
					{"name": "token1"},
				},
			},
			wantErr: false, // different case => not duplicate
		},
		"empty_names_are_duplicates": {
			data: map[string]interface{}{
				"registration_tokens": []map[string]interface{}{
					{"name": ""},
					{"name": ""},
				},
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestResourceData(t, tc.data)
			err := hasDuplicateTokenNames(d)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "duplicate registration token name found")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ===========================================================================
// Schema structure
// ===========================================================================

func TestResourceEaaConnectorPoolSchema(t *testing.T) {
	resource := resourceEaaConnectorPool()

	expectedFields := []string{
		"name", "package_type", "description", "infra_type",
		"operating_mode", "uuid_url", "connectors",
		"registration_tokens", "apps", "cidrs",
	}
	for _, field := range expectedFields {
		_, ok := resource.Schema[field]
		assert.True(t, ok, "expected schema field %q to exist", field)
	}

	// Required fields
	assert.True(t, resource.Schema["name"].Required)
	assert.True(t, resource.Schema["package_type"].Required)

	// Optional/computed fields
	assert.False(t, resource.Schema["description"].Required)
	assert.False(t, resource.Schema["infra_type"].Required)
	assert.True(t, resource.Schema["infra_type"].Computed)
	assert.False(t, resource.Schema["operating_mode"].Required)
	assert.True(t, resource.Schema["operating_mode"].Computed)

	// Validation funcs
	assert.NotNil(t, resource.Schema["package_type"].ValidateFunc)
	assert.NotNil(t, resource.Schema["infra_type"].ValidateFunc)
	assert.NotNil(t, resource.Schema["operating_mode"].ValidateFunc)

	// CRUD operations
	assert.NotNil(t, resource.CreateContext)
	assert.NotNil(t, resource.ReadContext)
	assert.NotNil(t, resource.UpdateContext)
	assert.NotNil(t, resource.DeleteContext)

	// Importer
	require.NotNil(t, resource.Importer)
	assert.NotNil(t, resource.Importer.StateContext)
}

// ===========================================================================
// CRUD error paths (client creation fails)
// ===========================================================================

func TestResourceEaaConnectorPoolCreate_InvalidClient(t *testing.T) {
	d := createTestResourceData(t, map[string]interface{}{
		"name":         "pool",
		"package_type": "vmware",
	})
	diags := resourceEaaConnectorPoolCreate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaConnectorPoolCreate_AWSClassicBlocked(t *testing.T) {
	d := createTestResourceData(t, map[string]interface{}{
		"name":         "pool",
		"package_type": "aws_classic",
	})
	diags := resourceEaaConnectorPoolCreate(context.Background(), d, "invalid")
	require.NotEmpty(t, diags)
	found := false
	for _, diag := range diags {
		if strings.Contains(diag.Summary, "aws_classic") {
			found = true
		}
	}
	assert.True(t, found, "expected aws_classic rejection diagnostic")
}

func TestResourceEaaConnectorPoolCreate_DuplicateTokensBlocked(t *testing.T) {
	d := createTestResourceData(t, map[string]interface{}{
		"name":         "pool",
		"package_type": "vmware",
		"registration_tokens": []map[string]interface{}{
			{"name": "dup"},
			{"name": "dup"},
		},
	})
	diags := resourceEaaConnectorPoolCreate(context.Background(), d, "invalid")
	require.NotEmpty(t, diags)
	found := false
	for _, diag := range diags {
		if strings.Contains(diag.Summary, "duplicate") || strings.Contains(diag.Detail, "duplicate") {
			found = true
		}
	}
	assert.True(t, found, "expected duplicate token name diagnostic")
}

func TestResourceEaaConnectorPoolRead_InvalidClient(t *testing.T) {
	d := createTestResourceData(t, map[string]interface{}{})
	diags := resourceEaaConnectorPoolRead(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaConnectorPoolUpdate_InvalidClient(t *testing.T) {
	d := createTestResourceData(t, map[string]interface{}{
		"name":         "pool",
		"package_type": "vmware",
	})
	diags := resourceEaaConnectorPoolUpdate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaConnectorPoolDelete_InvalidClient(t *testing.T) {
	d := createTestResourceData(t, map[string]interface{}{})
	diags := resourceEaaConnectorPoolDelete(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

// ===========================================================================
// setConnectorPoolBasicAttributes
// ===========================================================================

func TestSetConnectorPoolBasicAttributes(t *testing.T) {
	tests := map[string]struct {
		connPool    *client.ConnectorPool
		expectedMap map[string]interface{}
	}{
		"full_pool": {
			connPool: &client.ConnectorPool{
				Name:          "test-pool",
				Description:   stringPtr("desc"),
				PackageType:   1,
				InfraType:     1,
				OperatingMode: 1,
				UUIDURL:       "uuid-123",
				CIDRs:         []string{"10.0.0.0/8"},
			},
			expectedMap: map[string]interface{}{
				"name":           "test-pool",
				"description":    "desc",
				"package_type":   "vmware",
				"infra_type":     "eaa",
				"operating_mode": "connector",
				"uuid_url":       "uuid-123",
			},
		},
		"nil_description": {
			connPool: &client.ConnectorPool{
				Name:          "pool-2",
				Description:   nil,
				PackageType:   2,
				InfraType:     1,
				OperatingMode: 1,
				UUIDURL:       "uuid-456",
			},
			expectedMap: map[string]interface{}{
				"name":           "pool-2",
				"description":    "",
				"package_type":   "vbox",
				"infra_type":     "eaa",
				"operating_mode": "connector",
				"uuid_url":       "uuid-456",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestResourceData(t, map[string]interface{}{})
			setConnectorPoolBasicAttributes(d, tc.connPool)

			for key, expected := range tc.expectedMap {
				assert.Equal(t, expected, d.Get(key), "mismatch for key %s", key)
			}
		})
	}
}
