package client

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

// TestValidateRequiredString tests ValidateRequiredString utility
func TestValidateRequiredString(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := &EaaClient{Logger: logger}
	testSchema := map[string]*schema.Schema{
		"required_field": {
			Type:     schema.TypeString,
			Required: true,
		},
	}
	tests := []struct {
		name      string
		data      map[string]interface{}
		fieldName string
		want      string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid required string",
			data:      map[string]interface{}{"required_field": "test_value"},
			fieldName: "required_field",
			want:      "test_value",
			wantErr:   false,
		},
		{
			name:      "missing required field",
			data:      map[string]interface{}{},
			fieldName: "required_field",
			want:      "",
			wantErr:   true,
			errMsg:    "required but missing",
		},
		{
			name:      "empty string",
			data:      map[string]interface{}{"required_field": ""},
			fieldName: "required_field",
			want:      "",
			wantErr:   true,
			errMsg:    "required but missing",
		},
		{
			name:      "wrong type - schema validation prevents this",
			data:      map[string]interface{}{"required_field": "123"},
			fieldName: "required_field",
			want:      "123",
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &schema.Resource{Schema: testSchema}
			d := resource.Data(nil)
			for k, v := range tt.data {
				d.Set(k, v)
			}
			result, err := ValidateRequiredString(d, tt.fieldName, client)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Equal(t, "", result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

// TestValidateOptionalString tests ValidateOptionalString utility
func TestValidateOptionalString(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := &EaaClient{Logger: logger}
	testSchema := map[string]*schema.Schema{
		"optional_field": {
			Type:     schema.TypeString,
			Optional: true,
		},
	}
	tests := []struct {
		name      string
		data      map[string]interface{}
		fieldName string
		want      string
		wantErr   bool
	}{
		{
			name:      "valid optional string",
			data:      map[string]interface{}{"optional_field": "test_value"},
			fieldName: "optional_field",
			want:      "test_value",
			wantErr:   false,
		},
		{
			name:      "missing optional field",
			data:      map[string]interface{}{},
			fieldName: "optional_field",
			want:      "",
			wantErr:   false,
		},
		{
			name:      "empty string",
			data:      map[string]interface{}{"optional_field": ""},
			fieldName: "optional_field",
			want:      "",
			wantErr:   false,
		},
		{
			name:      "wrong type - schema validation prevents this",
			data:      map[string]interface{}{"optional_field": "123"},
			fieldName: "optional_field",
			want:      "123",
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &schema.Resource{Schema: testSchema}
			d := resource.Data(nil)
			for k, v := range tt.data {
				d.Set(k, v)
			}
			result, err := ValidateOptionalString(d, tt.fieldName, client)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "", result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

// TestSetAttrs tests SetAttrs utility
func TestSetAttrs(t *testing.T) {
	testSchema := map[string]*schema.Schema{
		"attr1": {Type: schema.TypeString},
		"attr2": {Type: schema.TypeInt},
		"attr3": {Type: schema.TypeBool},
	}
	tests := []struct {
		name            string
		attributeValues map[string]interface{}
		wantErr         bool
	}{
		{
			name:            "set multiple attributes",
			attributeValues: map[string]interface{}{"attr1": "value1", "attr2": 42, "attr3": true},
			wantErr:         false,
		},
		{
			name:            "set single attribute",
			attributeValues: map[string]interface{}{"attr1": "value1"},
			wantErr:         false,
		},
		{
			name:            "empty attributes",
			attributeValues: map[string]interface{}{},
			wantErr:         false,
		},
		{
			name:            "nil value",
			attributeValues: map[string]interface{}{"attr1": nil},
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &schema.Resource{Schema: testSchema}
			d := resource.Data(nil)
			err := SetAttrs(d, tt.attributeValues)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				for key, expectedValue := range tt.attributeValues {
					actualValue := d.Get(key)
					if expectedValue != nil {
						assert.Equal(t, expectedValue, actualValue)
					}
				}
			}
		})
	}
}

// TestConvertConnectorsToObjects tests ConvertConnectorsToObjects utility
func TestConvertConnectorsToObjects(t *testing.T) {
	tests := []struct {
		name       string
		connectors json.RawMessage
		wantLen    int
		checkFirst func(*testing.T, []ConnectorSummary)
	}{
		{
			name:       "valid connector objects",
			connectors: json.RawMessage(`[{"name":"conn1","package":1,"state":2,"uuid_url":"uuid1"},{"name":"conn2","package":2,"uuid_url":"uuid2"}]`),
			wantLen:    2,
			checkFirst: func(t *testing.T, result []ConnectorSummary) {
				assert.Equal(t, "conn1", result[0].Name)
				assert.Equal(t, 1, result[0].Package)
				assert.Equal(t, "uuid1", result[0].UUIDURL)
			},
		},
		{
			name:       "empty array",
			connectors: json.RawMessage(`[]`),
			wantLen:    0,
		},
		{
			name:       "null value",
			connectors: json.RawMessage(`null`),
			wantLen:    0,
		},
		{
			name:       "empty raw message",
			connectors: json.RawMessage(``),
			wantLen:    0,
		},
		{
			name:       "invalid JSON",
			connectors: json.RawMessage(`not json`),
			wantLen:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertConnectorsToObjects(tt.connectors)
			assert.Len(t, result, tt.wantLen)
			if tt.checkFirst != nil && len(result) > 0 {
				tt.checkFirst(t, result)
			}
		})
	}
}

// TestConvertConnectorsToMap tests ConvertConnectorsToMap utility
func TestConvertConnectorsToMap(t *testing.T) {
	tests := []struct {
		name       string
		connectors json.RawMessage
		wantLen    int
		checkFirst func(*testing.T, []map[string]interface{})
	}{
		{
			name:       "valid connector objects",
			connectors: json.RawMessage(`[{"name":"conn1","package":1,"uuid_url":"uuid1"}]`),
			wantLen:    1,
			checkFirst: func(t *testing.T, result []map[string]interface{}) {
				assert.Equal(t, "conn1", result[0]["name"])
				assert.Equal(t, 1, result[0]["package"])
				assert.Equal(t, "uuid1", result[0]["uuid_url"])
			},
		},
		{
			name:       "empty array",
			connectors: json.RawMessage(`[]`),
			wantLen:    0,
		},
		{
			name:       "null value",
			connectors: json.RawMessage(`null`),
			wantLen:    0,
		},
		{
			name:       "invalid JSON",
			connectors: json.RawMessage(`not json`),
			wantLen:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertConnectorsToMap(tt.connectors)
			assert.Len(t, result, tt.wantLen)
			if tt.checkFirst != nil && len(result) > 0 {
				tt.checkFirst(t, result)
			}
		})
	}
}

// TestUpdateAdvancedSettings tests UpdateAdvancedSettings utility
func TestUpdateAdvancedSettings(t *testing.T) {
	tests := []struct {
		name     string
		complete *AdvancedSettings_Complete
		delta    AdvancedSettings
		check    func(*testing.T, *AdvancedSettings_Complete)
	}{
		{
			name: "update string field",
			complete: &AdvancedSettings_Complete{
				AppAuth:  "none",
				WappAuth: "form",
			},
			delta: AdvancedSettings{
				AppAuth: "kerberos",
				WappAuth: "form",
			},
			check: func(t *testing.T, result *AdvancedSettings_Complete) {
				assert.Equal(t, "kerberos", result.AppAuth)
				assert.Equal(t, "form", result.WappAuth)
			},
		},
		{
			name: "update pointer field (AppAuthDomain - AdvancedSettings uses *string)",
			complete: &AdvancedSettings_Complete{
				AppAuthDomain: "",
			},
			delta: AdvancedSettings{
				AppAuthDomain: stringPtr("example.com"),
			},
			check: func(t *testing.T, result *AdvancedSettings_Complete) {
				assert.Equal(t, "example.com", result.AppAuthDomain)
			},
		},
		{
			name: "update slice field",
			complete: &AdvancedSettings_Complete{
				CustomHeaders: []CustomHeader{},
			},
			delta: AdvancedSettings{
				CustomHeaders: []CustomHeader{
					{Header: "X-Header", AttributeType: "user"},
				},
			},
			check: func(t *testing.T, result *AdvancedSettings_Complete) {
				assert.Len(t, result.CustomHeaders, 1)
				assert.Equal(t, "X-Header", result.CustomHeaders[0].Header)
			},
		},
		{
			name: "update multiple fields",
			complete: &AdvancedSettings_Complete{
				AppAuth:             "none",
				WappAuth:            "form",
				HealthCheckInterval: "30000",
			},
			delta: AdvancedSettings{
				AppAuth:             "oidc",
				WappAuth:            "form",
				HealthCheckInterval: "60000",
			},
			check: func(t *testing.T, result *AdvancedSettings_Complete) {
				assert.Equal(t, "oidc", result.AppAuth)
				assert.Equal(t, "form", result.WappAuth)
				assert.Equal(t, "60000", result.HealthCheckInterval)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UpdateAdvancedSettings(tt.complete, tt.delta)
			if tt.check != nil {
				tt.check(t, tt.complete)
			}
		})
	}
}
