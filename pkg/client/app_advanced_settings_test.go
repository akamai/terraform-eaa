package client

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SetAdvancedSettings
// ---------------------------------------------------------------------------

func TestSetAdvancedSettings_NilSettings(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"advanced_settings": {
			Type:     schema.TypeMap,
			Optional: true,
		},
	}
	d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{})

	err := SetAdvancedSettings(d, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "advanced settings cannot be nil")
}

// ---------------------------------------------------------------------------
// ParseAdvancedSettingsWithDefaults
// ---------------------------------------------------------------------------

func TestParseAdvancedSettingsWithDefaults_EmptyJSON(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{}`)
	require.NoError(t, err)

	// Verify several important defaults
	assert.Equal(t, string(DefaultCORSSupportCredential), advSettings.CORSSupportCredential)
	assert.Nil(t, advSettings.ExternalCookieDomain)
	assert.Equal(t, string(DefaultIsSSLVerificationEnabled), advSettings.IsSSLVerificationEnabled)
	assert.Equal(t, string(DefaultKeepAliveTimeout), advSettings.KeepaliveTimeout)
	assert.Equal(t, string(DefaultSingleHostCookieDomain), advSettings.SingleHostCookieDomain)
	assert.Equal(t, string(DefaultAcceleration), advSettings.Acceleration)
	assert.Equal(t, string(DefaultAppAuth), advSettings.AppAuth)
	assert.Equal(t, "round-robin", advSettings.LoadBalancingMetric)
	assert.Equal(t, "50", advSettings.AnonymousServerConnLimit)
	assert.Equal(t, "100", advSettings.AnonymousServerReqLimit)
	assert.Equal(t, FlexString("60"), advSettings.AppServerReadTimeout)
}

func TestParseAdvancedSettingsWithDefaults_EnterpriseHTTPApp(t *testing.T) {
	input := `{
		"acceleration": "true",
		"app_auth": "none",
		"load_balancing_metric": "weighted-round-robin",
		"health_check_type": "0",
		"websocket_enabled": "true"
	}`

	advSettings, err := ParseAdvancedSettingsWithDefaults(input)
	require.NoError(t, err)

	assert.Equal(t, "true", advSettings.Acceleration)
	assert.Equal(t, "none", advSettings.AppAuth)
	assert.Equal(t, "weighted-round-robin", advSettings.LoadBalancingMetric)
	assert.Equal(t, "0", advSettings.HealthCheckType)
	assert.Equal(t, "true", advSettings.WebSocketEnabled)
	// Other defaults should still be applied
	assert.Equal(t, "50", advSettings.AnonymousServerConnLimit)
}

func TestParseAdvancedSettingsWithDefaults_TunnelApp(t *testing.T) {
	input := `{
		"app_auth": "none",
		"internal_host_port": "8080",
		"wildcard_internal_hostname": "*.example.com"
	}`

	advSettings, err := ParseAdvancedSettingsWithDefaults(input)
	require.NoError(t, err)

	assert.Equal(t, "none", advSettings.AppAuth)
	assert.Equal(t, "8080", advSettings.InternalHostPort)
	assert.Equal(t, "*.example.com", advSettings.WildcardInternalHostname)
}

func TestParseAdvancedSettingsWithDefaults_SaaSApp(t *testing.T) {
	input := `{
		"saas_enabled": "true",
		"app_auth": "oidc",
		"single_host_enable": "true",
		"single_host_fqdn": "app.saas.example.com"
	}`

	advSettings, err := ParseAdvancedSettingsWithDefaults(input)
	require.NoError(t, err)

	assert.Equal(t, "true", advSettings.SaaSEnabled)
	assert.Equal(t, "oidc", advSettings.AppAuth)
	assert.Equal(t, "true", advSettings.SingleHostEnable)
	assert.Equal(t, "app.saas.example.com", advSettings.SingleHostFQDN)
}

func TestParseAdvancedSettingsWithDefaults_InvalidJSON(t *testing.T) {
	_, err := ParseAdvancedSettingsWithDefaults(`{not json}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestParseAdvancedSettingsWithDefaults_InvalidHealthCheckType(t *testing.T) {
	_, err := ParseAdvancedSettingsWithDefaults(`{"health_check_type":"99"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid health_check_type")
}

func TestParseAdvancedSettingsWithDefaults_PointerStringFields(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{
		"external_cookie_domain": "",
		"login_url": null,
		"user_name": "alice"
	}`)
	require.NoError(t, err)

	require.NotNil(t, advSettings.ExternalCookieDomain)
	assert.Equal(t, "", *advSettings.ExternalCookieDomain)
	assert.Nil(t, advSettings.LoginURL)
	require.NotNil(t, advSettings.UserName)
	assert.Equal(t, "alice", *advSettings.UserName)
}

func TestParseAdvancedSettingsWithDefaults_RemoteSparkSnakeCaseAliases(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{
		"remote_spark_map_clipboard": "true",
		"remote_spark_map_disk": "false",
		"remote_spark_map_printer": "true"
	}`)
	require.NoError(t, err)

	assert.Equal(t, "true", advSettings.RemoteSparkMapClipboard)
	assert.Equal(t, "false", advSettings.RemoteSparkMapDisk)
	assert.Equal(t, "true", advSettings.RemoteSparkMapPrinter)

	var complete AdvancedSettingsComplete
	UpdateAdvancedSettings(&complete, advSettings)

	payload, err := json.Marshal(complete)
	require.NoError(t, err)

	payloadStr := string(payload)
	for _, key := range []string{"remote_spark_mapClipboard", "remote_spark_mapDisk", "remote_spark_mapPrinter"} {
		assert.Contains(t, payloadStr, `"`+key+`"`, "payload should contain API key %s", key)
	}
	for _, key := range []string{"remote_spark_map_clipboard", "remote_spark_map_disk", "remote_spark_map_printer"} {
		assert.NotContains(t, payloadStr, `"`+key+`"`, "payload should NOT contain HCL alias key %s", key)
	}
}

func TestParseAdvancedSettingsWithDefaults_UnknownFieldsGoToExtraFields(t *testing.T) {
	input := `{"unknown_field": "some_value", "another_unknown": "42"}`
	advSettings, err := ParseAdvancedSettingsWithDefaults(input)
	require.NoError(t, err)

	require.NotNil(t, advSettings.ExtraFields)
	assert.Equal(t, "some_value", advSettings.ExtraFields["unknown_field"])
	assert.Equal(t, "42", advSettings.ExtraFields["another_unknown"])
}

// ---------------------------------------------------------------------------
// advancedSettingsFromBlock
// ---------------------------------------------------------------------------

func TestAdvancedSettingsFromBlock_FormPostAttributes(t *testing.T) {
	tests := map[string]struct {
		block   map[string]interface{}
		wantErr string
		wantLen int
	}{
		"valid_json": {
			block:   map[string]interface{}{"form_post_attributes": `["attr1","attr2"]`},
			wantLen: 2,
		},
		"empty_string": {
			block:   map[string]interface{}{"form_post_attributes": ""},
			wantLen: 0,
		},
		"invalid_json": {
			block:   map[string]interface{}{"form_post_attributes": `not-json`},
			wantErr: "invalid form_post_attributes JSON",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := advancedSettingsFromBlock(tc.block)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got.FormPostAttributes, tc.wantLen)
		})
	}
}

func TestAdvancedSettingsFromBlock_CustomHeaders(t *testing.T) {
	tests := map[string]struct {
		block   map[string]interface{}
		wantErr string
		wantLen int
	}{
		"valid_json": {
			block:   map[string]interface{}{"custom_headers": `[{"attribute_type":"static","header":"X-Foo","attribute":"bar"}]`},
			wantLen: 1,
		},
		"invalid_json": {
			block:   map[string]interface{}{"custom_headers": `{bad json`},
			wantErr: "invalid custom_headers JSON",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := advancedSettingsFromBlock(tc.block)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got.CustomHeaders, tc.wantLen)
			if tc.wantLen > 0 {
				assert.Equal(t, "static", got.CustomHeaders[0].AttributeType)
				assert.Equal(t, "X-Foo", got.CustomHeaders[0].Header)
				assert.Equal(t, "bar", got.CustomHeaders[0].Attribute)
			}
		})
	}
}

func TestAdvancedSettingsFromBlock_RDPRemoteApps(t *testing.T) {
	tests := map[string]struct {
		block   map[string]interface{}
		wantErr string
		wantLen int
	}{
		"valid_json": {
			block:   map[string]interface{}{"rdp_remote_apps": `[{"remote_app":"notepad","remote_app_args":"/f","remote_app_dir":"C:\\"}]`},
			wantLen: 1,
		},
		"invalid_json": {
			block:   map[string]interface{}{"rdp_remote_apps": `not-json`},
			wantErr: "invalid rdp_remote_apps JSON",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := advancedSettingsFromBlock(tc.block)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got.RDPRemoteApps, tc.wantLen)
			if tc.wantLen > 0 {
				assert.Equal(t, "notepad", got.RDPRemoteApps[0].RemoteApp)
			}
		})
	}
}

func TestAdvancedSettingsFromBlock_RequestParameters(t *testing.T) {
	block := map[string]interface{}{
		"request_parameters": `{"key":"value"}`,
	}
	got, err := advancedSettingsFromBlock(block)
	require.NoError(t, err)
	require.NotNil(t, got.RequestParameters)
	assert.Equal(t, `{"key":"value"}`, *got.RequestParameters)
}

func TestAdvancedSettingsFromBlock_InvalidHealthCheckType(t *testing.T) {
	block := map[string]interface{}{
		"health_check_type": "99",
	}

	_, err := advancedSettingsFromBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid health_check_type")
}

// ---------------------------------------------------------------------------
// AdvancedSettings MarshalJSON (ExtraFields merge)
// ---------------------------------------------------------------------------

func TestAdvancedSettings_MarshalJSON_ExtraFieldsMerged(t *testing.T) {
	as := &AdvancedSettings{
		Acceleration: "true",
		ExtraFields: map[string]interface{}{
			"custom_unknown_field": "hello",
		},
	}

	data, err := as.MarshalJSON()
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, "hello", parsed["custom_unknown_field"])
	assert.Equal(t, "true", parsed["acceleration"])
}

func TestAdvancedSettings_MarshalJSON_NoExtraFields(t *testing.T) {
	as := &AdvancedSettings{
		Acceleration: "false",
	}

	data, err := as.MarshalJSON()
	require.NoError(t, err)

	payloadStr := string(data)
	assert.True(t, strings.Contains(payloadStr, `"acceleration"`))
	// Ensure it doesn't error without ExtraFields
}

func TestAdvancedSettingsFromBlock_ProxyAndKerberosFieldsRoundTrip(t *testing.T) {
	block := map[string]interface{}{
		"proxy_buffer_size_kb":    "256",
		"keyed_keepalive_enable":  "true",
		"kerberos_negotiate_once": "on",
		"proxy_disable_clipboard": "true",
		"rate_limit":              "off",
	}

	advSettings, err := advancedSettingsFromBlock(block)
	require.NoError(t, err)

	assert.Equal(t, "256", advSettings.ProxyBufferSizeKB)
	assert.Equal(t, "true", advSettings.KeyedKeepaliveEnable)
	assert.Equal(t, "on", advSettings.KerberosNegotiateOnce)
	assert.Equal(t, "true", advSettings.ProxyDisableClipboard)
	assert.Equal(t, "off", advSettings.RateLimit)

	var complete AdvancedSettingsComplete
	UpdateAdvancedSettings(&complete, advSettings)

	assert.Equal(t, "256", complete.ProxyBufferSizeKB)
	assert.Equal(t, "true", complete.KeyedKeepaliveEnable)
	assert.Equal(t, "on", complete.KerberosNegotiateOnce)
	assert.Equal(t, "true", complete.ProxyDisableClipboard)
	assert.Equal(t, "off", complete.RateLimit)
}

func TestAdvancedSettingsFromBlock_OffloadOnpremiseTrafficRoundTrip(t *testing.T) {
	block := map[string]interface{}{
		"offload_onpremise_traffic": "true",
	}

	advSettings, err := advancedSettingsFromBlock(block)
	require.NoError(t, err)

	assert.Equal(t, "true", advSettings.OffloadOnPremiseTraffic)

	var complete AdvancedSettingsComplete
	UpdateAdvancedSettings(&complete, advSettings)

	assert.Equal(t, "true", complete.OffloadOnPremiseTraffic)
}

func TestAdvancedSettingsFromBlock_DeadFieldsDropped(t *testing.T) {
	block := map[string]interface{}{
		"dynamic_ip":     "true",
		"sticky_cookies": "true",
		"acceleration":   "true",
	}

	advSettings, err := advancedSettingsFromBlock(block)
	require.NoError(t, err)

	// dynamic_ip and sticky_cookies should land in ExtraFields, not struct fields
	assert.Equal(t, "true", advSettings.ExtraFields["dynamic_ip"])
	assert.Equal(t, "true", advSettings.ExtraFields["sticky_cookies"])

	// A real field should still work
	assert.Equal(t, "true", advSettings.Acceleration)
}

func TestAdvancedSettings_UnmarshalJSON_NumericFlexFields(t *testing.T) {
	jsonStr := `{
		"app_server_read_timeout": 60,
		"x_wapp_pool_size": 20,
		"x_wapp_pool_timeout": 120,
		"x_wapp_read_timeout": 900
	}`
	var as AdvancedSettings
	err := json.Unmarshal([]byte(jsonStr), &as)
	require.NoError(t, err)
	assert.Equal(t, FlexString("60"), as.AppServerReadTimeout)
	assert.Equal(t, FlexString("20"), as.XWappPoolSize)
	assert.Equal(t, FlexString("120"), as.XWappPoolTimeout)
	assert.Equal(t, FlexString("900"), as.XWappReadTimeout)
}

func TestAdvancedSettingsComplete_UnmarshalJSON_NumericFlexFields(t *testing.T) {
	jsonStr := `{
		"app_server_read_timeout": 60,
		"x_wapp_pool_size": 20,
		"x_wapp_pool_timeout": 120,
		"x_wapp_read_timeout": 900
	}`
	var asc AdvancedSettingsComplete
	err := json.Unmarshal([]byte(jsonStr), &asc)
	require.NoError(t, err)
	assert.Equal(t, FlexString("60"), asc.AppServerReadTimeout)
	assert.Equal(t, FlexString("20"), asc.XWappPoolSize)
	assert.Equal(t, FlexString("120"), asc.XWappPoolTimeout)
	assert.Equal(t, FlexString("900"), asc.XWappReadTimeout)
}

func TestUpdateAdvancedSettings_CopiesFlexStringFields(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{}`)
	require.NoError(t, err)

	var complete AdvancedSettingsComplete
	UpdateAdvancedSettings(&complete, advSettings)

	assert.Equal(t, FlexString("60"), complete.AppServerReadTimeout)
	assert.Equal(t, FlexString("20"), complete.XWappPoolSize)
	assert.Equal(t, FlexString("120"), complete.XWappPoolTimeout)
	assert.Equal(t, FlexString("900"), complete.XWappReadTimeout)
}

func TestParseAdvancedSettingsWithDefaults_NewFieldDefaults(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{}`)
	require.NoError(t, err)

	assert.Equal(t, "4", advSettings.ProxyBufferSizeKB)
	assert.Equal(t, "false", advSettings.KeyedKeepaliveEnable)
	assert.Equal(t, "off", advSettings.KerberosNegotiateOnce)
	assert.Equal(t, "false", advSettings.ProxyDisableClipboard)
	assert.Equal(t, "on", advSettings.RateLimit)
}

func TestAdvancedSettingsFromBlock_StripsComputedKeys(t *testing.T) {
	block := map[string]interface{}{
		"acceleration":               "true",
		"g2o_key":                    "user-should-not-set-this",
		"g2o_nonce":                  "nor-this",
		"edge_cookie_key":            "nor-this-either",
		"sla_object_url":             "ignore-me",
		"edge_transport_property_id": "also-ignored",
	}

	advSettings, err := advancedSettingsFromBlock(block)
	require.NoError(t, err)

	// Verify user-settable keys are preserved
	assert.Equal(t, "true", advSettings.Acceleration)

	// Verify server-computed keys are NOT set from user input
	// (they retain their default/zero values)
	assert.Nil(t, advSettings.G2OKey)
	assert.Nil(t, advSettings.G2ONonce)
	assert.Nil(t, advSettings.EdgeCookieKey)
	assert.Nil(t, advSettings.SLAObjectURL)
	assert.Nil(t, advSettings.EdgeTransportPropertyID)
}
