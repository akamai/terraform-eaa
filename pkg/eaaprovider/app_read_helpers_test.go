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

// TestMapAdvancedSettingsFromResponseWithInvalidHealthCheckType tests that
// mapAdvancedSettingsFromResponse returns an error when the API returns an
// invalid health_check_type value. This is the error path that runs on
// every terraform plan/apply/refresh during the read phase.
func TestMapAdvancedSettingsFromResponseWithInvalidHealthCheckType(t *testing.T) {
	tests := []struct {
		name           string
		healthCheckVal string
	}{
		{
			name:           "invalid_numeric_99",
			healthCheckVal: "99",
		},
		{
			name:           "invalid_negative",
			healthCheckVal: "-1",
		},
		{
			name:           "invalid_non_numeric",
			healthCheckVal: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a resource schema
			resourceSchema := map[string]*schema.Schema{
				"uuid_url": {
					Type:     schema.TypeString,
					Computed: true,
				},
				"name": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"app_type": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"host": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"advanced_settings": {
					Type:     schema.TypeMap,
					Optional: true,
				},
			}

			// Create test resource data
			d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
				"uuid_url": "test-app-id",
				"name":     "test-app",
				"app_type": "http",
				"host":     "test.example.com",
				"advanced_settings": map[string]interface{}{
					"health_check_type": "Default", // Add a valid value to the state
				},
			})

			// Create an application response with invalid health_check_type
			appResp := &client.ApplicationResponse{
				UUIDURL: "test-app-id",
				Name:    "test-app",
				AdvancedSettings: client.AdvancedSettingsComplete{
					AllowCORS:           "false",
					HealthCheckType:     tt.healthCheckVal, // Invalid value
					HealthCheckFall:     "3",
					HealthCheckRise:     "2",
					HealthCheckTimeout:  "50000",
					HealthCheckInterval: "30000",
				},
			}

			// Call mapAdvancedSettingsFromResponse
			diags := mapAdvancedSettingsFromResponse(d, appResp)

			// Verify that we get an error diagnostic
			if !diags.HasError() {
				t.Errorf("mapAdvancedSettingsFromResponse with invalid health_check_type %q returned no errors, want error", tt.healthCheckVal)
			}

			// Check that the error message mentions health_check_type
			if len(diags) == 0 {
				t.Fatal("Expected at least one diagnostic error")
			}

			errorMsg := diags[0].Summary
			if errorMsg != "failed to map health_check_type from API value" && !strings.Contains(diags[0].Summary, "health_check_type") {
				t.Errorf("Error message = %q, want message containing 'health_check_type'", errorMsg)
			}
		})
	}
}

// TestMapAdvancedSettingsFromResponseWithValidHealthCheckType tests that
// mapAdvancedSettingsFromResponse correctly handles valid health_check_type values.
func TestMapAdvancedSettingsFromResponseWithValidHealthCheckType(t *testing.T) {
	tests := []struct {
		name           string
		healthCheckVal string
		expectedResult string
	}{
		{name: "default", healthCheckVal: "0", expectedResult: "Default"},
		{name: "http", healthCheckVal: "1", expectedResult: "HTTP"},
		{name: "https", healthCheckVal: "2", expectedResult: "HTTPS"},
		{name: "tls", healthCheckVal: "3", expectedResult: "TLS"},
		{name: "sslv3", healthCheckVal: "4", expectedResult: "SSLv3"},
		{name: "tcp", healthCheckVal: "5", expectedResult: "TCP"},
		{name: "none", healthCheckVal: "6", expectedResult: "None"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a resource schema
			resourceSchema := map[string]*schema.Schema{
				"uuid_url": {
					Type:     schema.TypeString,
					Computed: true,
				},
				"name": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"app_type": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"host": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"advanced_settings": {
					Type:     schema.TypeMap,
					Optional: true,
				},
			}

			// Create test resource data with some prior state
			d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
				"uuid_url": "test-app-id",
				"name":     "test-app",
				"app_type": "http",
				"host":     "test.example.com",
				"advanced_settings": map[string]interface{}{
					"health_check_type": "Default", // Include in prior state
				},
			})

			// Create an application response with valid health_check_type
			appResp := &client.ApplicationResponse{
				UUIDURL: "test-app-id",
				Name:    "test-app",
				AdvancedSettings: client.AdvancedSettingsComplete{
					AllowCORS:           "false",
					HealthCheckType:     tt.healthCheckVal,
					HealthCheckFall:     "3",
					HealthCheckRise:     "2",
					HealthCheckTimeout:  "50000",
					HealthCheckInterval: "30000",
				},
			}

			// Call mapAdvancedSettingsFromResponse
			diags := mapAdvancedSettingsFromResponse(d, appResp)

			// Verify no errors
			if diags.HasError() {
				t.Errorf("mapAdvancedSettingsFromResponse with valid health_check_type %q returned errors: %v", tt.healthCheckVal, diags)
			}

			// Verify the state was set correctly
			advSettingsRaw := d.Get("advanced_settings")
			advSettings, ok := advSettingsRaw.(map[string]interface{})
			if !ok {
				t.Fatalf("advanced_settings type = %T, want map[string]interface{}", advSettingsRaw)
			}

			if got := advSettings["health_check_type"]; got != tt.expectedResult {
				t.Errorf("health_check_type = %q, want %q", got, tt.expectedResult)
			}
		})
	}
}

func TestMapAdvancedSettingsFromResponse_FlexStringFields(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"uuid_url": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"name": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"app_type": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"host": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"advanced_settings": {
			Type:     schema.TypeMap,
			Optional: true,
		},
	}

	d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
		"uuid_url":          "test-app-id",
		"name":              "test-app",
		"app_type":          "http",
		"host":              "test.example.com",
		"advanced_settings": map[string]interface{}{},
	})

	appResp := &client.ApplicationResponse{
		UUIDURL: "test-app-id",
		Name:    "test-app",
		AdvancedSettings: client.AdvancedSettingsComplete{
			HealthCheckType:      "0",
			AppServerReadTimeout: client.FlexString("60"),
			XWappPoolSize:        client.FlexString("20"),
			XWappPoolTimeout:     client.FlexString("120"),
			XWappReadTimeout:     client.FlexString("900"),
		},
	}

	diags := mapAdvancedSettingsFromResponse(d, appResp)
	if diags.HasError() {
		t.Fatalf("mapAdvancedSettingsFromResponse returned errors: %v", diags)
	}

	advSettings := d.Get("advanced_settings").(map[string]interface{})
	assert.Equal(t, "60", advSettings["app_server_read_timeout"])
	assert.Equal(t, "20", advSettings["x_wapp_pool_size"])
	assert.Equal(t, "120", advSettings["x_wapp_pool_timeout"])
	assert.Equal(t, "900", advSettings["x_wapp_read_timeout"])
}

func TestMapAdvancedSettingsFromResponse_ImportExcludesServerComputedKeys(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"uuid_url": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"name": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"app_type": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"host": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"advanced_settings": {
			Type:     schema.TypeMap,
			Optional: true,
		},
	}

	// Empty advanced_settings simulates import (no prior state).
	d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
		"uuid_url":          "test-app-id",
		"name":              "test-app",
		"app_type":          "http",
		"host":              "test.example.com",
		"advanced_settings": map[string]interface{}{},
	})

	g2oKey := "secret-g2o-key"
	g2oNonce := "secret-g2o-nonce"
	edgeCookieKey := "secret-edge-cookie"
	slaURL := "https://sla.example.com"
	edgeTransportID := "etp-12345"

	appResp := &client.ApplicationResponse{
		UUIDURL: "test-app-id",
		Name:    "test-app",
		AdvancedSettings: client.AdvancedSettingsComplete{
			HealthCheckType:         "0",
			G2OKey:                  &g2oKey,
			G2ONonce:                &g2oNonce,
			EdgeCookieKey:           edgeCookieKey,
			SLAObjectURL:            slaURL,
			EdgeTransportPropertyID: &edgeTransportID,
			AllowCORS:               "true",
			LoadBalancingMetric:     "round-robin",
		},
	}

	diags := mapAdvancedSettingsFromResponse(d, appResp)
	require.False(t, diags.HasError(), "unexpected error: %v", diags)

	advSettings := d.Get("advanced_settings").(map[string]interface{})

	for key := range client.ServerComputedAdvancedSettingsKeys {
		_, present := advSettings[key]
		assert.False(t, present, "server-computed key %q should not appear in import state", key)
	}

	assert.Equal(t, "true", advSettings["allow_cors"], "non-computed key allow_cors should be present")
	assert.Equal(t, "round-robin", advSettings["load_balancing_metric"], "non-computed key load_balancing_metric should be present")
}

func TestMapBasicAttributesFromResponse_TLSSuiteName(t *testing.T) {
	basicSchema := map[string]*schema.Schema{
		"name":            {Type: schema.TypeString, Optional: true},
		"description":     {Type: schema.TypeString, Optional: true},
		"app_profile":     {Type: schema.TypeString, Optional: true},
		"app_type":        {Type: schema.TypeString, Optional: true},
		"client_app_mode": {Type: schema.TypeString, Optional: true},
		"domain":          {Type: schema.TypeString, Computed: true},
		"domain_suffix":   {Type: schema.TypeString, Computed: true},
		"host":            {Type: schema.TypeString, Optional: true, Computed: true},
		"bookmark_url":    {Type: schema.TypeString, Optional: true},
		"origin_host":     {Type: schema.TypeString, Optional: true, Computed: true},
		"orig_tls":        {Type: schema.TypeBool, Computed: true},
		"origin_port":     {Type: schema.TypeInt, Computed: true},
		"pop":             {Type: schema.TypeString, Computed: true},
		"popname":         {Type: schema.TypeString, Computed: true},
		"popregion":       {Type: schema.TypeString, Optional: true, Computed: true},
		"auth_enabled":    {Type: schema.TypeString, Optional: true},
		"app_deployed":    {Type: schema.TypeBool, Computed: true},
		"app_operational": {Type: schema.TypeInt, Computed: true},
		"app_status":      {Type: schema.TypeInt, Computed: true},
		"saml":            {Type: schema.TypeBool, Computed: true},
		"oidc":            {Type: schema.TypeBool, Computed: true},
		"wsfed":           {Type: schema.TypeBool, Computed: true},
		"cname":           {Type: schema.TypeString, Computed: true},
		"app_category":    {Type: schema.TypeString, Optional: true},
		"cert":            {Type: schema.TypeString, Computed: true},
		"uuid_url":        {Type: schema.TypeString, Computed: true},
		"tls_suite_name":  {Type: schema.TypeString, Optional: true, Computed: true},
		"app_bundle":      {Type: schema.TypeString, Optional: true},
	}

	t.Run("non-nil tls_suite_name is set", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, basicSchema, map[string]interface{}{})
		suiteName := "my-tls-suite"
		appResp := &client.ApplicationResponse{
			UUIDURL:      "test-app-id",
			Name:         "test-app",
			TLSSuiteName: &suiteName,
		}

		diags := mapBasicAttributesFromResponse(context.Background(), d, appResp, nil)
		require.False(t, diags.HasError(), "unexpected error: %v", diags)
		assert.Equal(t, "my-tls-suite", d.Get("tls_suite_name"))
	})

	t.Run("nil tls_suite_name is cleared", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, basicSchema, map[string]interface{}{
			"tls_suite_name": "old-suite",
		})
		appResp := &client.ApplicationResponse{
			UUIDURL:      "test-app-id",
			Name:         "test-app",
			TLSSuiteName: nil,
		}

		diags := mapBasicAttributesFromResponse(context.Background(), d, appResp, nil)
		require.False(t, diags.HasError(), "unexpected error: %v", diags)
		assert.Equal(t, "", d.Get("tls_suite_name"))
	})
}
