package client

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestValidateAdvancedSettings(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name         string
		settings     map[string]interface{}
		appType      string
		appProfile   string
		clientAppMode string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "valid settings for enterprise HTTP",
			settings:     map[string]interface{}{"allow_cors": "false", "logging_enabled": "true"},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "unknown setting",
			settings:     map[string]interface{}{"unknown_setting": "value"},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      true,
			errContains:  "unknown setting",
		},
		{
			name:         "invalid enum value",
			settings:     map[string]interface{}{"allow_cors": "invalid_value"},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      true,
			errContains:  "must be one of",
		},
		{
			name:         "setting not allowed for app type",
			settings:     map[string]interface{}{"rdp_keyboard_lang": "en-US"},
			appType:      "enterprise",
			appProfile:   "http", // RDP settings only for RDP profile
			clientAppMode: "",
			wantErr:      true,
			errContains:  "not allowed for app_profile",
		},
		{
			name:         "setting allowed for tunnel TCP",
			settings:     map[string]interface{}{"internal_hostname": "internal.example.com"},
			appType:      "tunnel",
			appProfile:   "tcp",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "empty settings",
			settings:     map[string]interface{}{},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "valid health check settings",
			settings:     map[string]interface{}{"health_check_type": "HTTP", "health_check_interval": "30000"},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "setting not allowed for app type",
			settings:     map[string]interface{}{"app_auth": "kerberos"},
			appType:      "tunnel",
			appProfile:   "tcp",
			clientAppMode: "",
			wantErr:      true,
			errContains:  "not allowed for app_type",
		},
		{
			name:         "tunnel app skips profile validation",
			settings:     map[string]interface{}{"internal_hostname": "internal.example.com"},
			appType:      "tunnel",
			appProfile:   "invalid_profile",
			clientAppMode: "",
			wantErr:      false, // Tunnel apps skip profile validation
		},
		{
			name:         "multiple settings with dependencies",
			settings:     map[string]interface{}{
				"allow_cors": "true",
				"cors_origin_list": "https://example.com",
				"cors_method_list": "GET,POST",
				"cors_header_list": "Content-Type",
				"cors_support_credential": "on",
				"cors_max_age": "3600",
			},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "dependency missing",
			settings:     map[string]interface{}{"cors_support_credential": "on"},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      true,
			errContains:  "field 'allow_cors' is required",
		},
		{
			name:         "bookmark app type with empty settings",
			settings:     map[string]interface{}{},
			appType:      "bookmark",
			appProfile:   "",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "saas app type with empty settings",
			settings:     map[string]interface{}{},
			appType:      "saas",
			appProfile:   "",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "conditional rule wapp_auth certonly with app_auth",
			settings:     map[string]interface{}{
				"wapp_auth": "certonly",
				"app_auth": "none",
			},
			appType:      "enterprise",
			appProfile:   "rdp",
			clientAppMode: "",
			wantErr:      false,
		},
		{
			name:         "conditional rule wapp_auth certonly invalid app_auth for RDP",
			settings:     map[string]interface{}{
				"wapp_auth": "certonly",
				"app_auth": "saml",
			},
			appType:      "enterprise",
			appProfile:   "rdp",
			clientAppMode: "",
			wantErr:      true,
			errContains:  "must be one of",
		},
		{
			name:         "wapp_auth certonly not allowed for HTTP profile",
			settings:     map[string]interface{}{"wapp_auth": "certonly"},
			appType:      "enterprise",
			appProfile:   "http",
			clientAppMode: "",
			wantErr:      true,
			errContains:  "certonly is only allowed for RDP profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdvancedSettings(tt.settings, tt.appType, tt.appProfile, tt.clientAppMode, logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHealthCheckConfiguration(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name       string
		settings   map[string]interface{}
		appType    string
		appProfile string
		wantErr    bool
	}{
		{
			name:       "no health check settings",
			settings:   map[string]interface{}{"acceleration": "on"},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    false,
		},
		{
			name:       "valid health check settings",
			settings:   map[string]interface{}{"health_check_type": "HTTP", "health_check_interval": "30000", "health_check_http_url": "/health", "health_check_http_version": "1.1", "health_check_http_host_header": "example.com"},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    false,
		},
		{
			name:       "invalid health check type",
			settings:   map[string]interface{}{"health_check_type": "INVALID"},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    true,
		},
		{
			name:       "HTTP health check missing required fields",
			settings:   map[string]interface{}{"health_check_type": "HTTP"},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    true,
		},
		{
			name:       "HTTPS health check missing required fields",
			settings:   map[string]interface{}{"health_check_type": "HTTPS"},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    true,
		},
		{
			name:       "HTTP health check with all required fields",
			settings:   map[string]interface{}{
				"health_check_type": "HTTP",
				"health_check_http_url": "/health",
				"health_check_http_version": "HTTP/1.1",
				"health_check_http_host_header": "example.com",
			},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    false,
		},
		{
			name:       "TCP health check for tunnel app",
			settings:   map[string]interface{}{"health_check_type": "TCP"},
			appType:    "tunnel",
			appProfile: "tcp",
			wantErr:    false,
		},
		{
			name:       "multiple health check fields",
			settings:   map[string]interface{}{
				"health_check_type": "HTTP",
				"health_check_interval": "30000",
				"health_check_rise": "3",
				"health_check_fall": "3",
				"health_check_http_url": "/health",
				"health_check_http_version": "HTTP/1.1",
				"health_check_http_host_header": "example.com",
			},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHealthCheckConfiguration(tt.settings, tt.appType, tt.appProfile, logger)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAdvancedSettings_AppTypes(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name       string
		settings   map[string]interface{}
		appType    string
		appProfile string
		wantErr    bool
	}{
		{
			name:       "tunnel app with internal_hostname",
			settings:   map[string]interface{}{"internal_hostname": "internal.example.com"},
			appType:    "tunnel",
			appProfile: "tcp",
			wantErr:    false,
		},
		{
			name:       "enterprise app cannot use internal_hostname",
			settings:   map[string]interface{}{"internal_hostname": "internal.example.com"},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    true,
		},
		{
			name:       "RDP profile can use RDP settings",
			settings:   map[string]interface{}{"rdp_keyboard_lang": "en-US"},
			appType:    "enterprise",
			appProfile: "rdp",
			wantErr:    false,
		},
		{
			name:       "bookmark app type with empty settings",
			settings:   map[string]interface{}{},
			appType:    "bookmark",
			appProfile: "",
			wantErr:    false,
		},
		{
			name:       "saas app type with empty settings",
			settings:   map[string]interface{}{},
			appType:    "saas",
			appProfile: "",
			wantErr:    false,
		},
		{
			name:       "SharePoint profile",
			settings:   map[string]interface{}{"app_auth": "kerberos"},
			appType:    "enterprise",
			appProfile: "sharepoint",
			wantErr:    false,
		},
		{
			name:       "Jira profile",
			settings:   map[string]interface{}{"app_auth": "basic"},
			appType:    "enterprise",
			appProfile: "jira",
			wantErr:    false,
		},
		{
			name:       "Jenkins profile",
			settings:   map[string]interface{}{"app_auth": "auto"},
			appType:    "enterprise",
			appProfile: "jenkins",
			wantErr:    false,
		},
		{
			name:       "Confluence profile",
			settings:   map[string]interface{}{"app_auth": "none"},
			appType:    "enterprise",
			appProfile: "confluence",
			wantErr:    false,
		},
		{
			name:       "VNC profile with wapp_auth",
			settings:   map[string]interface{}{"wapp_auth": "form"},
			appType:    "enterprise",
			appProfile: "vnc",
			wantErr:    false,
		},
		{
			name:       "SSH profile with wapp_auth",
			settings:   map[string]interface{}{"wapp_auth": "basic"},
			appType:    "enterprise",
			appProfile: "ssh",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdvancedSettings(tt.settings, tt.appType, tt.appProfile, "", logger)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAdvancedSettings_EnumValues(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		settings  map[string]interface{}
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid allow_cors value",
			settings:  map[string]interface{}{"allow_cors": "true"},
			wantErr:   false,
		},
		{
			name:      "valid allow_cors value false",
			settings:  map[string]interface{}{"allow_cors": "false"},
			wantErr:   false,
		},
		{
			name:      "invalid allow_cors value",
			settings:  map[string]interface{}{"allow_cors": "invalid"},
			wantErr:   true,
			errMsg:    "must be one of",
		},
		{
			name:      "valid cors_support_credential with allow_cors",
			settings:  map[string]interface{}{"allow_cors": "true", "cors_support_credential": "on"},
			wantErr:   false,
		},
		{
			name:      "invalid cors_support_credential without allow_cors",
			settings:  map[string]interface{}{"cors_support_credential": "on"},
			wantErr:   true,
			errMsg:    "field 'allow_cors' is required",
		},
		{
			name:      "valid cors_origin_list with allow_cors",
			settings:  map[string]interface{}{
				"allow_cors": "true",
				"cors_origin_list": "https://example.com",
			},
			wantErr:   false,
		},
		{
			name:      "valid cors_method_list with allow_cors",
			settings:  map[string]interface{}{
				"allow_cors": "true",
				"cors_method_list": "GET,POST",
			},
			wantErr:   false,
		},
		{
			name:      "valid cors_header_list with allow_cors",
			settings:  map[string]interface{}{
				"allow_cors": "true",
				"cors_header_list": "Content-Type",
			},
			wantErr:   false,
		},
		{
			name:      "invalid cors_origin_list without allow_cors",
			settings:  map[string]interface{}{"cors_origin_list": []string{"https://example.com"}},
			wantErr:   true,
			errMsg:    "field 'allow_cors' is required",
		},
		{
			name:      "invalid cors_method_list without allow_cors",
			settings:  map[string]interface{}{"cors_method_list": "GET"},
			wantErr:   true,
			errMsg:    "field 'allow_cors' is required",
		},
		{
			name:      "invalid cors_header_list without allow_cors",
			settings:  map[string]interface{}{"cors_header_list": "Content-Type"},
			wantErr:   true,
			errMsg:    "field 'allow_cors' is required",
		},
		{
			name:      "valid g2o_enabled",
			settings:  map[string]interface{}{"g2o_enabled": "true"},
			wantErr:   false,
		},
		{
			name:      "invalid g2o_enabled value",
			settings:  map[string]interface{}{"g2o_enabled": "invalid"},
			wantErr:   true,
			errMsg:    "must be one of",
		},
		{
			name:      "valid load_balancing_metric",
			settings:  map[string]interface{}{"load_balancing_metric": "round-robin"},
			wantErr:   false,
		},
		{
			name:      "invalid load_balancing_metric",
			settings:  map[string]interface{}{"load_balancing_metric": "invalid"},
			wantErr:   true,
			errMsg:    "must be one of",
		},
		{
			name:      "valid websocket_enabled",
			settings:  map[string]interface{}{"websocket_enabled": "true"},
			wantErr:   false,
		},
		{
			name:      "invalid websocket_enabled value",
			settings:  map[string]interface{}{"websocket_enabled": "invalid"},
			wantErr:   true,
			errMsg:    "must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdvancedSettings(tt.settings, "enterprise", "http", "", logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAdvancedSettings_IntegerRanges(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		settings  map[string]interface{}
		wantErr   bool
	}{
		{
			name:      "valid health_check_interval",
			settings:  map[string]interface{}{"health_check_interval": "30000"},
			wantErr:   false,
		},
		{
			name:      "valid health_check_interval at minimum",
			settings:  map[string]interface{}{"health_check_interval": "1000"},
			wantErr:   false,
		},
		{
			name:      "health_check_interval as string - validation happens at different layer",
			settings:  map[string]interface{}{"health_check_interval": "500"},
			wantErr:   false, // String validation doesn't check numeric ranges
		},
		{
			name:      "valid health_check_interval at maximum",
			settings:  map[string]interface{}{"health_check_interval": "600000"},
			wantErr:   false,
		},
		{
			name:      "health_check_interval as integer",
			settings:  map[string]interface{}{"health_check_interval": 30000},
			wantErr:   false,
		},
		{
			name:      "health_check_rise valid",
			settings:  map[string]interface{}{"health_check_rise": "3"},
			wantErr:   false,
		},
		{
			name:      "health_check_fall valid",
			settings:  map[string]interface{}{"health_check_fall": "3"},
			wantErr:   false,
		},
		{
			name:      "health_check_timeout valid",
			settings:  map[string]interface{}{"health_check_timeout": "5000"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdvancedSettings(tt.settings, "enterprise", "http", "", logger)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

