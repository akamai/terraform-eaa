package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAdvancedSettingsWithDefaults(t *testing.T) {
	tests := []struct {
		name        string
		jsonStr     string
		wantErr     bool
		checkFields func(*testing.T, *AdvancedSettings)
	}{
		{
			name:    "empty JSON",
			jsonStr: `{}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				// Should have defaults
				assert.Equal(t, string(DefaultAppAuth), settings.AppAuth)
				assert.Equal(t, string(DefaultWappAuth), settings.WappAuth)
				assert.Equal(t, "30000", settings.HealthCheckInterval)
			},
		},
		{
			name:    "valid JSON with custom values",
			jsonStr: `{"app_auth": "kerberos", "wapp_auth": "certonly", "health_check_interval": "60000"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "kerberos", settings.AppAuth)
				assert.Equal(t, "certonly", settings.WappAuth)
				assert.Equal(t, "60000", settings.HealthCheckInterval)
			},
		},
		{
			name:    "invalid JSON",
			jsonStr: `{invalid json}`,
			wantErr: true,
			checkFields: nil,
		},
		{
			name:    "health check type conversion",
			jsonStr: `{"health_check_type": "TCP"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				// TCP should be converted to numeric value
				assert.NotEmpty(t, settings.HealthCheckType)
			},
		},
		{
			name:    "custom headers",
			jsonStr: `{"custom_headers": [{"attribute_type": "request", "header": "X-Custom", "attribute": "value"}]}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Len(t, settings.CustomHeaders, 1)
				assert.Equal(t, "request", settings.CustomHeaders[0].AttributeType)
				assert.Equal(t, "X-Custom", settings.CustomHeaders[0].Header)
				assert.Equal(t, "value", settings.CustomHeaders[0].Attribute)
			},
		},
		{
			name:    "form post attributes as string",
			jsonStr: `{"form_post_attributes": "attr1,attr2,attr3"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, []string{"attr1", "attr2", "attr3"}, settings.FormPostAttributes)
			},
		},
		{
			name:    "RDP remote apps",
			jsonStr: `{"remote_app": "notepad.exe", "remote_app_args": "/p", "remote_app_dir": "C:\\Windows"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Len(t, settings.RDPRemoteApps, 1)
				assert.Equal(t, "notepad.exe", settings.RDPRemoteApps[0].RemoteApp)
				assert.Equal(t, "/p", settings.RDPRemoteApps[0].RemoteAppArgs)
				assert.Equal(t, "C:\\Windows", settings.RDPRemoteApps[0].RemoteAppDir)
			},
		},
		{
			name:    "pointer fields (app_auth_domain)",
			jsonStr: `{"app_auth_domain": "example.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.AppAuthDomain)
				assert.Equal(t, "example.com", *settings.AppAuthDomain)
			},
		},
		{
			name:    "numeric to string conversion",
			jsonStr: `{"health_check_interval": 45000}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "45000", settings.HealthCheckInterval)
			},
		},
		{
			name:    "app_auth strict validation - rejects non-string",
			jsonStr: `{"app_auth": 123}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				// Should keep default value, not set to "123"
				assert.Equal(t, string(DefaultAppAuth), settings.AppAuth)
			},
		},
		{
			name:    "CORS fields - origin list",
			jsonStr: `{"cors_origin_list": "https://example.com,https://test.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "https://example.com,https://test.com", settings.CORSOriginList)
			},
		},
		{
			name:    "CORS fields - method list",
			jsonStr: `{"cors_method_list": "GET,POST,PUT"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "GET,POST,PUT", settings.CORSMethodList)
			},
		},
		{
			name:    "CORS fields - header list",
			jsonStr: `{"cors_header_list": "Content-Type,Authorization"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "Content-Type,Authorization", settings.CORSHeaderList)
			},
		},
		{
			name:    "CORS fields - max age",
			jsonStr: `{"cors_max_age": "3600"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "3600", settings.CORSMaxAge)
			},
		},
		{
			name:    "CORS fields - support credential",
			jsonStr: `{"cors_support_credential": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.CORSSupportCredential)
			},
		},
		{
			name:    "G2O settings - enabled",
			jsonStr: `{"g2o_enabled": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.G2OEnabled)
			},
		},
		{
			name:    "JWT fields - issuers",
			jsonStr: `{"jwt_issuers": "https://issuer1.com,https://issuer2.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "https://issuer1.com,https://issuer2.com", settings.JWTIssuers)
			},
		},
		{
			name:    "JWT fields - audience",
			jsonStr: `{"jwt_audience": "my-audience"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "my-audience", settings.JWTAudience)
			},
		},
		{
			name:    "JWT fields - grace period",
			jsonStr: `{"jwt_grace_period": "120"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "120", settings.JWTGracePeriod)
			},
		},
		{
			name:    "JWT fields - return option",
			jsonStr: `{"jwt_return_option": "302"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "302", settings.JWTReturnOption)
			},
		},
		{
			name:    "JWT fields - username",
			jsonStr: `{"jwt_username": "sub"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "sub", settings.JWTUsername)
			},
		},
		{
			name:    "JWT fields - return URL",
			jsonStr: `{"jwt_return_url": "https://example.com/return"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "https://example.com/return", settings.JWTReturnURL)
			},
		},
		{
			name:    "Kerberos fields - keytab",
			jsonStr: `{"keytab": "test-keytab-value"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "test-keytab-value", settings.Keytab)
			},
		},
		{
			name:    "Kerberos fields - service principal name",
			jsonStr: `{"service_principle_name": "HTTP/example.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.ServicePrincipalName)
				assert.Equal(t, "HTTP/example.com", *settings.ServicePrincipalName)
			},
		},
		{
			name:    "Kerberos fields - forward ticket granting ticket",
			jsonStr: `{"forward_ticket_granting_ticket": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.ForwardTicketGrantingTicket)
			},
		},
		{
			name:    "Load balancing metric",
			jsonStr: `{"load_balancing_metric": "least-conn"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "least-conn", settings.LoadBalancingMetric)
			},
		},
		{
			name:    "SSL verification enabled",
			jsonStr: `{"is_ssl_verification_enabled": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.IsSSLVerificationEnabled)
			},
		},
		{
			name:    "WebSocket enabled",
			jsonStr: `{"websocket_enabled": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.WebSocketEnabled)
			},
		},
		{
			name:    "Multiple pointer fields - cookie domain",
			jsonStr: `{"cookie_domain": ".example.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.CookieDomain)
				assert.Equal(t, ".example.com", *settings.CookieDomain)
			},
		},
		{
			name:    "Multiple pointer fields - edge cookie key",
			jsonStr: `{"edge_cookie_key": "edge-key-123"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.EdgeCookieKey)
				assert.Equal(t, "edge-key-123", *settings.EdgeCookieKey)
			},
		},
		{
			name:    "Multiple pointer fields - app cookie domain",
			jsonStr: `{"app_cookie_domain": "app.example.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.AppCookieDomain)
				assert.Equal(t, "app.example.com", *settings.AppCookieDomain)
			},
		},
		{
			name:    "Multiple pointer fields - login URL",
			jsonStr: `{"login_url": "https://example.com/login"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.LoginURL)
				assert.Equal(t, "https://example.com/login", *settings.LoginURL)
			},
		},
		{
			name:    "Multiple pointer fields - logout URL",
			jsonStr: `{"logout_url": "https://example.com/logout"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.LogoutURL)
				assert.Equal(t, "https://example.com/logout", *settings.LogoutURL)
			},
		},
		{
			name:    "Health check - HTTP URL",
			jsonStr: `{"health_check_http_url": "/health"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "/health", settings.HealthCheckHTTPURL)
			},
		},
		{
			name:    "Health check - HTTP version",
			jsonStr: `{"health_check_http_version": "1.0"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "1.0", settings.HealthCheckHTTPVersion)
			},
		},
		{
			name:    "Health check - HTTP host header",
			jsonStr: `{"health_check_http_host_header": "example.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.NotNil(t, settings.HealthCheckHTTPHostHeader)
				assert.Equal(t, "example.com", *settings.HealthCheckHTTPHostHeader)
			},
		},
		{
			name:    "Health check - timeout",
			jsonStr: `{"health_check_timeout": "10000"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "10000", settings.HealthCheckTimeout)
			},
		},
		{
			name:    "Health check - rise",
			jsonStr: `{"health_check_rise": "5"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "5", settings.HealthCheckRise)
			},
		},
		{
			name:    "Health check - fall",
			jsonStr: `{"health_check_fall": "7"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "7", settings.HealthCheckFall)
			},
		},
		{
			name:    "Edge cases - empty string for pointer field",
			jsonStr: `{"app_auth_domain": ""}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				// Empty string should still set the pointer
				assert.NotNil(t, settings.AppAuthDomain)
				assert.Equal(t, "", *settings.AppAuthDomain)
			},
		},
		{
			name:    "Edge cases - multiple custom headers",
			jsonStr: `{"custom_headers": [{"attribute_type": "request", "header": "X-Header-1", "attribute": "val1"}, {"attribute_type": "response", "header": "X-Header-2", "attribute": "val2"}, {"attribute_type": "request", "header": "X-Header-3", "attribute": "val3"}]}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Len(t, settings.CustomHeaders, 3)
				assert.Equal(t, "X-Header-1", settings.CustomHeaders[0].Header)
				assert.Equal(t, "X-Header-2", settings.CustomHeaders[1].Header)
				assert.Equal(t, "X-Header-3", settings.CustomHeaders[2].Header)
			},
		},
		{
			name:    "Edge cases - empty custom headers array",
			jsonStr: `{"custom_headers": []}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Len(t, settings.CustomHeaders, 0)
			},
		},
		{
			name:    "Edge cases - form post attributes with spaces",
			jsonStr: `{"form_post_attributes": "attr1, attr2, attr3"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, []string{"attr1", "attr2", "attr3"}, settings.FormPostAttributes)
			},
		},
		{
			name:    "Edge cases - empty form post attributes",
			jsonStr: `{"form_post_attributes": ""}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, []string{""}, settings.FormPostAttributes)
			},
		},
		{
			name:    "Edge cases - multiple RDP remote apps",
			jsonStr: `{"remote_app": "app1.exe", "remote_app_args": "arg1", "remote_app_dir": "C:\\Apps"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Len(t, settings.RDPRemoteApps, 1)
				assert.Equal(t, "app1.exe", settings.RDPRemoteApps[0].RemoteApp)
			},
		},
		{
			name:    "Edge cases - ignore cname resolution",
			jsonStr: `{"ignore_cname_resolution": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.IgnoreCnameResolution)
			},
		},
		{
			name:    "Edge cases - edge authentication enabled",
			jsonStr: `{"edge_authentication_enabled": "off"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "off", settings.EdgeAuthenticationEnabled)
			},
		},
		{
			name:    "Edge cases - allow CORS",
			jsonStr: `{"allow_cors": "off"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "off", settings.AllowCORS)
			},
		},
		{
			name:    "Edge cases - acceleration",
			jsonStr: `{"acceleration": "off"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "off", settings.Acceleration)
			},
		},
		{
			name:    "Edge cases - sticky agent",
			jsonStr: `{"sticky_agent": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.StickyAgent)
			},
		},
		{
			name:    "Edge cases - IP access allow",
			jsonStr: `{"ip_access_allow": "on"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "on", settings.IPAccessAllow)
			},
		},
		{
			name:    "Edge cases - internal host port",
			jsonStr: `{"internal_host_port": "8080"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "8080", settings.InternalHostPort)
			},
		},
		{
			name:    "Edge cases - wildcard internal hostname",
			jsonStr: `{"wildcard_internal_hostname": "*.example.com"}`,
			wantErr: false,
			checkFields: func(t *testing.T, settings *AdvancedSettings) {
				assert.Equal(t, "*.example.com", settings.WildcardInternalHostname)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseAdvancedSettingsWithDefaults(tt.jsonStr)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.checkFields != nil {
					tt.checkFields(t, result)
				}
			}
		})
	}
}

func TestParseAdvancedSettingsWithDefaults_Defaults(t *testing.T) {
	// Test that all default values are properly set
	settings, err := ParseAdvancedSettingsWithDefaults(`{}`)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	// Verify some key defaults
	assert.Equal(t, string(DefaultAcceleration), settings.Acceleration)
	assert.Equal(t, string(DefaultAllowCORS), settings.AllowCORS)
	assert.Equal(t, string(DefaultAppAuth), settings.AppAuth)
	assert.Equal(t, string(DefaultWappAuth), settings.WappAuth)
	assert.Equal(t, "50", settings.AnonymousServerConnLimit)
	assert.Equal(t, "100", settings.AnonymousServerReqLimit)
	assert.Equal(t, "30000", settings.HealthCheckInterval)
	assert.Equal(t, "2", settings.HealthCheckRise)
	assert.Equal(t, "3", settings.HealthCheckFall)
}

func TestParseAdvancedSettingsWithDefaults_ComplexJSON(t *testing.T) {
	complexJSON := `{
		"app_auth": "kerberos",
		"wapp_auth": "saml",
		"health_check_type": "HTTP",
		"health_check_interval": "60000",
		"custom_headers": [
			{"attribute_type": "request", "header": "X-Header-1", "attribute": "value1"},
			{"attribute_type": "response", "header": "X-Header-2", "attribute": "value2"}
		],
		"form_post_attributes": "attr1, attr2, attr3",
		"app_auth_domain": "test.example.com",
		"cors_origin_list": "https://example.com",
		"websocket_enabled": "on"
	}`

	settings, err := ParseAdvancedSettingsWithDefaults(complexJSON)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	assert.Equal(t, "kerberos", settings.AppAuth)
	assert.Equal(t, "saml", settings.WappAuth)
	assert.Equal(t, "60000", settings.HealthCheckInterval)
	assert.Len(t, settings.CustomHeaders, 2)
	assert.Equal(t, []string{"attr1", "attr2", "attr3"}, settings.FormPostAttributes)
	assert.NotNil(t, settings.AppAuthDomain)
	assert.Equal(t, "test.example.com", *settings.AppAuthDomain)
}

func TestParseAdvancedSettingsWithDefaults_JSONRoundTrip(t *testing.T) {
	// Test that we can parse, modify, and the structure is correct
	input := `{"app_auth": "oidc", "health_check_interval": "45000"}`
	settings, err := ParseAdvancedSettingsWithDefaults(input)
	assert.NoError(t, err)

	// Verify the parsed values
	assert.Equal(t, "oidc", settings.AppAuth)
	assert.Equal(t, "45000", settings.HealthCheckInterval)

	// Verify defaults are still present for fields not in input
	assert.Equal(t, string(DefaultWappAuth), settings.WappAuth)
}

