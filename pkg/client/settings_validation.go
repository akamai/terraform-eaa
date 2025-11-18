package client

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// SettingRule defines validation rules for a specific advanced setting
type SettingRule struct {
	Type        string   // Field type: "string", "int" (boolean fields use "string" with ValidValues, supports pointer types)
	ValidValues []string // Allowed values (for enum fields)
	AppTypes    []string // Allowed app types
	Profiles    []string // Allowed app profiles
	MinValue    int      // Minimum value for numeric fields
	MaxValue    int      // Maximum value for numeric fields
	Required    bool     // Whether field is required (nullable fields should be false)

	// Dependency rules
	DependsOn   map[string]string      // Field dependencies: {"field_name": "required_value"}
	Conditional map[string]interface{} // Conditional validation rules
}

// SETTINGS_RULES defines validation rules for all advanced settings
var SETTINGS_RULES = map[string]SettingRule{
	// Authentication Settings
	"app_auth": {
		Type: "string",
		ValidValues: []string{
			string(AppAuthTypeNone),
			string(AppAuthTypeKerberos),
			string(AppAuthTypeBasic),
			string(AppAuthTypeNTLMv1),
			string(AppAuthTypeNTLMv2),
			string(AppAuthTypeAuto),
			string(AppAuthTypeServiceAccount),
			string(AppAuthTypeSAML),
			string(AppAuthTypeSAML2),
			string(AppAuthTypeOIDC),
			string(AppAuthTypeOIDCFull),
			string(AppAuthTypeWSFED),
			string(AppAuthTypeWSFEDFull),
		},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
		},
		// Conditional dependency: When wapp_auth is "certonly", app_auth behavior depends on profile
		// For RDP profile: when wapp_auth=certonly, app_auth can only be "none", "auto", "service account"
		// For non-RDP profiles: when wapp_auth=certonly, app_auth can only be "none", "kerberos", "oidc"
		Conditional: map[string]interface{}{
			"wapp_auth": map[string]interface{}{
				string(WappAuthTypeCertOnly): map[string]interface{}{
					"ValidValues": []string{
						string(AppAuthTypeNone),
						string(AppAuthTypeKerberos),
						string(AppAuthTypeOIDC),
					},
				},
			},
		},
	},
	"wapp_auth": {
		Type: "string",
		ValidValues: []string{
			string(WappAuthTypeForm),
			string(WappAuthTypeBasic),
			string(WappAuthTypeBasicCookie),
			string(WappAuthTypeJWT),
			string(WappAuthTypeCertOnly),
		},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Conditional: certonly is only allowed for RDP profile
		Conditional: map[string]interface{}{
			"profile": map[string]interface{}{
				string(AppProfileHTTP): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
					},
					"Exclude": []string{string(WappAuthTypeCertOnly)}, // certonly not allowed for HTTP
				},
				string(AppProfileSharePoint): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
					},
					"Exclude": []string{string(WappAuthTypeCertOnly)}, // certonly not allowed for SharePoint
				},
				string(AppProfileJira): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
					},
					"Exclude": []string{string(WappAuthTypeCertOnly)}, // certonly not allowed for Jira
				},
				string(AppProfileJenkins): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
					},
					"Exclude": []string{string(WappAuthTypeCertOnly)}, // certonly not allowed for Jenkins
				},
				string(AppProfileConfluence): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
					},
					"Exclude": []string{string(WappAuthTypeCertOnly)}, // certonly not allowed for Confluence
				},
				string(AppProfileRDP): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
						string(WappAuthTypeCertOnly),
					}, // certonly allowed for RDP
				},
				string(AppProfileVNC): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
					},
					"Exclude": []string{string(WappAuthTypeCertOnly)}, // certonly not allowed for VNC
				},
				string(AppProfileSSH): map[string]interface{}{
					"ValidValues": []string{
						string(WappAuthTypeForm),
						string(WappAuthTypeBasic),
						string(WappAuthTypeBasicCookie),
						string(WappAuthTypeJWT),
					},
					"Exclude": []string{string(WappAuthTypeCertOnly)}, // certonly not allowed for SSH
				},
			},
			// Conflict validation: JWT fields conflict with non-JWT auth types
			string(WappAuthTypeBasic): map[string]interface{}{
				"ConflictsWith": []string{"jwt_audience", "jwt_grace_period", "jwt_issuers", "jwt_return_option", "jwt_return_url", "jwt_username"},
			},
			string(WappAuthTypeCertOnly): map[string]interface{}{
				"ConflictsWith": []string{"jwt_audience", "jwt_grace_period", "jwt_issuers", "jwt_return_option", "jwt_return_url", "jwt_username"},
			},
			string(WappAuthTypeBasicCookie): map[string]interface{}{
				"ConflictsWith": []string{"jwt_audience", "jwt_grace_period", "jwt_issuers", "jwt_return_option", "jwt_return_url", "jwt_username"},
			},
		},
	},
	"login_url": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"logout_url": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"service_principle_name": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"keytab": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	// Health Check Settings
	"health_check_type": {
		Type: "string",
		ValidValues: []string{
			string(HealthCheckTypeDefault),
			string(HealthCheckTypeHTTP),
			string(HealthCheckTypeHTTPS),
			string(HealthCheckTypeTLS),
			string(HealthCheckTypeSSLv3),
			string(HealthCheckTypeNone),
			string(HealthCheckTypeTCP),
		},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"health_check_http_url": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: HTTP URL is only valid when health_check_type is HTTP or HTTPS
		DependsOn: map[string]string{
			"health_check_type": "HTTP|HTTPS",
		},
	},
	"health_check_http_version": {
		Type: "string",
		ValidValues: []string{
			string(HTTPVersion1_0),
			string(HTTPVersion1_1),
			"HTTP/1.0",
			"HTTP/1.1",
		},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: HTTP version is only valid when health_check_type is HTTP or HTTPS
		DependsOn: map[string]string{
			"health_check_type": "HTTP|HTTPS",
		},
	},
	"health_check_http_host_header": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"health_check_rise": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 10,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileRDP),
			string(AppProfileTCP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"health_check_fall": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 10,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"health_check_timeout": {
		Type:     "string",
		MinValue: 1000,
		MaxValue: 300000,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"health_check_interval": {
		Type:     "string",
		MinValue: 1000,
		MaxValue: 300000,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	// Server Load Balancing Settings
	"load_balancing_metric": {
		Type: "string",
		ValidValues: []string{
			string(LoadBalancingRoundRobin),
			string(LoadBalancingIPHash),
			string(LoadBalancingLeastConn),
			string(LoadBalancingWeightedRR),
		},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileTCP),
		},
		// Blocked for RDP/SSH/VNC profiles (remote desktop protocols)
		Conditional: map[string]interface{}{
			"app_type": map[string]interface{}{
				"enterprise": map[string]interface{}{
					"blocked_profiles": []string{
						string(AppProfileRDP),
						string(AppProfileSSH),
						string(AppProfileVNC),
					},
				},
			},
		},
	},
	"session_sticky": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileTCP),
		},
		// Blocked for RDP/SSH/VNC profiles (remote desktop protocols)
		Conditional: map[string]interface{}{
			"app_type": map[string]interface{}{
				"enterprise": map[string]interface{}{
					"blocked_profiles": []string{
						string(AppProfileRDP),
						string(AppProfileSSH),
						string(AppProfileVNC),
					},
				},
			},
		},
	},
	"cookie_age": {
		Type:     "string",
		MinValue: 0,
		MaxValue: 86400,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
		},
		// Dependency: Cookie age requires session_sticky to be enabled (for non-tunnel apps)
		DependsOn: map[string]string{
			"session_sticky": "true",
		},
	},
	"tcp_optimization": {
		Type:        "string",
		ValidValues: []string{"on", "off"},
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileTCP),
		},
		// Blocked for SMB profile in tunnel apps
		Conditional: map[string]interface{}{
			"app_type": map[string]interface{}{
				"tunnel": map[string]interface{}{
					"blocked_profiles": []string{
						string(AppProfileSMB),
					},
				},
			},
		},
	},

	// RDP Configuration Settings
	"rdp_initial_program": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"remote_app": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"remote_app_args": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"remote_app_dir": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"rdp_tls1": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"rdp_keyboard_lang": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"rdp_window_color_depth": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"rdp_window_height": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"rdp_window_width": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},

	// RDP Remote Spark Features (RDP V2 only)
	"remote_spark_mapClipboard": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"rdp_legacy_mode": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"remote_spark_audio": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"remote_spark_mapPrinter": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"remote_spark_printer": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
		// Dependency: Remote printer requires mapPrinter to be enabled
		DependsOn: map[string]string{
			"remote_spark_mapPrinter": "true",
		},
	},
	"remote_spark_mapDisk": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},
	"remote_spark_disk": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
		// Dependency: Remote disk requires mapDisk to be enabled
		DependsOn: map[string]string{
			"remote_spark_mapDisk": "true",
		},
	},
	"remote_spark_recording": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileRDP),
		},
	},

	// TLS Configuration Settings
	"tlsSuiteType": {
		Type: "string",
		ValidValues: []string{
			string(TLSSuiteTypeDefault),
			string(TLSSuiteTypeCustom),
		},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"tls_suite_name": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	// Miscellaneous Settings
	"proxy_buffer_size_kb": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 1000,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"ssh_audit_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileSSH),
		},
	},
	"allow_cors": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"cors_origin_list": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: CORS detail fields require allow_cors to be enabled
		DependsOn: map[string]string{
			"allow_cors": "true",
		},
	},
	"cors_header_list": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: CORS detail fields require allow_cors to be enabled
		DependsOn: map[string]string{
			"allow_cors": "true",
		},
	},
	"cors_method_list": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: CORS detail fields require allow_cors to be enabled
		DependsOn: map[string]string{
			"allow_cors": "true",
		},
	},
	"cors_support_credential": {
		Type:        "string",
		ValidValues: []string{"on", "off"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: CORS detail fields require allow_cors to be enabled
		DependsOn: map[string]string{
			"allow_cors": "true",
		},
	},
	"cors_max_age": {
		Type:     "string",
		MinValue: 0,
		MaxValue: 86400,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: CORS detail fields require allow_cors to be enabled
		DependsOn: map[string]string{
			"allow_cors": "true",
		},
	},
	"websocket_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"https_sslv3": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"logging_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppModeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"hidden_app": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"saas_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"sticky_agent": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"x_wapp_read_timeout": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 300,
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"dynamic_ip": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"sticky_cookies": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"offload_onpremise_traffic": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"x_wapp_pool_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false", "inherit"},
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileTCP),
			string(AppProfileSMB),
		},
	},
	"x_wapp_pool_size": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 50, // Updated from 100 to 50 based on tunnel validation
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{},
	},
	"x_wapp_pool_timeout": {
		Type:     "int",
		MinValue: 60,   // Updated from 1 to 60 based on tunnel validation
		MaxValue: 3600, // Updated from 300 to 3600 based on tunnel validation
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{},
	},

	// Tunnel Client Parameters (EAA Client Parameters - Tunnel Apps Only)
	"domain_exception_list": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{},
		// Dependency: Domain exception list requires wildcard internal hostname to be enabled
		DependsOn: map[string]string{
			"wildcard_internal_hostname": "true",
		},
	},
	"wildcard_internal_hostname": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{},
	},
	"acceleration": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{},
	},
	"force_ip_route": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileTCP),
			string(AppProfileSMB),
		},
	},

	// Enterprise Connectivity Parameters
	"idle_conn_floor": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 100,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"idle_conn_ceil": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 100,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"idle_conn_step": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 10,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},

	"idle_close_time_seconds": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 1800,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},

	"app_server_read_timeout": {
		Type:     "string",
		MinValue: 1,
		MaxValue: 300,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},
	"hsts_age": {
		Type:     "string",
		MinValue: 0,
		MaxValue: 31536000,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
			string(AppProfileTCP),
		},
	},

	// Related Applications Settings
	"app_bundle": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
		},
		// Note: Detailed validation (VNC/SSH exclusions, etc.) is handled by ValidateRelatedApplications function
	},

	// Additional Authentication Fields (Missing from original generic system)
	"intercept_url": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"form_post_url": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"form_post_attributes": {
		Type: "array",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"app_client_cert_auth": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"app_cookie_domain": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"app_auth_domain": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"jwt_issuers": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: JWT fields require wapp_auth to be "jwt"
		DependsOn: map[string]string{
			"wapp_auth": string(WappAuthTypeJWT),
		},
	},
	"jwt_audience": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: JWT fields require wapp_auth to be "jwt"
		DependsOn: map[string]string{
			"wapp_auth": string(WappAuthTypeJWT),
		},
	},
	"jwt_grace_period": {
		Type:     "string",
		MinValue: 0,
		MaxValue: 3600,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: JWT fields require wapp_auth to be "jwt"
		DependsOn: map[string]string{
			"wapp_auth": string(WappAuthTypeJWT),
		},
	},
	"jwt_return_option": {
		Type: "string",
		ValidValues: []string{
			string(HTTPStatus401),
			string(HTTPStatus302),
		},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: JWT fields require wapp_auth to be "jwt"
		DependsOn: map[string]string{
			"wapp_auth": string(WappAuthTypeJWT),
		},
	},
	"jwt_return_url": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: JWT fields require wapp_auth to be "jwt"
		DependsOn: map[string]string{
			"wapp_auth": string(WappAuthTypeJWT),
		},
	},
	"jwt_username": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
		// Dependency: JWT fields require wapp_auth to be "jwt"
		DependsOn: map[string]string{
			"wapp_auth": string(WappAuthTypeJWT),
		},
	},
	"kerberos_negotiate_once": {
		Type:        "string",
		ValidValues: []string{"on", "off"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"forward_ticket_granting_ticket": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"http_only_cookie": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"disable_user_agent_check": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"preauth_consent": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},
	"sentry_redirect_401": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	// Additional Load Balancing Fields
	"session_sticky_cookie_maxage": {
		Type:     "string",
		MinValue: 0,
		MaxValue: 86400,
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileTCP),
		},
		// Dependency: Only relevant when session_sticky is enabled
		DependsOn: map[string]string{
			"session_sticky": "true",
		},
	},
	"session_sticky_server_cookie": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileTCP),
		},
		// Dependency: Only relevant when session_sticky is enabled
		DependsOn: map[string]string{
			"session_sticky": "true",
		},
	},
	"refresh_sticky_cookie": {
		Type:        "string",
		ValidValues: []string{"on", "off"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
			string(ClientAppTypeTunnel),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileTCP),
		},
		// Dependency: Only relevant when session_sticky is enabled
		DependsOn: map[string]string{
			"session_sticky": "true",
		},
	},

	// Additional Miscellaneous Fields
	// Note: custom_headers validation is handled by ValidateCustomHeadersConfiguration()
	// as it requires complex array/object validation that SETTINGS_RULES cannot handle
	"custom_headers": {
		Type: "array", // Allow complex array validation to pass through
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	// Additional TLS Fields
	"tls_cipher_suite": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	"cookie_domain": {
		Type: "string",
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	// Additional Authentication Fields (from payload analysis)
	"sentry_restore_form_post": {
		Type:        "string",
		ValidValues: []string{"on", "off"},
		AppTypes: []string{
			string(ClientAppTypeEnterprise),
		},
		Profiles: []string{
			string(AppProfileHTTP),
			string(AppProfileSharePoint),
			string(AppProfileJira),
			string(AppProfileJenkins),
			string(AppProfileConfluence),
			string(AppProfileRDP),
			string(AppProfileVNC),
			string(AppProfileSSH),
		},
	},

	// Additional Settings Support
	"edge_authentication_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{string(ClientAppTypeEnterprise)},
		Profiles:    []string{string(AppProfileHTTP), string(AppProfileSharePoint), string(AppProfileJira), string(AppProfileJenkins), string(AppProfileConfluence)},
	},
	"ignore_cname_resolution": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{string(ClientAppTypeEnterprise)},
		Profiles:    []string{string(AppProfileHTTP), string(AppProfileSharePoint), string(AppProfileJira), string(AppProfileJenkins), string(AppProfileConfluence)},
	},
	"g2o_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{string(ClientAppTypeEnterprise)},
		Profiles:    []string{string(AppProfileHTTP), string(AppProfileSharePoint), string(AppProfileJira), string(AppProfileJenkins), string(AppProfileConfluence)},
	},
	"is_ssl_verification_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{string(ClientAppTypeEnterprise), string(ClientAppTypeTunnel)},
		Profiles:    []string{string(AppProfileHTTP), string(AppProfileSharePoint), string(AppProfileJira), string(AppProfileJenkins), string(AppProfileConfluence), string(AppProfileRDP), string(AppProfileVNC), string(AppProfileSSH), string(AppProfileSMB), string(AppProfileTCP)},
	},
	"service_principal_name": {
		Type:     "string",
		AppTypes: []string{string(ClientAppTypeEnterprise)},
		Profiles: []string{string(AppProfileHTTP), string(AppProfileSharePoint), string(AppProfileJira), string(AppProfileJenkins), string(AppProfileConfluence), string(AppProfileRDP)},
	},
	"internal_host_port": {
		Type:     "string",
		AppTypes: []string{string(ClientAppTypeEnterprise), string(ClientAppTypeTunnel)},
		Profiles: []string{string(AppProfileTCP)},
	},
	"internal_hostname": {
		Type:     "string",
		AppTypes: []string{string(ClientAppTypeTunnel)},
		Profiles: []string{string(AppProfileTCP)},
	},
	"ip_access_allow": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{string(ClientAppTypeTunnel)},
		Profiles:    []string{string(AppProfileTCP)},
	},
}

// ValidateAdvancedSettings validates all advanced settings using the generic rules
func ValidateAdvancedSettings(settings map[string]interface{}, appType, appProfile, clientAppMode string, logger hclog.Logger) error {
	logger.Debug("Validating advanced settings for app_type='%s', app_profile='%s', client_app_mode='%s'", appType, appProfile, clientAppMode)

	// Validate each setting
	for settingName, settingValue := range settings {
		rule, exists := SETTINGS_RULES[settingName]
		if !exists {
			logger.Warn("Unknown setting '%s' found in advanced_settings", settingName)
			return fmt.Errorf("unknown setting '%s' in advanced_settings", settingName)
		}

		// Validate the setting against its rule
		if err := validateSetting(settingName, settingValue, rule, settings, appType, appProfile, logger); err != nil {
			return err
		}
	}

	// STEP 2: Call specialized validation modules
	// Dependencies are now handled by SETTINGS_RULES dependency system

	// STEP 2.1: Validate field conflicts using SETTINGS_RULES
	if err := validateFieldConflicts(settings, logger); err != nil {
		return err
	}

	// Format validation is now handled by SETTINGS_RULES validation system

	// STEP 2.2: Context-dependent validation is now handled by SETTINGS_RULES AppTypes/Profiles
	logger.Debug("Context-dependent validation handled by SETTINGS_RULES")

	logger.Debug("Advanced settings validation completed successfully")
	return nil
}

// ValidateHealthCheckConfiguration validates health check configuration using SETTINGS_RULES
func ValidateHealthCheckConfiguration(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	// Check if health check settings are present
	hasHealthCheckSettings := false
	for _, field := range HealthCheckFields {
		if _, exists := settings[field]; exists {
			hasHealthCheckSettings = true
			break
		}
	}

	// If no health check settings are present, skip validation
	if !hasHealthCheckSettings {
		return nil
	}

	logger.Debug("Health check settings found, proceeding with validation using SETTINGS_RULES")

	// Use the existing SETTINGS_RULES validation system for all health check fields
	for _, field := range HealthCheckFields {
		if value, exists := settings[field]; exists {
			// Get the rule for this field from SETTINGS_RULES
			if rule, hasRule := SETTINGS_RULES[field]; hasRule {
				if err := validateSetting(field, value, rule, settings, appType, appProfile, logger); err != nil {
					return err
				}
			} else {
				logger.Warn("No validation rule found for health check field: %s", field)
			}
		}
	}

	// STEP 2: Check for missing required fields when dependencies are met
	logger.Debug("Checking for missing required fields when dependencies are met")
	if err := validateHealthCheckRequiredDependencies(settings, logger); err != nil {
		return err
	}

	logger.Debug("Health check configuration validation completed successfully using SETTINGS_RULES")
	return nil
}

// validateHealthCheckRequiredDependencies validates that required fields are present when dependencies are met
func validateHealthCheckRequiredDependencies(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating health check required dependencies")

	// Check if health_check_type is present and is HTTP or HTTPS
	healthCheckType, exists := settings["health_check_type"]
	if !exists {
		return nil // No health check type specified, no dependencies to check
	}

	healthCheckTypeStr, ok := healthCheckType.(string)
	if !ok {
		return nil // Invalid type, will be caught by other validation
	}

	// Check if health check type requires HTTP-specific fields
	if healthCheckTypeStr == string(HealthCheckTypeHTTP) || healthCheckTypeStr == string(HealthCheckTypeHTTPS) {
		logger.Debug("Health check type is %s, checking for required HTTP fields", healthCheckTypeStr)

		// Define required fields for HTTP/HTTPS health checks (must be present and not empty)
		requiredFields := map[string]string{
			"health_check_http_url":         "health_check_http_url is required when health_check_type is HTTP/HTTPS (e.g., '/health')",
			"health_check_http_version":     "health_check_http_version is required when health_check_type is HTTP/HTTPS (e.g., 'HTTP/1.1')",
			"health_check_http_host_header": "health_check_http_host_header is required when health_check_type is HTTP/HTTPS (e.g., 'myapp.example.com')",
		}

		// Check each required field
		for fieldName, errorMessage := range requiredFields {
			fieldValue, exists := settings[fieldName]
			if !exists {
				logger.Error("Missing required field: %s", fieldName)
				return fmt.Errorf(errorMessage)
			}

			// For health_check_http_url and health_check_http_version, empty strings are not allowed
			if fieldName == "health_check_http_url" || fieldName == "health_check_http_version" {
				if fieldValueStr, ok := fieldValue.(string); ok && fieldValueStr == "" {
					logger.Error("Required field %s is empty", fieldName)
					return fmt.Errorf(errorMessage)
				}
			}
			// For health_check_http_host_header, empty strings are allowed but field must be present

			logger.Debug("Required field %s is present", fieldName)
		}

		logger.Debug("All required HTTP fields are present and valid")
	}

	return nil
}

// validateFieldConflicts validates field conflicts using SETTINGS_RULES
func validateFieldConflicts(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating field conflicts using SETTINGS_RULES")

	// Check each field for conflict rules
	for fieldName, _ := range settings {
		rule, exists := SETTINGS_RULES[fieldName]
		if !exists {
			continue // Skip unknown fields
		}

		// Check if this field has conditional conflict rules
		if rule.Conditional != nil {
			// Check each conditional rule
			for conditionalField, conditionalRules := range rule.Conditional {
				// Get the conditional field value
				conditionalValue, exists := settings[conditionalField]
				if !exists {
					continue
				}

				conditionalValueStr := fmt.Sprintf("%v", conditionalValue)

				// Check if conditional rules exist for this field value
				if conditionalRulesMap, ok := conditionalRules.(map[string]interface{}); ok {
					if fieldRules, hasRules := conditionalRulesMap[conditionalValueStr]; hasRules {
						// Check for ConflictsWith rules
						if fieldRulesMap, ok := fieldRules.(map[string]interface{}); ok {
							if conflictsWith, hasConflictsWith := fieldRulesMap["ConflictsWith"]; hasConflictsWith {
								if conflictsSlice, ok := conflictsWith.([]string); ok {
									// Check if any conflicting fields are present
									for _, conflictField := range conflictsSlice {
										if _, conflictExists := settings[conflictField]; conflictExists {
											logger.Warn("Field conflict detected: %s='%s' conflicts with field '%s'", conditionalField, conditionalValueStr, conflictField)
											return fmt.Errorf("field conflict: %s='%s' conflicts with field '%s'", conditionalField, conditionalValueStr, conflictField)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	logger.Debug("Field conflicts validation completed")
	return nil
}

// validateSetting validates a single setting against its rule
func validateSetting(settingName string, value interface{}, rule SettingRule, settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("Validating setting '%s' with value: %v", settingName, value)

	// Check if setting is allowed for this app type
	if len(rule.AppTypes) > 0 {
		if !contains(rule.AppTypes, appType) {
			return fmt.Errorf("setting '%s' is not allowed for app_type='%s'. Allowed app types: %v",
				settingName, appType, rule.AppTypes)
		}
	}

	// Check if setting is allowed for this app profile
	// Skip profile validation for tunnel apps
	if len(rule.Profiles) > 0 && appType != string(ClientAppTypeTunnel) {
		if !contains(rule.Profiles, appProfile) {
			return fmt.Errorf("setting '%s' is not allowed for app_profile='%s'. Allowed profiles: %v",
				settingName, appProfile, rule.Profiles)
		}
	}

	// Check for blocked profiles in conditional rules is handled in validateConditionalRules below

	// Validate dependencies
	if err := validateSettingDependencies(settingName, rule, settings, logger); err != nil {
		return fmt.Errorf("setting '%s': %v", settingName, err)
	}

	// Check Conditional rules
	if rule.Conditional != nil && len(rule.Conditional) > 0 {
		logger.Debug("Setting '%s' has conditional rules: %v", settingName, rule.Conditional)
		if err := validateConditionalRules(settingName, value, rule.Conditional, settings, appType, appProfile, logger); err != nil {
			return err
		}
	}

	// Validate setting type and value
	if err := validateSettingValue(value, rule, logger); err != nil {
		return fmt.Errorf("setting '%s': %v", settingName, err)
	}

	logger.Debug("Setting '%s' validation passed", settingName)
	return nil
}

// validateSettingDependencies validates field dependencies for a setting
func validateSettingDependencies(settingName string, rule SettingRule, settings map[string]interface{}, logger hclog.Logger) error {
	// Check DependsOn rules
	if rule.DependsOn != nil && len(rule.DependsOn) > 0 {
		for dependentField, requiredValue := range rule.DependsOn {
			logger.Debug("Setting '%s' depends on field '%s' having value '%s'", settingName, dependentField, requiredValue)

			// Check if the dependent field exists in settings
			dependentValue, exists := settings[dependentField]
			if !exists {
				return fmt.Errorf("field '%s' is required for setting '%s'", dependentField, settingName)
			}

			// Check if the dependent field has the required value
			if !validateDependencyValue(dependentValue, requiredValue, logger) {
				return fmt.Errorf("field '%s' must have value '%s' for setting '%s'", dependentField, requiredValue, settingName)
			}
		}
	}

	return nil
}

// validateConditionalRules validates conditional rules for a setting
func validateConditionalRules(settingName string, value interface{}, conditional map[string]interface{}, settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	// Delegate auth-specific conditional checks
	if err := handleAuthConditionalRules(settingName, value, settings, appType, appProfile, logger); err != nil {
		return err
	}

	// Handle conditional rules like: {"wapp_auth": {"certonly": {"ValidValues": ["none", "kerberos", "oidc"]}}}
	for conditionalField, conditionalRules := range conditional {
		logger.Debug("Checking conditional field '%s' for setting '%s'", conditionalField, settingName)

		// Get the conditional field value from settings
		conditionalValue, exists := settings[conditionalField]
		if !exists {
			logger.Debug("Conditional field '%s' not found in settings, skipping conditional validation", conditionalField)
			continue
		}

		// Convert conditional value to string for comparison
		conditionalValueStr := fmt.Sprintf("%v", conditionalValue)

		// Check if conditional rules exist for this field value
		if conditionalRulesMap, ok := conditionalRules.(map[string]interface{}); ok {
			if fieldRules, hasRules := conditionalRulesMap[conditionalValueStr]; hasRules {
				logger.Debug("Found conditional rules for '%s'='%s': %v", conditionalField, conditionalValueStr, fieldRules)

				// Apply the conditional rules
				if err := applyConditionalRules(settingName, value, fieldRules, logger); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// applyConditionalRules applies specific conditional rules to a setting value
func applyConditionalRules(settingName string, value interface{}, rules interface{}, logger hclog.Logger) error {
	if rulesMap, ok := rules.(map[string]interface{}); ok {
		// Handle ValidValues restriction
		if validValues, hasValidValues := rulesMap["ValidValues"]; hasValidValues {
			if validValuesSlice, ok := validValues.([]string); ok {
				valueStr := fmt.Sprintf("%v", value)
				if !contains(validValuesSlice, valueStr) {
					return fmt.Errorf("when conditional rule applies, setting '%s' must be one of %v, got '%s'", settingName, validValuesSlice, valueStr)
				}
				logger.Debug("Conditional ValidValues validation passed for '%s': '%s' ∈ %v", settingName, valueStr, validValuesSlice)
			}
		}

		// Handle Exclude restriction
		if exclude, hasExclude := rulesMap["Exclude"]; hasExclude {
			if excludeSlice, ok := exclude.([]string); ok {
				valueStr := fmt.Sprintf("%v", value)
				if contains(excludeSlice, valueStr) {
					return fmt.Errorf("setting '%s'='%s' is not allowed for this profile. Excluded values: %v", settingName, valueStr, excludeSlice)
				}
				logger.Debug("Exclude validation passed for '%s': '%s' not in %v", settingName, valueStr, excludeSlice)
			}
		}

		// Handle Condition restriction (e.g., "wapp_auth == certonly")
		if condition, hasCondition := rulesMap["Condition"]; hasCondition {
			if conditionStr, ok := condition.(string); ok {
				// Note: We need access to settings to evaluate conditions properly
				// For now, we'll skip condition evaluation and apply the rule
				logger.Debug("Condition '%s' found for '%s', applying rule", conditionStr, settingName)
			}
		}

		// Handle blocked_profiles restriction
		if blockedProfiles, hasBlockedProfiles := rulesMap["blocked_profiles"]; hasBlockedProfiles {
			if blockedProfilesSlice, ok := blockedProfiles.([]string); ok {
				// This will be handled by the profile validation in the main validation function
				logger.Debug("Conditional blocked_profiles validation for '%s': %v", settingName, blockedProfilesSlice)
			}
		}

		// Handle ConflictsWith restriction
		if conflictsWith, hasConflictsWith := rulesMap["ConflictsWith"]; hasConflictsWith {
			if conflictsSlice, ok := conflictsWith.([]string); ok {
				logger.Debug("Checking ConflictsWith rule for '%s': %v", settingName, conflictsSlice)
				// Note: Conflict validation is handled at the field level, not the value level
				// This is just a placeholder for the rule structure
				logger.Debug("ConflictsWith rule structure validated for '%s'", settingName)
			}
		}

		// Handle other conditional rules (MinValue, MaxValue, etc.)
		// TODO: Add more conditional rule types as needed
	}

	return nil
}

// validateDependencyValue checks if a field value matches the required dependency value
func validateDependencyValue(fieldValue interface{}, requiredValue string, logger hclog.Logger) bool {
	// Handle different value types
	switch v := fieldValue.(type) {
	case string:
		// Support multiple values separated by | (OR logic)
		if strings.Contains(requiredValue, "|") {
			allowedValues := strings.Split(requiredValue, "|")
			for _, allowedValue := range allowedValues {
				if strings.TrimSpace(allowedValue) == v {
					return true
				}
			}
			return false
		}
		return v == requiredValue
	case bool:
		// Convert boolean to string for comparison
		boolStr := fmt.Sprintf("%t", v)
		return boolStr == requiredValue
	case int:
		// Convert int to string for comparison
		intStr := fmt.Sprintf("%d", v)
		return intStr == requiredValue
	default:
		logger.Warn("Unsupported dependency value type: %T", fieldValue)
		return false
	}
}

// validateSettingValue validates the value of a setting based on its type and constraints
func validateSettingValue(value interface{}, rule SettingRule, logger hclog.Logger) error {
	// Handle null values
	if value == nil {
		if rule.Required {
			return fmt.Errorf("required setting cannot be null")
		}
		return nil // null is allowed for optional settings
	}

	// Use reflect for comprehensive type checking
	valueType := reflect.TypeOf(value)
	valueKind := valueType.Kind()

	switch rule.Type {
	case "string":
		return validateStringSettingWithReflect(value, valueKind, rule, logger)
	case "int":
		return validateIntSettingWithReflect(value, valueKind, rule, logger)
	case "array":
		return validateArraySettingWithReflect(value, valueKind, rule, logger)
	default:
		return fmt.Errorf("unsupported setting type: %s", rule.Type)
	}
}

// validateStringSettingWithReflect validates string settings using reflect for comprehensive type checking
func validateStringSettingWithReflect(value interface{}, kind reflect.Kind, rule SettingRule, logger hclog.Logger) error {
	var strValue string

	// Handle different input types more comprehensively
	switch kind {
	case reflect.String:
		strValue = value.(string)
	case reflect.Ptr:
		// Handle pointer types (*string, *int, etc.)
		ptrValue := reflect.ValueOf(value)
		if ptrValue.IsNil() {
			// Null pointer - check if required
			if rule.Required {
				return fmt.Errorf("required setting cannot be null")
			}
			return nil // null is allowed for optional settings
		}
		// Dereference the pointer and validate the underlying value
		elemValue := ptrValue.Elem()
		elemKind := elemValue.Kind()

		switch elemKind {
		case reflect.String:
			strValue = elemValue.String()
			logger.Debug("Dereferenced string pointer to '%s'", strValue)
		case reflect.Bool:
			boolValue := elemValue.Bool()
			strValue = fmt.Sprintf("%t", boolValue)
			logger.Debug("Dereferenced boolean pointer %v to string '%s'", boolValue, strValue)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			intValue := elemValue.Int()
			strValue = fmt.Sprintf("%d", intValue)
			logger.Debug("Dereferenced integer pointer %d to string '%s'", intValue, strValue)
		case reflect.Float32, reflect.Float64:
			floatValue := elemValue.Float()
			strValue = fmt.Sprintf("%.0f", floatValue)
			logger.Debug("Dereferenced float pointer %.0f to string '%s'", floatValue, strValue)
		default:
			return fmt.Errorf("unsupported pointer element type: %s", elemKind)
		}
	case reflect.Bool:
		// Convert boolean to string representation
		boolValue := value.(bool)
		strValue = fmt.Sprintf("%t", boolValue)
		logger.Debug("Converted boolean %v to string '%s'", boolValue, strValue)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Convert integer to string
		intValue := reflect.ValueOf(value).Int()
		strValue = fmt.Sprintf("%d", intValue)
		logger.Debug("Converted integer %d to string '%s'", intValue, strValue)
	case reflect.Float32, reflect.Float64:
		// Convert float to string
		floatValue := reflect.ValueOf(value).Float()
		strValue = fmt.Sprintf("%.0f", floatValue)
		logger.Debug("Converted float %.0f to string '%s'", floatValue, strValue)
	default:
		return fmt.Errorf("expected string-compatible type, got %s", kind)
	}

	// Check if empty string is allowed
	if strValue == "" && rule.Required {
		return fmt.Errorf("required setting cannot be empty")
	}

	// Validate enum values
	if len(rule.ValidValues) > 0 {
		if !contains(rule.ValidValues, strValue) {
			return fmt.Errorf("must be one of %v, got '%s'", rule.ValidValues, strValue)
		}
	}

	return nil
}

// validateStringSetting validates string settings (legacy function for backward compatibility)
func validateStringSetting(value interface{}, rule SettingRule, logger hclog.Logger) error {
	strValue, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}

	// Check if empty string is allowed
	if strValue == "" && rule.Required {
		return fmt.Errorf("required setting cannot be empty")
	}

	// Validate enum values
	if len(rule.ValidValues) > 0 {
		if !contains(rule.ValidValues, strValue) {
			return fmt.Errorf("must be one of %v, got '%s'", rule.ValidValues, strValue)
		}
	}

	return nil
}

// validateIntSetting validates integer settings
func validateIntSetting(value interface{}, rule SettingRule, logger hclog.Logger) error {
	var intValue int

	switch v := value.(type) {
	case int:
		intValue = v
	case float64:
		intValue = int(v)
	case string:
		// Handle string-to-integer mapping only for TLS suite types
		if rule.ValidValues != nil && len(rule.ValidValues) > 0 && rule.ValidValues[0] == "default" {
			// This is a TLS suite type field that accepts "default" or "custom"
			switch v {
			case "default":
				intValue = 1
			case "custom":
				intValue = 2
			default:
				return fmt.Errorf("expected 'default' or 'custom', got '%s'", v)
			}
		} else {
			// For other integer fields, try to parse the string as an integer
			if parsed, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("expected integer, got '%s'", v)
			} else {
				intValue = parsed
			}
		}
	default:
		return fmt.Errorf("expected integer, got %T", value)
	}

	// Validate range
	if rule.MinValue != 0 || rule.MaxValue != 0 {
		if intValue < rule.MinValue || intValue > rule.MaxValue {
			return fmt.Errorf("must be between %d and %d, got %d", rule.MinValue, rule.MaxValue, intValue)
		}
	}

	// Validate enum values (for string representations of integers and string mappings)
	if len(rule.ValidValues) > 0 {
		// Check if the original value was a string that maps to this integer
		if strValue, ok := value.(string); ok {
			if !contains(rule.ValidValues, strValue) {
				return fmt.Errorf("must be one of %v, got '%s'", rule.ValidValues, strValue)
			}
		} else {
			// For integer values, check the string representation
			strValue := strconv.Itoa(intValue)
			if !contains(rule.ValidValues, strValue) {
				return fmt.Errorf("must be one of %v, got %d", rule.ValidValues, intValue)
			}
		}
	}

	return nil
}

// validateIntSettingWithReflect validates integer settings using reflect for comprehensive type checking
func validateIntSettingWithReflect(value interface{}, kind reflect.Kind, rule SettingRule, logger hclog.Logger) error {
	var intValue int

	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intValue = int(reflect.ValueOf(value).Int())
		logger.Debug("Validated integer value: %d", intValue)
	case reflect.Ptr:
		// Handle pointer types (*int, *string, etc.)
		ptrValue := reflect.ValueOf(value)
		if ptrValue.IsNil() {
			// Null pointer - check if required
			if rule.Required {
				return fmt.Errorf("required setting cannot be null")
			}
			return nil // null is allowed for optional settings
		}
		// Dereference the pointer and validate the underlying value
		elemValue := ptrValue.Elem()
		elemKind := elemValue.Kind()

		switch elemKind {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			intValue = int(elemValue.Int())
			logger.Debug("Dereferenced integer pointer to %d", intValue)
		case reflect.Float32, reflect.Float64:
			floatVal := elemValue.Float()
			intValue = int(floatVal)
			logger.Debug("Dereferenced float pointer %.2f to int %d", floatVal, intValue)
		case reflect.String:
			strVal := elemValue.String()
			// Handle string-to-integer mapping for enum fields
			if rule.ValidValues != nil && len(rule.ValidValues) > 0 {
				// Check if this is an enum field that maps strings to integers
				if contains(rule.ValidValues, strVal) {
					// Map enum string values to integers based on their position
					for i, validValue := range rule.ValidValues {
						if validValue == strVal {
							intValue = i + 1 // Start from 1, not 0
							logger.Debug("Dereferenced enum '%s' (position %d) to int %d", strVal, i, intValue)
							break
						}
					}
				} else {
					return fmt.Errorf("must be one of %v, got '%s'", rule.ValidValues, strVal)
				}
			} else {
				// For other integer fields, try to parse the string as an integer
				if parsed, err := strconv.Atoi(strVal); err != nil {
					return fmt.Errorf("expected integer, got '%s'", strVal)
				} else {
					intValue = parsed
					logger.Debug("Dereferenced string '%s' to int %d", strVal, intValue)
				}
			}
		case reflect.Bool:
			// Convert boolean to integer (true=1, false=0)
			boolVal := elemValue.Bool()
			if boolVal {
				intValue = 1
			} else {
				intValue = 0
			}
			logger.Debug("Dereferenced boolean pointer %v to int %d", boolVal, intValue)
		default:
			return fmt.Errorf("unsupported pointer element type: %s", elemKind)
		}
	case reflect.Float32, reflect.Float64:
		floatVal := reflect.ValueOf(value).Float()
		intValue = int(floatVal)
		logger.Debug("Converted float %.2f to int %d", floatVal, intValue)
	case reflect.String:
		strVal := reflect.ValueOf(value).String()
		// Handle string-to-integer mapping for enum fields
		if rule.ValidValues != nil && len(rule.ValidValues) > 0 {
			// Check if this is an enum field that maps strings to integers
			if contains(rule.ValidValues, strVal) {
				// Map enum string values to integers based on their position
				for i, validValue := range rule.ValidValues {
					if validValue == strVal {
						intValue = i + 1 // Start from 1, not 0
						logger.Debug("Converted enum '%s' (position %d) to int %d", strVal, i, intValue)
						break
					}
				}
			} else {
				return fmt.Errorf("must be one of %v, got '%s'", rule.ValidValues, strVal)
			}
		} else {
			// For other integer fields, try to parse the string as an integer
			if parsed, err := strconv.Atoi(strVal); err != nil {
				return fmt.Errorf("expected integer, got '%s'", strVal)
			} else {
				intValue = parsed
				logger.Debug("Converted string '%s' to int %d", strVal, intValue)
			}
		}
	case reflect.Bool:
		// Convert boolean to integer (true=1, false=0)
		boolVal := reflect.ValueOf(value).Bool()
		if boolVal {
			intValue = 1
		} else {
			intValue = 0
		}
		logger.Debug("Converted boolean %v to int %d", boolVal, intValue)
	default:
		return fmt.Errorf("expected integer-compatible type, got %s", kind)
	}

	// Validate range
	if rule.MinValue != 0 || rule.MaxValue != 0 {
		if intValue < rule.MinValue || intValue > rule.MaxValue {
			return fmt.Errorf("must be between %d and %d, got %d", rule.MinValue, rule.MaxValue, intValue)
		}
		logger.Debug("Integer value %d is within valid range [%d, %d]", intValue, rule.MinValue, rule.MaxValue)
	}

	// Validate enum values (for string representations of integers and string mappings)
	if len(rule.ValidValues) > 0 {
		// Check if the original value was a string that maps to this integer
		if strValue, ok := value.(string); ok {
			if !contains(rule.ValidValues, strValue) {
				return fmt.Errorf("must be one of %v, got '%s'", rule.ValidValues, strValue)
			}
		} else {
			// For integer values, check the string representation
			strValue := strconv.Itoa(intValue)
			if !contains(rule.ValidValues, strValue) {
				return fmt.Errorf("must be one of %v, got %d", rule.ValidValues, intValue)
			}
		}
	}

	return nil
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// validateCORSFields validates CORS fields (non-tunnel apps only)
func validateCORSFields(settings map[string]interface{}, appType string) error {
	// CORS fields are not available for tunnel apps
	// Based on HTML: ng-if="$ctrl.application.app_type!==$ctrl.ApplicationType.APP_TYPE_TUNNEL"
	corsFields := []string{"allow_cors", "cors_origin_list", "cors_header_list", "cors_method_list", "cors_support_credential", "cors_max_age"}

	for _, field := range corsFields {
		if _, exists := settings[field]; exists {
			if appType == "tunnel" {
				return ErrMiscFieldNotAvailableForTunnel
			}
		}
	}

	// Additional validation: CORS detail fields only when allow_cors is true
	if allowCors, exists := settings["allow_cors"]; exists {
		if allowCors == "true" {
			requiredCorsFields := []string{"cors_origin_list", "cors_header_list", "cors_method_list", "cors_support_credential", "cors_max_age"}
			for _, field := range requiredCorsFields {
				if _, fieldExists := settings[field]; !fieldExists {
					return ErrMiscCORSFieldRequired
				}
			}
		}
	}

	return nil
}

// validateArraySettingWithReflect validates array settings using reflect for comprehensive type checking
func validateArraySettingWithReflect(value interface{}, kind reflect.Kind, rule SettingRule, logger hclog.Logger) error {
	// For custom_headers, we just need to ensure it's an array/slice
	// The detailed validation is handled by ValidateCustomHeadersConfiguration()
	switch kind {
	case reflect.Slice, reflect.Array:
		logger.Debug("Array setting validated successfully")
		return nil
	default:
		return fmt.Errorf("setting must be an array, got %s", kind)
	}
}
