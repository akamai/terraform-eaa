package eaaprovider

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/go-hclog"
)

// SettingRule defines validation rules for a specific advanced setting
type SettingRule struct {
	Type        string   // Field type: "string", "int", "bool"
	ValidValues []string // Allowed values (for enum fields)
	AppTypes    []string // Allowed app types
	Profiles    []string // Allowed app profiles
	MinValue    int      // Minimum value for numeric fields
	MaxValue    int      // Maximum value for numeric fields
	Required    bool     // Whether field is required
}

// SETTINGS_RULES defines validation rules for all advanced settings
var SETTINGS_RULES = map[string]SettingRule{
	// Authentication Settings
	"app_auth": {
		Type:        "string",
		ValidValues: []string{"none", "kerberos", "basic", "NTLMv1", "NTLMv2"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"wapp_auth": {
		Type:        "string",
		ValidValues: []string{"form", "basic", "basic_cookie", "jwt", "certonly"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"login_url": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"logout_url": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"service_principle_name": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"keytab": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},

	// Health Check Settings
	"health_check_type": {
		Type:        "string",
		ValidValues: []string{"Default", "HTTP", "HTTPS", "TLS", "SSLv3", "TCP", "None"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"health_check_http_url": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"health_check_http_version": {
		Type:        "string",
		ValidValues: []string{"1.0", "1.1"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"health_check_http_host_header": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"health_check_rise": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 10,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"health_check_fall": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 10,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"health_check_timeout": {
		Type:     "int",
		MinValue: 1000,
		MaxValue: 300000,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"health_check_interval": {
		Type:     "int",
		MinValue: 1000,
		MaxValue: 300000,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},

	// Server Load Balancing Settings
	"load_balancing_metric": {
		Type:        "string",
		ValidValues: []string{"round-robin", "ip-hash"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "tcp", "smb"},
	},
	"session_sticky": {
		Type:        "bool",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "tcp", "smb"},
	},
	"cookie_age": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 86400,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"tcp_optimization": {
		Type:        "string",
		ValidValues: []string{"on", "off"},
		AppTypes:    []string{"tunnel"},
		Profiles:    []string{"tcp"},
	},

	// RDP Configuration Settings
	"rdp_initial_program": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_app": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_app_args": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_app_dir": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"rdp_tls1": {
		Type:     "bool",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"rdp_keyboard_lang": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"rdp_window_color_depth": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"rdp_window_height": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"rdp_window_width": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},

	// RDP Remote Spark Features (RDP V2 only)
	"remote_spark_mapClipboard": {
		Type:     "bool",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"rdp_legacy_mode": {
		Type:     "bool",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_spark_audio": {
		Type:     "bool",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_spark_mapPrinter": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_spark_printer": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_spark_mapDisk": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_spark_disk": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},
	"remote_spark_recording": {
		Type:     "bool",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"rdp"},
	},

	// TLS Configuration Settings
	"tlsSuiteType": {
		Type:        "string",
		ValidValues: []string{"default", "custom"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http", "rdp", "vnc", "ssh"},
	},
	"tls_suite_name": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http", "rdp", "vnc", "ssh"},
	},

	// Miscellaneous Settings
	"proxy_buffer_size_kb": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 1000,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "tcp"},
	},
	"ssh_audit_enabled": {
		Type:     "bool",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"ssh"},
	},
	"allow_cors": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"cors_origin_list": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},
	"cors_header_list": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},
	"cors_method_list": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},
	"cors_support_credential": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"cors_max_age": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 86400,
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},
	"websocket_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "tcp"},
	},
	"https_sslv3": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"logging_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "tcp"},
	},
	"hidden_app": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"saas_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"sticky_agent": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "tcp"},
	},
	"x_wapp_read_timeout": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 300,
		AppTypes: []string{"tunnel"},
		Profiles: []string{"tcp"},
	},
	"dynamic_ip": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http", "tcp"},
	},
	"sticky_cookies": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"offload_onpremise_traffic": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"x_wapp_pool_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false", "inherit"},
		AppTypes:    []string{"tunnel"},
		Profiles:    []string{"tcp"},
	},
	"x_wapp_pool_size": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 50,  // Updated from 100 to 50 based on tunnel validation
		AppTypes: []string{"tunnel"},
		Profiles: []string{"tcp"},
	},
	"x_wapp_pool_timeout": {
		Type:     "int",
		MinValue: 60,   // Updated from 1 to 60 based on tunnel validation
		MaxValue: 3600, // Updated from 300 to 3600 based on tunnel validation
		AppTypes: []string{"tunnel"},
		Profiles: []string{"tcp"},
	},

	// Tunnel Client Parameters (EAA Client Parameters - Tunnel Apps Only)
	"domain_exception_list": {
		Type:     "string",
		AppTypes: []string{"tunnel"},
		Profiles: []string{"tcp"},
	},
	"wildcard_internal_hostname": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"tunnel"},
		Profiles:    []string{"tcp"},
	},
	"acceleration": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"tunnel"},
		Profiles:    []string{"tcp"},
	},
	"force_ip_route": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"tunnel"},
		Profiles:    []string{"tcp"},
	},

	// Enterprise Connectivity Parameters
	"idle_conn_floor": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 100,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "tcp"},
	},
	"idle_conn_ceil": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 100,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "tcp"},
	},
	"idle_conn_step": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 10,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "tcp"},
	},
	"idle_close_time_seconds": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 3600,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "tcp"},
	},
	"max_conn_floor": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 1000,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"max_conn_ceil": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 1000,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"max_conn_step": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 100,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"conn_retry_interval": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 3600,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"conn_retry_max_attempts": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 100,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"conn_retry_max_interval": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 3600,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "rdp", "tcp", "vnc", "ssh", "smb"},
	},
	"app_server_read_timeout": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 300,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "tcp"},
	},
	"hsts_age": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 31536000,
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},

	// Related Applications Settings
	"app_bundle": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http", "https", "tcp", "rdp"},
	},

	// Additional Miscellaneous Fields
	"ignore_cname_resolution": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "https", "tcp", "rdp", "vnc", "ssh", "smb"},
	},

	// Additional Authentication Fields (Missing from original generic system)
	"intercept_url": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"form_post_url": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"form_post_attributes": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"app_client_cert_auth": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"app_cookie_domain": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"app_auth_domain": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"jwt_issuers": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"jwt_audience": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"jwt_grace_period": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 3600,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"jwt_return_option": {
		Type:        "string",
		ValidValues: []string{"redirect", "post"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"jwt_return_url": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"jwt_username": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"kerberos_negotiate_once": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"forward_ticket_granting_ticket": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"http_only_cookie": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"disable_user_agent_check": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"preauth_consent": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"sentry_redirect_401": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},

	// Additional Load Balancing Fields
	"session_sticky_cookie_maxage": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 86400,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"session_sticky_server_cookie": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"refresh_sticky_cookie": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},

	// Edge Transport Fields
	"edge_authentication_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"edge_cookie_key": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},
	"sla_object_url": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},
	"g2o_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise"},
		Profiles:    []string{"http"},
	},
	"g2o_key": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},
	"g2o_nonce": {
		Type:     "string",
		AppTypes: []string{"enterprise"},
		Profiles: []string{"http"},
	},

	// Additional Miscellaneous Fields
	"custom_headers": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"enable_client_side_xhr_rewrite": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"is_brotli_enabled": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"inject_ajax_javascript": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"internal_host_port": {
		Type:     "int",
		MinValue: 1,
		MaxValue: 65535,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"onramp": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"proxy_disable_clipboard": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"rate_limit": {
		Type:     "int",
		MinValue: 0,
		MaxValue: 10000,
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},
	"request_body_rewrite": {
		Type:        "string",
		ValidValues: []string{"true", "false"},
		AppTypes:    []string{"enterprise", "tunnel"},
		Profiles:    []string{"http"},
	},
	"request_parameters": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http"},
	},

	// Additional TLS Fields
	"tls_cipher_suite": {
		Type:     "string",
		AppTypes: []string{"enterprise", "tunnel"},
		Profiles: []string{"http", "tcp"},
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
		if err := validateSetting(settingName, settingValue, rule, appType, appProfile, logger); err != nil {
			return err
		}
	}

	// STEP 2: Call specialized validation modules
	if err := ValidateAdvancedSettingsDependencies(settings, logger); err != nil {
		return err
	}

	if err := ValidateAdvancedSettingsConflicts(settings, logger); err != nil {
		return err
	}

	if err := ValidateAdvancedSettingsFormats(settings, logger); err != nil {
		return err
	}

	if err := ValidateAdvancedSettingsContext(settings, appType, appProfile, clientAppMode, logger); err != nil {
		return err
	}

	logger.Debug("Advanced settings validation completed successfully")
	return nil
}

// validateSetting validates a single setting against its rule
func validateSetting(settingName string, value interface{}, rule SettingRule, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("Validating setting '%s' with value: %v", settingName, value)

	// Check if setting is allowed for this app type
	if len(rule.AppTypes) > 0 {
		if !contains(rule.AppTypes, appType) {
			return fmt.Errorf("setting '%s' is not allowed for app_type='%s'. Allowed app types: %v", 
				settingName, appType, rule.AppTypes)
		}
	}

	// Check if setting is allowed for this app profile
	if len(rule.Profiles) > 0 {
		if !contains(rule.Profiles, appProfile) {
			return fmt.Errorf("setting '%s' is not allowed for app_profile='%s'. Allowed profiles: %v", 
				settingName, appProfile, rule.Profiles)
		}
	}

	// Validate setting type and value
	if err := validateSettingValue(value, rule, logger); err != nil {
		return fmt.Errorf("setting '%s': %v", settingName, err)
	}

	logger.Debug("Setting '%s' validation passed", settingName)
	return nil
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

	switch rule.Type {
	case "string":
		return validateStringSetting(value, rule, logger)
	case "int":
		return validateIntSetting(value, rule, logger)
	case "bool":
		return validateBoolSetting(value, rule, logger)
	default:
		return fmt.Errorf("unsupported setting type: %s", rule.Type)
	}
}

// validateStringSetting validates string settings
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

// validateBoolSetting validates boolean settings
func validateBoolSetting(value interface{}, rule SettingRule, logger hclog.Logger) error {
	_, ok := value.(bool)
	if !ok {
		return fmt.Errorf("expected boolean, got %T", value)
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
