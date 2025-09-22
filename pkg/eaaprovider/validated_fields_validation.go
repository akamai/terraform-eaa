package eaaprovider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// ValidatedFieldsMap contains all fields that are exposed in HTML UI and allowed for user configuration
var ValidatedFieldsMap = map[string]bool{
	// Authentication Fields (from HTML UI)
	"login_url":                        true,
	"logout_url":                       true,
	"wapp_auth":                        true,
	"app_auth":                         true,
	"intercept_url":                    true,
	"form_post_url":                    true,
	"form_post_attributes":             true,
	"app_client_cert_auth":             true,
	"app_cookie_domain":                true,
	"jwt_issuers":                      true,
	"jwt_audience":                     true,
	"jwt_grace_period":                 true,
	"jwt_return_option":                true,
	"jwt_return_url":                   true,
	"jwt_username":                     true,
	"app_auth_domain":                  true,
	"service_principle_name":           true,
	"keytab":                           true,
	"kerberos_negotiate_once":          true,
	"forward_ticket_granting_ticket":   true,
	"http_only_cookie":                 true,
	"disable_user_agent_check":         true,
	"preauth_consent":                  true,
	"sentry_redirect_401":              true,

	// Server Load Balancing Fields (from HTML UI)
	"load_balancing_metric":            true,
	"session_sticky":                   true,
	"session_sticky_cookie_maxage":     true,
	"session_sticky_server_cookie":     true,
	"refresh_sticky_cookie":            true,

	// Health Check Fields (from HTML UI)
	"health_check_type":                true,
	"health_check_http_url":            true,
	"health_check_http_host_header":    true,
	"health_check_http_version":        true,
	"health_check_rise":                true,
	"health_check_fall":                true,
	"health_check_timeout":             true,
	"health_check_interval":            true,

	// Custom HTTP Headers Fields (from HTML UI)
	"custom_headers":                   true,

	// Client Parameters Fields (from HTML UI)
	"domain_exception_list":            true,
	"acceleration":                     true,
	"force_ip_route":                   true,
	"x_wapp_pool_enabled":              true,
	"x_wapp_pool_size":                 true,
	"x_wapp_pool_timeout":              true,

	// Connectivity Parameters Fields (from HTML UI)
	"idle_conn_floor":                  true,
	"idle_conn_ceil":                   true,
	"idle_conn_step":                   true,
	"idle_close_time_seconds":          true,
	"app_server_read_timeout":          true,
	"hsts_age":                         true,

	// Edge Transport Fields (from HTML UI)
	"edge_authentication_enabled":      true,
	"edge_cookie_key":                  true,
	"sla_object_url":                   true,
	"g2o_enabled":                      true,
	"g2o_key":                          true,
	"g2o_nonce":                        true,

	// Miscellaneous Fields (from HTML UI)
	"proxy_buffer_size_kb":             true,
	"ssh_audit_enabled":                true,
	"allow_cors":                       true,
	"cors_origin_list":                 true,
	"cors_header_list":                 true,
	"cors_method_list":                 true,
	"cors_support_credential":          true,
	"cors_max_age":                     true,
	"websocket_enabled":                true,
	"https_sslv3":                      true,
	"logging_enabled":                  true,
	"hidden_app":                       true,
	"saas_enabled":                     true,
	"sticky_agent":                     true,
	"x_wapp_read_timeout":              true,
	"offload_onpremise_traffic":        true,
	"enable_client_side_xhr_rewrite":   true,
	"is_brotli_enabled":                true,

	// TLS Cipher Suite Fields (from HTML UI)
	"tlsSuiteType":                     true,
	"tls_suite_name":                   true,
	"tls_cipher_suite":                 true,

	// Related Applications Fields (from HTML UI)
	"app_bundle":                       true,

	// RDP Configuration Fields (from HTML UI)
	"rdp_initial_program":              true,
	"remote_app":                       true,
	"remote_app_args":                  true,
	"remote_app_dir":                   true,
	"rdp_tls1":                         true,
	"remote_spark_mapClipboard":        true,
	"rdp_legacy_mode":                  true,
	"remote_spark_audio":               true,
	"remote_spark_mapPrinter":          true,
	"remote_spark_printer":             true,
	"remote_spark_mapDisk":             true,
	"remote_spark_disk":                true,
	"remote_spark_recording":           true,

	// Additional fields that might be used
	"user_name":                        true,
	"pass_phrase":                      true,
	"private_key":                      true,
	"sign_cert":                        true,
	"sign_key":                         true,
	"self_signed":                      true,
}

// BlockedFieldsMap contains fields that should be blocked and use defaults
var BlockedFieldsMap = map[string]string{
	"app_location":                        "This field is not exposed in the UI and should not be configured by users",
	"client_cert_auth":                    "This field is not exposed in the UI and should not be configured by users",
	"client_cert_user_param":               "This field is not exposed in the UI and should not be configured by users",
	"cookie_domain":                        "This field is not exposed in the UI and should not be configured by users",
	"force_mfa":                           "This field is not exposed in the UI and should not be configured by users",
	"idp_idle_expiry":                     "This field is not exposed in the UI and should not be configured by users",
	"idp_max_expiry":                      "This field is not exposed in the UI and should not be configured by users",
	"ignore_bypass_mfa":                   "This field is not exposed in the UI and should not be configured by users",
	"mfa":                                 "This field is not exposed in the UI and should not be configured by users",
	"preauth_enforce_url":                 "This field is not exposed in the UI and should not be configured by users",
	"sso":                                 "This field is not exposed in the UI and should not be configured by users",
	"anonymous_server_conn_limit":         "This field is not exposed in the UI and should not be configured by users",
	"anonymous_server_request_limit":       "This field is not exposed in the UI and should not be configured by users",
	"authenticated_server_conn_limit":     "This field is not exposed in the UI and should not be configured by users",
	"authenticated_server_request_limit":  "This field is not exposed in the UI and should not be configured by users",
	"keepalive_connection_pool":           "This field is not exposed in the UI and should not be configured by users",
	"keepalive_enable":                    "This field is not exposed in the UI and should not be configured by users",
	"keepalive_timeout":                   "This field is not exposed in the UI and should not be configured by users",
	"keyed_keepalive_enable":              "This field is not exposed in the UI and should not be configured by users",
	"server_request_burst":                "This field is not exposed in the UI and should not be configured by users",
	"spdy_enabled":                        "This field is not exposed in the UI and should not be configured by users",
	"rdp_initial_program":                 "This field is not exposed in the UI and should not be configured by users",
	"remote_app":                          "This field is not exposed in the UI and should not be configured by users",
	"remote_app_args":                     "This field is not exposed in the UI and should not be configured by users",
	"remote_app_dir":                      "This field is not exposed in the UI and should not be configured by users",
	"rdp_tls1":                           "This field is not exposed in the UI and should not be configured by users",
	"remote_spark_mapClipboard":           "This field is not exposed in the UI and should not be configured by users",
	"rdp_legacy_mode":                    "This field is not exposed in the UI and should not be configured by users",
	"remote_spark_audio":                  "This field is not exposed in the UI and should not be configured by users",
	"remote_spark_mapPrinter":             "This field is not exposed in the UI and should not be configured by users",
	"remote_spark_printer":                "This field is not exposed in the UI and should not be configured by users",
	"remote_spark_mapDisk":                "This field is not exposed in the UI and should not be configured by users",
	"remote_spark_disk":                   "This field is not exposed in the UI and should not be configured by users",
	"remote_spark_recording":              "This field is not exposed in the UI and should not be configured by users",
	"single_host_content_rw":               "This field is not exposed in the UI and should not be configured by users",
	"single_host_cookie_domain":           "This field is not exposed in the UI and should not be configured by users",
	"single_host_enable":                  "This field is not exposed in the UI and should not be configured by users",
	"single_host_fqdn":                    "This field is not exposed in the UI and should not be configured by users",
	"single_host_path":                    "This field is not exposed in the UI and should not be configured by users",
	"inject_ajax_javascript":              "This field is not exposed in the UI and should not be configured by users",
	"internal_host_port":                  "This field is not exposed in the UI and should not be configured by users",
	"login_timeout":                       "This field is not exposed in the UI and should not be configured by users",
	"mdc_enable":                          "This field is not exposed in the UI and should not be configured by users",
	"onramp":                              "This field is not exposed in the UI and should not be configured by users",
	"pass_phrase":                         "This field is not exposed in the UI and should not be configured by users",
	"private_key":                         "This field is not exposed in the UI and should not be configured by users",
	"proxy_disable_clipboard":             "This field is not exposed in the UI and should not be configured by users",
	"rate_limit":                          "This field is not exposed in the UI and should not be configured by users",
	"request_body_rewrite":                "This field is not exposed in the UI and should not be configured by users",
	"request_parameters":                  "This field is not exposed in the UI and should not be configured by users",
	"segmentation_policy_enable":          "This field is not exposed in the UI and should not be configured by users",
	"sentry_restore_form_post":            "This field is not exposed in the UI and should not be configured by users",
	"user_name":                           "This field is not exposed in the UI and should not be configured by users",
}

// validateOnlyAllowedFields validates that only validated fields are present in advanced_settings
func validateOnlyAllowedFields(settings map[string]interface{}, logger hclog.Logger) error {
	var blockedFields []string

	// Check each field in the settings
	for fieldName := range settings {
		// Skip if it's a validated field
		if ValidatedFieldsMap[fieldName] {
			logger.Debug("Field '%s' is validated and allowed", fieldName)
			continue
		}

		// Check if it's a blocked field
		if reason, isBlocked := BlockedFieldsMap[fieldName]; isBlocked {
			logger.Warn("Field '%s' is blocked: %s", fieldName, reason)
			blockedFields = append(blockedFields, fmt.Sprintf("'%s': %s", fieldName, reason))
		} else {
			// Unknown field - also block it
			logger.Warn("Unknown field '%s' is not validated and should not be configured", fieldName)
			blockedFields = append(blockedFields, fmt.Sprintf("'%s': This field is not validated and should not be configured by users", fieldName))
		}
	}

	// If there are blocked fields, return an error
	if len(blockedFields) > 0 {
		errorMsg := fmt.Sprintf("The following fields are not allowed in advanced_settings and should use system defaults: %s",
			strings.Join(blockedFields, ", "))
		logger.Error("Blocked fields detected: %s", errorMsg)
		return fmt.Errorf(errorMsg)
	}

	logger.Debug("All fields in advanced_settings are validated and allowed")
	return nil
}

// GetValidatedFieldsList returns a list of all validated fields for documentation
func GetValidatedFieldsList() []string {
	var fields []string
	for field := range ValidatedFieldsMap {
		fields = append(fields, field)
	}
	return fields
}

// GetBlockedFieldsList returns a list of all blocked fields for documentation
func GetBlockedFieldsList() []string {
	var fields []string
	for field := range BlockedFieldsMap {
		fields = append(fields, field)
	}
	return fields
}
