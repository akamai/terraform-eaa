package eaaprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// validateAdvancedSettingsWithAppTypeAndProfile validates advanced_settings with app_type and app_profile context
func validateAdvancedSettingsWithAppTypeAndProfile(d *schema.ResourceData) error {
	// Create a null logger for schema validation (this function doesn't have access to meta)
	logger := hclog.NewNullLogger()

	// Get app_type and app_profile first
	appType := ""
	appProfile := ""

	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	if ap, ok := d.GetOk("app_profile"); ok {
		appProfile = ap.(string)
	}

	// For bookmark and saas, advanced_settings should not be allowed at all
	// These app types should use resource-level configuration instead
	if appType == string(client.ClientAppTypeBookmark) || appType == string(client.ClientAppTypeSaaS) {
		advSettings, ok := d.GetOk("advanced_settings")
		if ok {
			advSettingsStr, ok := advSettings.(string)
			if ok && advSettingsStr != "" && advSettingsStr != "{}" {
				return client.ErrAdvancedSettingsNotAllowedForAppType
			}
		}
		return nil
	}

	// Get advanced_settings for other app types
	advSettings, ok := d.GetOk("advanced_settings")
	if !ok {
		return nil // No advanced settings provided
	}

	advSettingsStr, ok := advSettings.(string)
	if !ok {
		return client.ErrAdvancedSettingsNotString
	}

	// If empty, it's valid (will use defaults)
	if advSettingsStr == "" || advSettingsStr == "{}" {
		return nil
	}

	// Parse the JSON
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(advSettingsStr), &settings); err != nil {
		return client.ErrAdvancedSettingsInvalidJSON
	}

	// Validate app_auth if present
	if appAuth, exists := settings["app_auth"]; exists {
		if appAuthStr, ok := appAuth.(string); ok {
			if err := validateAppAuthForTypeAndProfile(appAuthStr, appType, appProfile); err != nil {
				return err
			}
		}
	}

	// Validate health check settings if present (skip for tunnel apps)
	if appType != string(client.ClientAppTypeTunnel) {
		logger.Debug("Validating health check for app_type: %s", appType)
		if err := client.ValidateHealthCheckConfiguration(settings, appType, appProfile, logger); err != nil {
			logger.Error("Health check validation failed for app_type %s: %v", appType, err)
			return err // Return the specific error instead of generic one
		}
	} else {
		logger.Debug("Skipping health check validation for tunnel app")
	}

	// Server load balancing settings validation is now handled by SETTINGS_RULES

	// Related applications settings validation is now handled by SETTINGS_RULES

	// Note: Enterprise connectivity, miscellaneous parameters, RDP configuration, and tunnel client parameters
	// are now validated by the comprehensive generic validation system in ValidateAdvancedSettings()

	// Validate TLS Suite configuration restrictions
	if err := validateTLSSuiteRestrictions(appType, appProfile, settings); err != nil {
		return client.ErrTLSSuiteRestrictionsValidationFailed
	}

	// Validate TLS Suite required dependencies
	if err := validateTLSSuiteRequiredDependencies(settings, logger); err != nil {
		return err
	}

	// Note: TLS custom suite name validation is skipped in schema validation
	// as this function doesn't have access to the client/meta for API calls
	// This validation is performed in plan-time validation instead

	return nil
}

// validateTLSSuiteRequiredDependencies validates that required fields are present when dependencies are met
func validateTLSSuiteRequiredDependencies(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating TLS Suite required dependencies")

	// Check if tlsSuiteType is present and is "custom"
	tlsSuiteType, exists := settings["tlsSuiteType"]
	if !exists {
		return nil // No TLS Suite Type specified, no dependencies to check
	}

	tlsSuiteTypeStr, ok := tlsSuiteType.(string)
	if !ok {
		return nil // Invalid type, will be caught by other validation
	}

	// Check if TLS Suite Type requires tls_suite_name
	if tlsSuiteTypeStr == "custom" {
		logger.Debug("TLS Suite Type is custom, checking for required tls_suite_name field")

		// Check if tls_suite_name is present
		tlsSuiteName, exists := settings["tls_suite_name"]
		if !exists {
			logger.Error("Missing required field: tls_suite_name")
			return fmt.Errorf("tls_suite_name is required when tlsSuiteType is custom")
		}

		// Check if tls_suite_name is empty string
		if tlsSuiteNameStr, ok := tlsSuiteName.(string); ok && tlsSuiteNameStr == "" {
			logger.Error("Required field tls_suite_name is empty")
			return fmt.Errorf("tls_suite_name cannot be empty when tlsSuiteType is custom")
		}

		logger.Debug("Required field tls_suite_name is present and not empty")
	}

	return nil
}

// validateTLSSuiteRestrictions validates TLS Suite configuration restrictions based on app_type and app_profile
func validateTLSSuiteRestrictions(appType, appProfile string, settings map[string]interface{}) error {
	// Define TLS Suite fields
	tlsSuiteFields := []string{
		"tlsSuiteType", "tls_suite_name", "tls_cipher_suite",
	}

	// Check if any TLS Suite fields are present
	hasTLSSuiteFields := false
	for _, field := range tlsSuiteFields {
		if _, exists := settings[field]; exists {
			hasTLSSuiteFields = true
			break
		}
	}

	// If no TLS Suite fields are present, no validation needed
	if !hasTLSSuiteFields {
		return nil
	}

	// TLS Suite is NOT AVAILABLE for Tunnel, Bookmark, or SaaS app_types
	if appType == string(client.ClientAppTypeTunnel) || appType == string(client.ClientAppTypeBookmark) || appType == string(client.ClientAppTypeSaaS) {
		return client.ErrTLSSuiteNotAvailableForAppType
	}

	// TLS Suite is NOT AVAILABLE for SMB app_profile (regardless of app_type)
	if appProfile == string(client.AppProfileSMB) {
		return client.ErrTLSSuiteNotAvailableForSMBProfile
	}

	// TLS Suite is AVAILABLE for enterprise app_type with appropriate app_profiles
	if appType == string(client.ClientAppTypeEnterprise) {
		validProfiles := []string{string(client.AppProfileHTTP), string(client.AppProfileSharePoint), string(client.AppProfileJira), string(client.AppProfileJenkins), string(client.AppProfileConfluence), string(client.AppProfileRDP), string(client.AppProfileVNC), string(client.AppProfileSSH)}
		isValidProfile := false
		for _, validProfile := range validProfiles {
			if appProfile == validProfile {
				isValidProfile = true
				break
			}
		}

		if !isValidProfile {
			return client.ErrTLSSuiteNotAvailableForEnterpriseProfile
		}
	}

	return nil
}

// validateTLSCustomSuiteName validates that when tlsSuiteType = 2 (CUSTOM), tls_suite_name must be a valid cipher suite
func validateTLSCustomSuiteName(settings map[string]interface{}, validCipherSuites []string) error {
	// Check if tlsSuiteType is present and equals 2 (CUSTOM)
	tlsSuiteType, exists := settings["tlsSuiteType"]
	if !exists {
		return nil // No TLS Suite Type to validate
	}

	tlsSuiteTypeNum, ok := tlsSuiteType.(float64)
	if !ok {
		return nil // Invalid TLS Suite Type
	}

	// Only validate when tlsSuiteType = 2 (CUSTOM)
	if tlsSuiteTypeNum != 2 {
		return nil
	}

	// Get tls_suite_name
	tlsSuiteName, exists := settings["tls_suite_name"]
	if !exists {
		return client.ErrTLSSuiteNameRequired
	}

	tlsSuiteNameStr, ok := tlsSuiteName.(string)
	if !ok {
		return client.ErrTLSSuiteNameNotString
	}

	// Check if the provided tls_suite_name is valid
	isValid := false
	for _, validSuite := range validCipherSuites {
		if tlsSuiteNameStr == validSuite {
			isValid = true
			break
		}
	}

	if !isValid {
		return client.ErrTLSSuiteNameInvalid
	}

	return nil
}

// validateAdvancedSettingsJSON validates that advanced_settings is valid JSON
func validateAdvancedSettingsJSON(i interface{}, k string) ([]string, []error) {
	var warnings []string
	var errors []error

	// Get the advanced_settings value
	advancedSettingsStr, ok := i.(string)
	if !ok {
		errors = append(errors, client.ErrAdvancedSettingsNotString)
		return warnings, errors
	}

	// If empty, it's valid (will use defaults)
	if advancedSettingsStr == "" || advancedSettingsStr == "{}" {
		return warnings, errors
	}

	// Parse the JSON to validate it's valid
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(advancedSettingsStr), &settings); err != nil {
		errors = append(errors, client.ErrAdvancedSettingsInvalidJSON)
		return warnings, errors
	}

	// For now, we can't access app_type from ValidateFunc
	// This is a limitation of the Terraform SDK
	// We'll need to use a different approach

	return warnings, errors
}

// validateTunnelAppAdvancedSettings validates that tunnel apps only use allowed parameter categories
func validateTunnelAppAdvancedSettings(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("validateTunnelAppAdvancedSettings called for tunnel app")

	// Define allowed parameter categories for tunnel apps
	allowedCategories := map[string][]string{
		// Server Load Balancing Parameters
		"server_load_balancing": {
			"load_balancing_metric",
			"session_sticky",
			"session_sticky_cookie_maxage",
			"session_sticky_server_cookie",
			"refresh_sticky_cookie",
			"tcp_optimization",
		},
		// Enterprise Connectivity Parameters
		"enterprise_connectivity": {
			"idle_conn_floor",
			"idle_conn_ceil",
			"idle_conn_step",
			"max_conn_floor",
			"max_conn_ceil",
			"max_conn_step",
			"conn_retry_interval",
			"conn_retry_max_attempts",
			"conn_retry_max_interval",
		},
		// Tunnel Client Parameters (tunnel-specific)
		"tunnel_client_parameters": {
			"domain_exception_list",
			"acceleration",
			"force_ip_route",
			"x_wapp_pool_enabled",
			"x_wapp_pool_size",
			"x_wapp_pool_timeout",
			"x_wapp_read_timeout",
		},
		// Health Check Parameters (tunnel apps only support TCP)
		"health_check": {
			"health_check_type",
			"health_check_rise",
			"health_check_fall",
			"health_check_timeout",
			"health_check_interval",
		},
		// Basic Configuration Parameters
		"basic_config": {
			"is_ssl_verification_enabled",
			"ip_access_allow",
			"websocket_enabled",
			"wildcard_internal_hostname",
		},
	}

	// Create a map of all allowed fields
	allowedFields := make(map[string]bool)
	for _, fields := range allowedCategories {
		for _, field := range fields {
			allowedFields[field] = true
		}
	}

	// Check each field in the settings
	var blockedFields []string
	for fieldName := range settings {
		if !allowedFields[fieldName] {
			// Determine which category this field belongs to (for better error message)
			category := "unknown"
			if isAuthField(fieldName) {
				category = "authentication"
			} else if isCORSField(fieldName) {
				category = "CORS"
			} else if isTLSField(fieldName) {
				category = "TLS Suite"
			} else if isMiscField(fieldName) {
				category = "miscellaneous"
			} else if isRDPField(fieldName) {
				category = "RDP configuration"
			}

			blockedFields = append(blockedFields, fmt.Sprintf("'%s' (%s parameters)", fieldName, category))
		}
	}

	// If there are blocked fields, return an error
	if len(blockedFields) > 0 {
		errorMsg := fmt.Sprintf("Tunnel apps only support Server Load Balancing, Enterprise Connectivity, Tunnel Client Parameters, Health Check, and Basic Configuration parameters. The following fields are not allowed: %s",
			strings.Join(blockedFields, ", "))
		logger.Error("Blocked fields detected for tunnel app: %s", errorMsg)
		return errors.New(errorMsg)
	}

	logger.Debug("All fields in tunnel app advanced_settings are allowed")
	return nil
}

// Helper functions to categorize fields
func isAuthField(fieldName string) bool {
	authFields := []string{
		"login_url", "logout_url", "wapp_auth", "app_auth", "intercept_url",
		"form_post_url", "form_post_attributes", "app_client_cert_auth",
		"app_cookie_domain", "jwt_issuers", "jwt_audience", "jwt_grace_period",
		"jwt_return_option", "jwt_return_url", "jwt_username", "app_auth_domain",
		"service_principle_name", "keytab", "kerberos_negotiate_once",
		"forward_ticket_granting_ticket", "http_only_cookie", "disable_user_agent_check",
		"preauth_consent", "sentry_redirect_401",
	}
	for _, field := range authFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isCORSField(fieldName string) bool {
	corsFields := []string{
		"allow_cors", "cors_origin_list", "cors_header_list", "cors_method_list",
		"cors_support_credential", "cors_max_age",
	}
	for _, field := range corsFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isTLSField(fieldName string) bool {
	tlsFields := []string{
		"tlsSuiteType", "tls_suite_name", "tls_cipher_suite",
	}
	for _, field := range tlsFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isMiscField(fieldName string) bool {
	miscFields := []string{
		"proxy_buffer_size_kb", "ssh_audit_enabled", "hidden_app", "logging_enabled",
		"offload_onpremise_traffic", "saas_enabled", "segmentation_policy_enable",
		"sentry_restore_form_post", "sla_object_url", "user_name", "custom_headers",
		"inject_ajax_javascript", "internal_host_port", "login_timeout", "mdc_enable",
		"onramp", "pass_phrase", "private_key", "proxy_disable_clipboard", "rate_limit",
		"request_body_rewrite", "request_parameters",
	}
	for _, field := range miscFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isRDPField(fieldName string) bool {
	rdpFields := []string{
		"rdp_audio_redirection", "rdp_clipboard_redirection", "rdp_disk_redirection",
		"rdp_port_redirection", "rdp_printer_redirection", "rdp_smart_card_redirection",
		"rdp_usb_redirection", "rdp_webcam_redirection",
	}
	for _, field := range rdpFields {
		if fieldName == field {
			return true
		}
	}
	return false
}
