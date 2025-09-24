package eaaprovider

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// AdvancedSettingsSchema defines the JSON schema for advanced settings validation
type AdvancedSettingsSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Required   []string               `json:"required,omitempty"`
}

// Schema field type definitions
var (
	stringField          = map[string]interface{}{"type": "string"}
	numericField         = map[string]interface{}{"type": "string", "pattern": "^[0-9]+$"}
	integerField         = map[string]interface{}{"type": "integer"}
	booleanField         = map[string]interface{}{"type": "string", "enum": []string{"true", "false"}}
	onOffField           = map[string]interface{}{"type": "string", "enum": []string{"on", "off"}}
	nullableStringField  = map[string]interface{}{"type": "string", "nullable": true}
	nullableNumericField = map[string]interface{}{"type": "string", "pattern": "^[0-9]+$", "nullable": true}
)

// Helper functions to create field definitions
func stringFieldWithEnum(enum []string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "enum": enum}
}

func integerFieldWithRange(min, max int) map[string]interface{} {
	return map[string]interface{}{"type": "integer", "minimum": min, "maximum": max}
}

func stringFieldWithPattern(pattern string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "pattern": pattern}
}

// GetAdvancedSettingsSchema returns the complete JSON schema for advanced settings
func GetAdvancedSettingsSchema() *AdvancedSettingsSchema {
	properties := make(map[string]interface{})

	// Authentication & Authorization
	authFields := map[string]interface{}{
		"app_auth":                    nullableStringField,
		"app_auth_domain":             nullableStringField,
		"app_client_cert_auth":        booleanField,
		"app_cookie_domain":           nullableStringField,
		"app_location":                nullableStringField,
		"client_cert_auth":            booleanField,
		"client_cert_user_param":      stringField,
		"cookie_domain":               stringField,
		"edge_authentication_enabled": booleanField,
		"edge_cookie_key":             stringField,
		"force_mfa":                   onOffField,
		"idp_idle_expiry":             nullableNumericField,
		"idp_max_expiry":              nullableNumericField,
		"ignore_bypass_mfa":           onOffField,
		"mfa":                         stringField,
		"preauth_consent":             booleanField,
		"preauth_enforce_url":         stringField,
		"sso":                         booleanField,
		"wapp_auth":                   stringField,
	}

	// CORS Settings
	corsFields := map[string]interface{}{
		"allow_cors":              booleanField,
		"cors_header_list":        stringField,
		"cors_max_age":            numericField,
		"cors_method_list":        stringField,
		"cors_origin_list":        stringField,
		"cors_support_credential": onOffField,
	}

	// Connection & Performance
	connectionFields := map[string]interface{}{
		"acceleration":                       booleanField,
		"anonymous_server_conn_limit":        numericField,
		"anonymous_server_request_limit":     numericField,
		"authenticated_server_conn_limit":    numericField,
		"authenticated_server_request_limit": numericField,
		"app_server_read_timeout":            numericField,
		"idle_close_time_seconds":            numericField,
		"idle_conn_ceil":                     numericField,
		"idle_conn_floor":                    numericField,
		"idle_conn_step":                     numericField,
		"keepalive_connection_pool":          numericField,
		"keepalive_enable":                   booleanField,
		"keepalive_timeout":                  numericField,
		"keyed_keepalive_enable":             booleanField,
		"load_balancing_metric":              stringFieldWithEnum([]string{"round-robin", "ip-hash"}),
		"session_sticky":                     booleanField,
		"session_sticky_cookie_maxage":       numericField,
		"session_sticky_server_cookie":       nullableStringField,
		"refresh_sticky_cookie":              onOffField,
		"server_request_burst":               numericField,
		"spdy_enabled":                       booleanField,
		"websocket_enabled":                  booleanField,
	}

	// Health Check Settings
	healthCheckFields := map[string]interface{}{
		"health_check_fall":             numericField,
		"health_check_http_host_header": nullableStringField,
		"health_check_http_url":         stringField,
		"health_check_http_version":     stringField,
		"health_check_interval":         numericField,
		"health_check_rise":             numericField,
		"health_check_timeout":          numericField,
		"health_check_type":             stringFieldWithPattern("^(Default|HTTP|HTTPS|SSL|TCP|None|[0-9]+)$"),
	}

	// Security Settings
	securityFields := map[string]interface{}{
		"disable_user_agent_check":       booleanField,
		"domain_exception_list":          stringField,
		"edge_transport_manual_mode":     booleanField,
		"edge_transport_property_id":     nullableStringField,
		"enable_client_side_xhr_rewrite": booleanField,
		"external_cookie_domain":         nullableStringField,
		"force_ip_route":                 booleanField,
		"g2o_enabled":                    nullableStringField,
		"g2o_key":                        nullableStringField,
		"g2o_nonce":                      nullableStringField,
		"host_key":                       nullableStringField,
		"hsts_age":                       numericField,
		"http_only_cookie":               booleanField,
		"https_sslv3":                    booleanField,
		"ignore_cname_resolution":        nullableStringField,
		"is_brotli_enabled":              booleanField,
		"is_ssl_verification_enabled":    booleanField,
		"ip_access_allow":                booleanField,
		"server_cert_validate":           booleanField,
		"wildcard_internal_hostname":     booleanField,
	}

	// Session & Cookie Settings
	sessionFields := map[string]interface{}{
		"session_sticky":               nullableStringField,
		"session_sticky_cookie_maxage": numericField,
		"session_sticky_server_cookie": nullableStringField,
		"sticky_agent":                 booleanField,
		"refresh_sticky_cookie":        onOffField,
	}

	// JWT Settings
	jwtFields := map[string]interface{}{
		"jwt_audience":      stringField,
		"jwt_grace_period":  numericField,
		"jwt_issuers":       stringField,
		"jwt_return_option": stringFieldWithEnum([]string{"401", "302"}),
		"jwt_return_url":    stringField,
		"jwt_username":      stringField,
	}

	// Kerberos Settings
	kerberosFields := map[string]interface{}{
		"kerberos_negotiate_once": onOffField,
		"keytab":                  stringField,
		"service_principle_name":  nullableStringField,
	}

	// RDP Settings
	rdpFields := map[string]interface{}{
		"rdp_initial_program":    nullableStringField,
		"rdp_keyboard_lang":      stringField,
		"rdp_legacy_mode":        booleanField,
		"rdp_tls1":               booleanField,
		"rdp_window_color_depth": stringField,
		"rdp_window_height":      stringField,
		"rdp_window_width":       stringField,
	}

	// Remote Spark Settings
	remoteSparkFields := map[string]interface{}{
		"remote_spark_audio":         booleanField,
		"remote_spark_disk":          stringField,
		"remote_spark_map_clipboard": onOffField,
		"remote_spark_map_disk":      booleanField,
		"remote_spark_map_printer":   booleanField,
		"remote_spark_printer":       stringField,
		"remote_spark_recording":     booleanField,
	}

	// Tunnel Client Parameters (EAA Client Parameters - Tunnel Apps Only)
	tunnelClientParametersFields := map[string]interface{}{
		"domain_exception_list": nullableStringField,
		"acceleration":          booleanField,
		"force_ip_route":        booleanField,
		"x_wapp_pool_enabled":   stringField,
		"x_wapp_pool_size":      integerField,
		"x_wapp_pool_timeout":   integerField,
	}

	// Single Host Settings
	singleHostFields := map[string]interface{}{
		"single_host_content_rw":    booleanField,
		"single_host_cookie_domain": booleanField,
		"single_host_enable":        booleanField,
		"single_host_fqdn":          stringField,
		"single_host_path":          stringField,
	}

	// WAPP Pool Settings
	wappPoolFields := map[string]interface{}{
		"x_wapp_pool_enabled": stringFieldWithEnum([]string{"true", "false", "inherit"}),
		"x_wapp_pool_size":    integerFieldWithRange(1, 50),
		"x_wapp_pool_timeout": integerFieldWithRange(60, 3600),
		"x_wapp_read_timeout": integerFieldWithRange(1, 3600),
	}

	// Other Settings
	otherFields := map[string]interface{}{
		"custom_headers":                 map[string]interface{}{"type": "array"},
		"form_post_attributes":           map[string]interface{}{"type": "array"},
		"form_post_url":                  stringField,
		"forward_ticket_granting_ticket": booleanField,
		"hidden_app":                     booleanField,
		"inject_ajax_javascript":         onOffField,
		"intercept_url":                  stringField,
		"internal_host_port":             numericField,
		"logging_enabled":                booleanField,
		"login_timeout":                  numericField,
		"login_url":                      nullableStringField,
		"logout_url":                     nullableStringField,
		"mdc_enable":                     booleanField,
		"offload_onpremise_traffic":      booleanField,
		"onramp":                         stringField,
		"pass_phrase":                    nullableStringField,
		"private_key":                    nullableStringField,
		"proxy_buffer_size_kb":           nullableNumericField,
		"proxy_disable_clipboard":        booleanField,
		"rate_limit":                     onOffField,
		"request_body_rewrite":           booleanField,
		"request_parameters":             map[string]interface{}{"type": "object"},
		"saas_enabled":                   booleanField,
		"segmentation_policy_enable":     booleanField,
		"sentry_redirect_401":            onOffField,
		"sentry_restore_form_post":       onOffField,
		"sla_object_url":                 stringField,
		"ssh_audit_enabled":              booleanField,
		"user_name":                      nullableStringField,
	}

	// Merge all field groups
	mergeFields(properties, authFields)
	mergeFields(properties, corsFields)
	mergeFields(properties, connectionFields)
	mergeFields(properties, healthCheckFields)
	mergeFields(properties, securityFields)
	mergeFields(properties, sessionFields)
	mergeFields(properties, jwtFields)
	mergeFields(properties, kerberosFields)
	mergeFields(properties, rdpFields)
	mergeFields(properties, remoteSparkFields)
	mergeFields(properties, tunnelClientParametersFields)
	mergeFields(properties, singleHostFields)
	mergeFields(properties, wappPoolFields)
	mergeFields(properties, otherFields)

	return &AdvancedSettingsSchema{
		Type:       "object",
		Properties: properties,
		Required:   []string{},
	}
}

// Helper function to merge field maps
func mergeFields(target map[string]interface{}, source map[string]interface{}) {
	for k, v := range source {
		target[k] = v
	}
}

// validateAdvancedSettingsWithSchema validates the advanced_settings JSON string using JSON schema
func validateAdvancedSettingsWithSchema(v interface{}, k string) (ws []string, errors []error) {
	value, ok := v.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", v))
		return
	}

	// If empty, it's valid (will use defaults)
	if value == "" || value == "{}" {
		return
	}

	// Parse the JSON to validate structure
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(value), &settings); err != nil {
		errors = append(errors, fmt.Errorf("invalid JSON format: %v", err))
		return
	}

	// Get the schema
	schema := GetAdvancedSettingsSchema()

	// Validate against schema
	if err := validateAgainstSchema(settings, schema); err != nil {
		errors = append(errors, err)
	}

	// Create a null logger for schema validation (schema validation functions don't have access to meta)
	logger := hclog.NewNullLogger()

	// Use the new generic validation system for schema validation
	// Note: During schema validation, we don't have app_type/app_profile context,
	// so we pass empty strings and let the generic system handle basic validation
	if err := ValidateAdvancedSettings(settings, "", "", "", logger); err != nil {
		errors = append(errors, err)
	}

	// Note: Tunnel client parameters validation is now handled by the comprehensive generic validation system

	// Validate wapp_auth if present
	if wappAuth, exists := settings["wapp_auth"]; exists {
		if wappAuthStr, ok := wappAuth.(string); ok {
			if err := validateWappAuthValue(wappAuthStr); err != nil {
				errors = append(errors, err)
			}
			// Validate certonly constraints (limited validation without resource context)
			if wappAuthStr == "certonly" {
				if err := validateCertonlyConstraintsSchema(settings); err != nil {
					errors = append(errors, err)
				}
			}
		}
	}

	return
}

// validateAppAuthWithTypeAndProfile validates app_auth based on app_type and app_profile
func validateAppAuthWithTypeAndProfile(appAuth string, d *schema.ResourceData) error {
	// Get app_type and app_profile from the resource data
	appType := ""
	appProfile := ""

	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	if ap, ok := d.GetOk("app_profile"); ok {
		appProfile = ap.(string)
	}

	// Check for SAML/OIDC/WSFED conflicts - when these are enabled, app_auth must be "none"
	if appAuth != "none" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("when saml is enabled (saml=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuth)
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("when oidc is enabled (oidc=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuth)
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("when wsfed is enabled (wsfed=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuth)
		}
	}

	// Additional validation: specific conflicts with SAML
	if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
		// When SAML is enabled, app_auth cannot be kerberos, NTLMv1, or NTLMv2
		conflictingValues := []string{"kerberos", "NTLMv1", "NTLMv2"}
		for _, conflictingValue := range conflictingValues {
			if appAuth == conflictingValue {
				return fmt.Errorf("when saml is enabled (saml=true), app_auth cannot be '%s' in advanced_settings. Use 'none' instead", conflictingValue)
			}
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	if appType == "bookmark" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}
	}

	// Check if tunnel app is trying to use advanced authentication methods
	if appType == "tunnel" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}
	}

	// Apply validation rules based on the requirements
	switch {
	case appType == "enterprise" && appProfile == "ssh":
		// app_auth is disabled - field should not be present in advanced_settings
		return fmt.Errorf("app_auth is disabled for app_type=enterprise and app_profile=ssh. This field should not be present in advanced_settings - defaults will be used")

	case appType == "saas":
		// app_auth should not be present in advanced_settings for SaaS apps
		// Authentication is handled at resource level using boolean flags (saml: true, oidc: true, wsfed: true)
		return fmt.Errorf("app_auth should not be present in advanced_settings for app_type=saas. Set authentication method at the resource level using saml, oidc, or wsfed boolean flags instead")

	case appType == "bookmark":
		// app_auth should not be present in advanced_settings - it's set at resource level
		return fmt.Errorf("app_auth should not be present in advanced_settings for app_type=bookmark. Set app_auth at the resource level instead")

	case appType == "tunnel":
		// app_auth should not be present in advanced_settings - it's set at resource level as "tcp"
		return fmt.Errorf("app_auth should not be present in advanced_settings for app_type=tunnel. Set app_auth at the resource level instead")

	case appType == "enterprise" && appProfile == "vnc":
		// app_auth is disabled - field should not be present in advanced_settings
		return fmt.Errorf("app_auth is disabled for app_type=enterprise and app_profile=vnc. This field should not be present in advanced_settings - defaults will be used")
	}

	return nil
}

// validateAgainstSchema validates a JSON object against the provided schema
func validateAgainstSchema(data map[string]interface{}, schema *AdvancedSettingsSchema) error {
	// Check required fields (currently none, as all fields should use defaults if not provided)
	for _, requiredField := range schema.Required {
		if _, exists := data[requiredField]; !exists {
			return fmt.Errorf("required field '%s' is missing", requiredField)
		}
	}

	// Validate each field in the data (only validate fields that are provided)
	for fieldName, fieldValue := range data {
		fieldSchema, exists := schema.Properties[fieldName]
		if !exists {
			return fmt.Errorf("unknown field '%s'", fieldName)
		}

		if err := validateField(fieldValue, fieldSchema); err != nil {
			return fmt.Errorf("field '%s': %v", fieldName, err)
		}
	}

	return nil
}

// validateField validates a single field against its schema definition
func validateField(value interface{}, fieldSchema interface{}) error {
	schemaMap, ok := fieldSchema.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid field schema")
	}

	// Handle null values for nullable fields
	if value == nil {
		if nullable, ok := schemaMap["nullable"].(bool); ok && nullable {
			return nil // null is valid for nullable fields
		}
		return fmt.Errorf("cannot be null")
	}

	// Check type
	if expectedType, ok := schemaMap["type"].(string); ok {
		if err := validateType(value, expectedType); err != nil {
			return err
		}
	}

	// Check enum values
	if enumValues, ok := schemaMap["enum"].([]interface{}); ok {
		if err := validateEnum(value, enumValues); err != nil {
			return err
		}
	}

	// Check pattern
	if pattern, ok := schemaMap["pattern"].(string); ok {
		if err := validatePattern(value, pattern); err != nil {
			return err
		}
	}

	// Check numeric constraints
	if min, ok := schemaMap["minimum"].(float64); ok {
		if err := validateMinimum(value, int(min)); err != nil {
			return err
		}
	}
	if max, ok := schemaMap["maximum"].(float64); ok {
		if err := validateMaximum(value, int(max)); err != nil {
			return err
		}
	}

	return nil
}

// validateType validates the type of a value
func validateType(value interface{}, expectedType string) error {
	switch expectedType {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("must be a string, got %T", value)
		}
	case "integer":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			// JSON numbers become float64, so accept them
		default:
			return fmt.Errorf("must be an integer, got %T", value)
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("must be an array, got %T", value)
		}
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("must be an object, got %T", value)
		}
	default:
		return fmt.Errorf("unsupported type: %s", expectedType)
	}
	return nil
}

// validateAppAuthWithContext validates app_auth based on app_type and app_profile
func validateAppAuthWithContext(v interface{}, k string) (ws []string, errors []error) {
	// This function will be called from the resource validation
	// For now, just do basic validation
	value, ok := v.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", v))
		return
	}

	// Basic validation - more specific validation will be done in the resource
	validValues := []string{"none", "SAML2.0", "oidc", "OpenID Connect 1.0", "wsfed", "WS-Federation", "kerberos", "basic", "NTLMv1", "NTLMv2"}

	isValid := false
	for _, validValue := range validValues {
		if value == validValue {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, fmt.Errorf("invalid app_auth value '%s'. Valid values are: %v", value, validValues))
		return
	}

	return
}

// validateEnum validates that a value is one of the allowed enum values
func validateEnum(value interface{}, enumValues []interface{}) error {
	valueStr, ok := value.(string)
	if !ok {
		return fmt.Errorf("enum validation only supports string values")
	}

	for _, enumValue := range enumValues {
		if enumStr, ok := enumValue.(string); ok && enumStr == valueStr {
			return nil
		}
	}

	return fmt.Errorf("must be one of %v, got '%s'", enumValues, valueStr)
}

// validatePattern validates that a string matches a regex pattern
func validatePattern(value interface{}, pattern string) error {
	valueStr, ok := value.(string)
	if !ok {
		// For numeric values, convert to string
		valueStr = fmt.Sprintf("%v", value)
	}

	matched, err := regexp.MatchString(pattern, valueStr)
	if err != nil {
		return fmt.Errorf("pattern validation error: %v", err)
	}
	if !matched {
		return fmt.Errorf("must match pattern '%s', got '%s'", pattern, valueStr)
	}

	return nil
}

// validateMinimum validates that a numeric value is at least the minimum
func validateMinimum(value interface{}, min int) error {
	numVal, err := getNumericValue(value)
	if err != nil {
		return err
	}

	if numVal < int64(min) {
		return fmt.Errorf("must be at least %d, got %d", min, numVal)
	}

	return nil
}

// validateMaximum validates that a numeric value is at most the maximum
func validateMaximum(value interface{}, max int) error {
	numVal, err := getNumericValue(value)
	if err != nil {
		return err
	}

	if numVal > int64(max) {
		return fmt.Errorf("must be at most %d, got %d", max, numVal)
	}

	return nil
}

// getNumericValue extracts a numeric value from various types
func getNumericValue(value interface{}) (int64, error) {
	switch v := value.(type) {
	case string:
		return strconv.ParseInt(v, 10, 64)
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint:
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		return int64(v), nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to numeric value", value)
	}
}

// validateCertonlyConstraintsSchema validates certonly constraints for schema validation
// This is a limited validation without access to resource context
func validateCertonlyConstraintsSchema(settings map[string]interface{}) error {
	// Constraint: app_auth can only be "none", "kerberos", or "oidc" when wapp_auth = "certonly"
	if appAuth, exists := settings["app_auth"]; exists {
		if appAuthStr, ok := appAuth.(string); ok {
			validCertonlyAppAuthValues := []string{"none", "kerberos", "oidc"}
			isValid := false
			for _, validValue := range validCertonlyAppAuthValues {
				if appAuthStr == validValue {
					isValid = true
					break
				}
			}
			if !isValid {
				return fmt.Errorf("when wapp_auth = \"certonly\", app_auth can only be one of: %v, got: \"%s\"", validCertonlyAppAuthValues, appAuthStr)
			}
		}
	}

	return nil
}
