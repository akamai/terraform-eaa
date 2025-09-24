package eaaprovider

import (
	"context"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// getMapKeys returns the keys of a map as a slice of strings
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}



// validateHealthCheckConfiguration validates health check configuration
func validateHealthCheckConfiguration(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {

	// Check if health check settings are present
	hasHealthCheckSettings := false
	healthCheckFields := []string{
		"health_check_type", "health_check_rise", "health_check_fall",
		"health_check_timeout", "health_check_interval", "health_check_http_url",
		"health_check_http_version", "health_check_http_host_header",
	}

	for _, field := range healthCheckFields {
		if _, exists := settings[field]; exists {
			hasHealthCheckSettings = true
			break
		}
	}

	// If no health check settings are present, skip validation
	if !hasHealthCheckSettings {
		return nil
	}

	logger.Debug("Health check settings found, proceeding with validation")

	// STEP 1: Validate app type and profile restrictions based on Table 1: Application Types and Health Check Support
	if appType != "" {
		switch appType {
		case "tunnel":
			// Health check allowed for tunnel applications
			logger.Warn("health check configuration is not supported for app_type=%s. Health checks are only available for supported application types", appType)
			return client.ErrHealthCheckNotSupported
			// Continue with validation instead of returning early
		case "saas", "bookmark":
			// Health check configuration in advanced_settings is not allowed for SaaS and Bookmark apps
			// Health checks are available for these app types, but must be configured at resource level, not in advanced_settings
			logger.Warn("health check configuration in advanced_settings is not allowed for app_type=%s. Health checks for SaaS and Bookmark apps must be configured at resource level", appType)
			return client.ErrAdvancedSettingsNotAllowed
		case "enterprise":
			// Health check available in advanced_settings for Enterprise apps only
			logger.Debug("Health check allowed in advanced_settings for %s app", appType)
		default:
			// For any other app types, health checks should not be present
			logger.Warn("health check configuration is not supported for app_type=%s. Health checks are only available for supported application types", appType)
			return client.ErrHealthCheckNotSupported
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		// but we can still validate the health check structure
		logger.Debug("App type not provided, skipping app type validation but continuing with health check structure validation")
		// During schema validation, we'll be more lenient and only validate the structure
		// The app type validation will happen during runtime validation (terraform apply)
	}
	// STEP 2: Validate health check type and required fields (only if app type allows it)
	// Get health_check_type value
	healthCheckType, hasType := settings["health_check_type"]
	if !hasType {
		return nil // No health check type specified, skip validation
	}

	typeStr, ok := healthCheckType.(string)
	if !ok {
		return client.ErrHealthCheckTypeInvalid
	}

	// Validate health check type enum (only descriptive names)
	validTypes := []string{"Default", "HTTP", "HTTPS", "TLS", "SSLv3", "TCP", "None"}
	isValidType := false
	for _, validType := range validTypes {
		if typeStr == validType {
			isValidType = true
			break
		}
	}
	if !isValidType {
		return client.ErrHealthCheckTypeUnsupported
	}

	// Conditional validation for HTTP/HTTPS fields (HTTP and HTTPS types)
	// Only validate HTTP fields if appType is provided (runtime validation)
	// During schema validation (appType is empty), skip HTTP field validation
	if (typeStr == "HTTP" || typeStr == "HTTPS") && appType != "" {
		logger.Debug("Validating HTTP/HTTPS fields for type: %s", typeStr)

		// HTTP fields are REQUIRED for HTTP/HTTPS health check types

		// Required: health_check_http_url
		httpURL, exists := settings["health_check_http_url"]
		logger.Debug("health_check_http_url exists: %v, value: %v", exists, httpURL)
		if !exists {
			logger.Warn("Missing health_check_http_url, returning error")
			return client.ErrHealthCheckHTTPURLRequired
		}
		if urlStr, ok := httpURL.(string); !ok {
			return client.ErrHealthCheckHTTPURLInvalid
		} else if urlStr == "" {
			return client.ErrHealthCheckHTTPURLEmpty
		}

		// Required: health_check_http_version
		httpVersion, exists := settings["health_check_http_version"]
		if !exists {
			return client.ErrHealthCheckHTTPVersionRequired
		}
		if versionStr, ok := httpVersion.(string); !ok {
			return client.ErrHealthCheckHTTPVersionInvalid
		} else if versionStr == "" {
			return client.ErrHealthCheckHTTPVersionEmpty
		}

		// Required: health_check_http_host_header
		hostHeader, exists := settings["health_check_http_host_header"]
		if !exists {
			return client.ErrHealthCheckHTTPHostHeaderRequired
		}
		if hostHeader == nil {
			return client.ErrHealthCheckHTTPHostHeaderNull
		}
		if _, ok := hostHeader.(string); !ok {
			return client.ErrHealthCheckHTTPHostHeaderInvalid
		}
	} else if appType != "" {
		// For non-HTTP/HTTPS types, HTTP-specific fields should not be set
		// Only HTTP and HTTPS health check types allow HTTP-specific fields
		logger.Debug("Validating non-HTTP/HTTPS health check fields for type: %s", typeStr)

		// HTTP-specific fields that should only be allowed for HTTP and HTTPS
		httpFields := []string{
			"health_check_http_url",
			"health_check_http_version",
			"health_check_http_host_header",
			"health_check_location",
			"health_check_internal_host",
		}

		for _, field := range httpFields {
			if _, exists := settings[field]; exists {
				return client.ErrHealthCheckHTTPFieldNotAllowed
			}
		}
	}

	// Validate numeric fields
	numericFields := []string{"health_check_rise", "health_check_fall", "health_check_timeout", "health_check_interval"}
	for _, field := range numericFields {
		if value, exists := settings[field]; exists {
			if strValue, ok := value.(string); ok {
				if strValue == "" {
					return client.ErrHealthCheckFieldEmpty
				}
				// Validate it's a numeric string
				if _, err := strconv.Atoi(strValue); err != nil {
					return client.ErrHealthCheckFieldNotNumeric
				}
			} else {
				return client.ErrHealthCheckFieldNotString
			}
		}
	}

	return nil
}

// validateServerLoadBalancingConfiguration validates server load balancing settings
func validateServerLoadBalancingConfiguration(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("validateServerLoadBalancingConfiguration called with appType='%s', appProfile='%s'", appType, appProfile)
	logger.Debug("validateServerLoadBalancingConfiguration - settings keys: %v", getMapKeys(settings))

	// Check if any server load balancing settings are present (excluding health check fields)
	hasLoadBalancingSettings := false
	loadBalancingFields := []string{
		"load_balancing_metric", "session_sticky", "cookie_age", "tcp_optimization",
	}

	// Health check fields are separate from load balancing
	healthCheckFields := []string{
		"health_check_type", "health_check_http_url", "health_check_timeout",
		"health_check_interval", "health_check_rise", "health_check_fall",
	}

	for _, field := range loadBalancingFields {
		if _, exists := settings[field]; exists {
			hasLoadBalancingSettings = true
			break
		}
	}

	// Check if we have health check settings but no load balancing settings
	hasHealthCheckSettings := false
	for _, field := range healthCheckFields {
		if _, exists := settings[field]; exists {
			hasHealthCheckSettings = true
			break
		}
	}

	// If we only have health check settings and no load balancing settings, skip load balancing validation
	if hasHealthCheckSettings && !hasLoadBalancingSettings {
		logger.Debug("Only health check settings found, skipping load balancing validation")
		return nil
	}

	if !hasLoadBalancingSettings {
		logger.Debug("No server load balancing settings found, skipping validation")
		return nil // No server load balancing settings, skip validation
	}

	logger.Debug("Server load balancing settings found, validating with app_type: %s, app_profile: %s", appType, appProfile)

	// STEP 1: Validate app type and profile restrictions based on Server Load Balancing Matrix
	if appType != "" {
		switch appType {
		case "enterprise":
			// Enterprise Hosted apps - check app profile restrictions
			if appProfile != "" {
				switch appProfile {
				case "rdp", "ssh", "vnc":
					// Hidden for remote desktop protocols
					return client.ErrLoadBalancingNotSupportedForRDP
				case "http", "https", "tcp", "smb":
					// Available for HTTP/HTTPS/TCP/SMB profiles
					logger.Debug("Server load balancing allowed for enterprise app with profile: %s", appProfile)
				default:
					// Available for other profiles
					logger.Debug("Server load balancing allowed for enterprise app with profile: %s", appProfile)
				}
			}
		case "saas", "bookmark":
			// Advanced Settings tab hidden for SaaS and Bookmark apps
			return client.ErrLoadBalancingNotSupportedForSaaS
		case "tunnel":
			// Tunnel apps - check profile restrictions
			if appProfile != "" {
				switch appProfile {
				case "smb":
					//  Available with conditions - but SMB is blocked
					return client.ErrLoadBalancingNotSupportedForTunnelSMB
				default:
					// Available with conditions for other tunnel profiles
					logger.Debug("Tunnel app detected with profile %s - server load balancing available with conditions", appProfile)
					// TCP optimization is only available for tunnel apps
					if _, exists := settings["tcp_optimization"]; exists {
						logger.Debug("TCP optimization detected for tunnel app - this is allowed")
					}
				}
			} else {
				// Available with conditions for tunnel apps (when profile not specified)
				logger.Debug("Tunnel app detected - server load balancing available with conditions")
				// TCP optimization is only available for tunnel apps
				if _, exists := settings["tcp_optimization"]; exists {
					logger.Debug("TCP optimization detected for tunnel app - this is allowed")
				}
			}
		default:
			// For any other app types, server load balancing should not be present
			return client.ErrLoadBalancingNotSupportedForAppType
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		// but we can still validate the server load balancing structure
		logger.Debug("App type not provided, skipping app type validation but continuing with server load balancing structure validation")
		// During schema validation, we'll be more lenient and only validate the structure
		// The app type validation will happen during runtime validation (terraform apply)
	}

	// STEP 2: Validate SLB feature matrix and field restrictions

	// Validate Load Balancing Type (load_balancing_metric)
	if loadBalancingMetric, exists := settings["load_balancing_metric"]; exists {
		metricStr, ok := loadBalancingMetric.(string)
		if !ok {
			return client.ErrLoadBalancingMetricNotString
		}
		validTypes := []string{"round-robin", "ip-hash", "least-conn", "weighted-rr"}
		isValidType := false
		for _, validType := range validTypes {
			if metricStr == validType {
				isValidType = true
				break
			}
		}
		if !isValidType {
			return client.ErrLoadBalancingMetricInvalid
		}
	}

	// Validate Sticky Session (session_sticky)
	if sessionSticky, exists := settings["session_sticky"]; exists {
		if _, ok := sessionSticky.(bool); !ok {
			return client.ErrSessionStickyNotBoolean
		}
	}

	// Validate Cookie Age (cookie_age) - only when sticky session is enabled
	if cookieAge, exists := settings["cookie_age"]; exists {
		if appType != "" && appType != "tunnel" {
			// Cookie age is only valid for non-tunnel apps when sticky session is enabled
			if sessionSticky, stickyExists := settings["session_sticky"]; stickyExists {
				if sessionStickyBool, ok := sessionSticky.(bool); ok && sessionStickyBool {
					// Validate cookie age is a number
					if _, ok := cookieAge.(float64); !ok {
						return client.ErrCookieAgeNotNumber
					}
				} else {
					return client.ErrCookieAgeRequiresStickySession
				}
			} else {
				return client.ErrCookieAgeRequiresStickySession
			}
		} else if appType == "tunnel" {
			return client.ErrCookieAgeNotSupportedForTunnel
		}
	}

	// Validate TCP Optimization (tcp_optimization) - only for tunnel apps
	if tcpOptimization, exists := settings["tcp_optimization"]; exists {
		if _, ok := tcpOptimization.(bool); !ok {
			return client.ErrTCPOptimizationNotBoolean
		}
		if appType != "" && appType != "tunnel" {
			return client.ErrTCPOptimizationOnlyForTunnel
		}
	}

	// STEP 3: Validate Health Check integration with SLB
	// Health check fields are part of SLB configuration
	hasHealthCheckFields := false
	for _, field := range healthCheckFields {
		if _, exists := settings[field]; exists {
			hasHealthCheckFields = true
			break
		}
	}

	if hasHealthCheckFields {
		logger.Debug("Health check fields detected in SLB configuration")

		// Validate health check type
		if healthCheckType, exists := settings["health_check_type"]; exists {
			typeStr, ok := healthCheckType.(string)
			if !ok {
				return client.ErrHealthCheckTypeInvalid
			}

			// Validate health check type enum
			validTypes := []string{"Default", "HTTP", "HTTPS", "TLS", "SSLv3", "TCP", "None"}
			isValidType := false
			for _, validType := range validTypes {
				if typeStr == validType {
					isValidType = true
					break
				}
			}
			if !isValidType {
				return client.ErrHealthCheckTypeUnsupported
			}

			// Validate HTTP-specific fields for HTTP/HTTPS health checks
			if typeStr == "HTTP" || typeStr == "HTTPS" {
				if httpURL, exists := settings["health_check_http_url"]; exists {
					if urlStr, ok := httpURL.(string); !ok || urlStr == "" {
						return client.ErrHealthCheckHTTPURLEmpty
					}
				} else {
					return client.ErrHealthCheckHTTPURLRequired
				}
			}
		}

		// Validate numeric health check fields (as strings)
		numericHealthCheckFields := []string{"health_check_timeout", "health_check_interval", "health_check_rise", "health_check_fall"}
		for _, field := range numericHealthCheckFields {
			if val, exists := settings[field]; exists {
				if _, ok := val.(string); !ok {
					return client.ErrHealthCheckFieldNotString
				}
			}
		}
	}

	return nil
}

// validateCustomHeadersConfiguration validates custom headers configuration
func validateCustomHeadersConfiguration(settings map[string]interface{}, appType string, logger hclog.Logger) error {
	// Check if custom headers are present
	if customHeaders, exists := settings["custom_headers"]; exists {
		logger.Debug("Custom headers found, validating with app_type: %s", appType)

		// STEP 1: Validate app type restrictions based on Table 4: Application Types and Custom HTTP Headers Support
		if appType != "" {
			switch appType {
			case "enterprise":
				// Custom headers are available for Enterprise apps (Advanced Settings)
				logger.Debug("Custom headers allowed for %s app (Advanced Settings)", appType)
				logger.Debug("Continuing with structure validation for enterprise app")
			case "saas", "bookmark":
				// Custom headers are disabled for SaaS and Bookmark apps
				// Since advanced_settings are blocked for these app types, custom headers are not available
				return client.ErrCustomHeadersNotSupportedForSaaS
			case "tunnel":
				//  Custom headers are disabled for tunnel applications
				return client.ErrCustomHeadersNotSupportedForTunnel
			default:
				// For any other app types, custom headers should not be present
				return client.ErrCustomHeadersNotSupportedForAppType
			}
		} else {
			// When appType is empty (schema validation), we cannot validate app type restrictions
			// but we can still validate the custom headers structure
			logger.Debug("App type not provided, skipping app type validation but continuing with custom headers structure validation")
			// During schema validation, we'll be more lenient and only validate the structure
			// The app type validation will happen during runtime validation (terraform apply)
		}

		logger.Debug("App type validation completed, proceeding to structure validation")

		// STEP 2: Sanitize and validate custom headers structure
		logger.Debug("About to validate custom headers structure")
		if headersList, ok := customHeaders.([]interface{}); ok {
			logger.Debug("Custom headers is an array with %d items", len(headersList))
			// Filter out empty headers (Table 8: Empty Headers validation)
			sanitizedHeaders := []interface{}{}
			for _, header := range headersList {
				if headerMap, ok := header.(map[string]interface{}); ok {
					// Check if header is empty (both header and attribute_type are empty)
					headerValue, hasHeader := headerMap["header"]
					attributeTypeValue, hasAttributeType := headerMap["attribute_type"]

					isEmpty := false
					if hasHeader && hasAttributeType {
						if headerStr, headerOk := headerValue.(string); headerOk {
							if attributeTypeStr, attributeTypeOk := attributeTypeValue.(string); attributeTypeOk {
								if headerStr == "" && attributeTypeStr == "" {
									isEmpty = true
								}
							}
						}
					}

					if !isEmpty {
						sanitizedHeaders = append(sanitizedHeaders, header)
					} else {
						logger.Debug("Sanitized empty custom header: %v", headerMap)
					}
				}
			}

			logger.Debug("Sanitized custom headers: %d original -> %d after sanitization", len(headersList), len(sanitizedHeaders))

			// Validate each non-empty custom header
			for i, header := range sanitizedHeaders {
				if headerMap, ok := header.(map[string]interface{}); ok {
					if err := validateCustomHeader(headerMap, i, logger); err != nil {
						return client.ErrCustomHeaderValidation
					}
				} else {
					return client.ErrCustomHeaderNotObject
				}
			}
		} else {
			return client.ErrCustomHeadersNotArray
		}
	}

	return nil
}

// validateCustomHeader validates a single custom header object based on Table 2-11 specifications
func validateCustomHeader(header map[string]interface{}, index int, logger hclog.Logger) error {
	logger.Debug("Validating custom header %d: %v", index, header)

	// STEP 1: Sanitize empty headers (Table 8: Empty Headers validation)
	// Remove headers with empty header and attribute_type
	headerValue, hasHeader := header["header"]
	attributeTypeValue, hasAttributeType := header["attribute_type"]

	if hasHeader && hasAttributeType {
		headerStr, headerOk := headerValue.(string)
		attributeTypeStr, attributeTypeOk := attributeTypeValue.(string)

		if headerOk && attributeTypeOk && headerStr == "" && attributeTypeStr == "" {
			logger.Debug("Skipping empty header %d (both header and attribute_type are empty)", index)
			return nil // Skip validation for empty headers
		}
	}

	// STEP 2: Validate required fields (Table 8: Required Fields validation)
	// Header name is required
	if !hasHeader {
		return client.ErrCustomHeaderMissingHeader
	}

	headerStr, ok := headerValue.(string)
	if !ok {
		return client.ErrCustomHeaderHeaderNotString
	}
	if headerStr == "" {
		return client.ErrCustomHeaderHeaderEmpty
	}

	// STEP 3: Validate attribute_type field (Table 3: Custom Header Attribute Types)
	if hasAttributeType {
		attributeTypeStr, ok := attributeTypeValue.(string)
		if !ok {
			return client.ErrCustomHeaderAttributeTypeNotString
		}

		// Validate attribute_type enum (Table 9: Custom Header Constants)
		validAttributeTypes := []string{"user", "group", "clientip", "fixed", "custom"}
		isValidAttributeType := false
		for _, validType := range validAttributeTypes {
			if attributeTypeStr == validType {
				isValidAttributeType = true
				break
			}
		}
		if !isValidAttributeType && attributeTypeStr != "" {
			return client.ErrCustomHeaderAttributeTypeInvalid
		}

		// STEP 4: Conditional validation for attribute field (Table 8: Attribute Input validation)
		// Attribute input is required when CUSTOM or FIXED is selected
		if attributeTypeStr == "custom" || attributeTypeStr == "fixed" {
			attributeValue, hasAttribute := header["attribute"]
			if !hasAttribute {
				return client.ErrCustomHeaderAttributeRequired
			}

			attributeStr, ok := attributeValue.(string)
			if !ok {
				return client.ErrCustomHeaderAttributeNotString
			}
			if attributeStr == "" {
				return client.ErrCustomHeaderAttributeEmpty
			}

			logger.Debug("Custom header %d: validated %s attribute_type with attribute='%s'", index, attributeTypeStr, attributeStr)
		} else if attributeTypeStr == "user" || attributeTypeStr == "group" || attributeTypeStr == "clientip" {
			// For user, group, clientip - attribute is not required (dropdown selection)
			logger.Debug("Custom header %d: validated %s attribute_type (no attribute input required)", index, attributeTypeStr)
		}
	} else {
		// If attribute_type is not provided, attribute should also not be provided
		if _, hasAttribute := header["attribute"]; hasAttribute {
			return client.ErrCustomHeaderAttributeNotAllowed
		}
	}

	// STEP 5: Validate attribute field type (if present)
	if attributeValue, hasAttribute := header["attribute"]; hasAttribute {
		if _, ok := attributeValue.(string); !ok {
			return client.ErrCustomHeaderAttributeNotString
		}
	}

	logger.Debug("Custom header %d validation passed", index)
	return nil
}

// validateMiscellaneousConfiguration validates miscellaneous settings based on HTML conditions
func validateMiscellaneousConfiguration(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("validateMiscellaneousConfiguration called with appType='%s', appProfile='%s'", appType, appProfile)

	// Check if any miscellaneous settings are present
	hasMiscSettings := false
	miscFields := []string{
		"proxy_buffer_size_kb", "ssh_audit_enabled", "allow_cors", "cors_origin_list",
		"cors_header_list", "cors_method_list", "cors_support_credential", "cors_max_age",
		"websocket_enabled", "https_sslv3", "logging_enabled", "hidden_app", "saas_enabled",
		"sticky_agent", "offload_onpremise_traffic", "x_wapp_pool_enabled", "x_wapp_pool_size",
		"x_wapp_pool_timeout", "is_brotli_enabled",
	}

	for _, field := range miscFields {
		if _, exists := settings[field]; exists {
			hasMiscSettings = true
			break
		}
	}

	if !hasMiscSettings {
		logger.Debug("No miscellaneous settings found, skipping validation")
		return nil
	}

	logger.Debug("Miscellaneous settings found, validating with conditions")

	// 1. SSH-specific fields validation
	if err := validateSSHSpecificFields(settings, appProfile); err != nil {
		return err
	}

	// 2. CORS fields validation (non-tunnel apps only)
	if err := validateCORSFields(settings, appType); err != nil {
		return err
	}

	// 3. WebSocket fields validation (not RDP v2)
	if err := validateWebSocketFields(settings, appProfile, logger); err != nil {
		return err
	}

	// 4. Traffic offload validation (not RDP/SSH/VNC/tunnel)
	if err := validateTrafficOffloadFields(settings, appType, appProfile); err != nil {
		return err
	}

	// 5. Tunnel-specific pool fields validation
	if err := validateTunnelPoolFields(settings, appType, logger); err != nil {
		return err
	}

	return nil
}

// validateSSHSpecificFields validates SSH-specific fields
func validateSSHSpecificFields(settings map[string]interface{}, appProfile string) error {
	// SSH fields are only available when isSsh() is true
	// Based on HTML: ng-show="$ctrl.isSsh()"
	sshFields := []string{"ssh_audit_enabled"}

	for _, field := range sshFields {
		if _, exists := settings[field]; exists {
			// Check if this is an SSH app profile
			if appProfile != "ssh" {
				return client.ErrMiscFieldOnlyForSSH
			}
		}
	}

	return nil
}

// validateCORSFields validates CORS fields (non-tunnel apps only)
func validateCORSFields(settings map[string]interface{}, appType string) error {
	// CORS fields are not available for tunnel apps
	// Based on HTML: ng-if="$ctrl.application.app_type!==$ctrl.ApplicationType.APP_TYPE_TUNNEL"
	corsFields := []string{"allow_cors", "cors_origin_list", "cors_header_list", "cors_method_list", "cors_support_credential", "cors_max_age"}

	for _, field := range corsFields {
		if _, exists := settings[field]; exists {
			if appType == "tunnel" {
				return client.ErrMiscFieldNotAvailableForTunnel
			}
		}
	}

	// Additional validation: CORS detail fields only when allow_cors is true
	if allowCors, exists := settings["allow_cors"]; exists {
		if allowCors == "true" {
			requiredCorsFields := []string{"cors_origin_list", "cors_header_list", "cors_method_list", "cors_support_credential", "cors_max_age"}
			for _, field := range requiredCorsFields {
				if _, fieldExists := settings[field]; !fieldExists {
					return client.ErrMiscCORSFieldRequired
				}
			}
		}
	}

	return nil
}

// validateWebSocketFields validates WebSocket fields (not RDP v2)
func validateWebSocketFields(settings map[string]interface{}, appProfile string, logger hclog.Logger) error {
	// WebSocket fields are not available for RDP v2
	// Based on HTML: ng-if="$ctrl.application.rdp_version !== $ctrl.RDP_VERSION.V2"
	if _, exists := settings["websocket_enabled"]; exists {
		if appProfile == "rdp" {
			// WebSocket fields are not available for RDP applications
			logger.Warn("WebSocket fields are not available for RDP applications")
			return client.ErrWebSocketNotAvailableForRDP
		}
	}

	return nil
}

// validateTrafficOffloadFields validates traffic offload fields
func validateTrafficOffloadFields(settings map[string]interface{}, appType, appProfile string) error {
	// Traffic offload is not available for RDP, SSH, VNC, or tunnel apps
	// Based on HTML: ng-if="$ctrl.appProtocol != $ctrl.APP_PROTOCOLS.RDP && $ctrl.appProtocol != $ctrl.APP_PROTOCOLS.SSH && $ctrl.appProtocol != $ctrl.APP_PROTOCOLS.VNC && $ctrl.application.app_type != $ctrl.applicationType.APP_TYPE_TUNNEL"
	if _, exists := settings["offload_onpremise_traffic"]; exists {
		restrictedProfiles := []string{"rdp", "ssh", "vnc"}
		restrictedTypes := []string{"tunnel"}

		for _, profile := range restrictedProfiles {
			if appProfile == profile {
				return client.ErrMiscOffloadNotAvailableForProfile
			}
		}

		for _, appTypeCheck := range restrictedTypes {
			if appType == appTypeCheck {
				return client.ErrMiscOffloadNotAvailableForType
			}
		}
	}

	return nil
}

// validateRelatedApplications validates related applications (app_bundle) field restrictions
func validateRelatedApplications(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("validateRelatedApplications called with appType='%s', appProfile='%s'", appType, appProfile)

	// Check if app_bundle field is present
	if _, exists := settings["app_bundle"]; !exists {
		logger.Debug("No related applications settings found, skipping validation")
		return nil // No related applications settings, skip validation
	}

	logger.Debug("Related applications settings found, validating with app_type: %s, app_profile: %s", appType, appProfile)

	// STEP 1: Validate app type and profile restrictions
	if appType != "" {
		switch appType {
		case "enterprise":
			// Enterprise apps - check app profile restrictions
			if appProfile != "" {
				switch appProfile {
				case "vnc", "ssh", "smb":
					// Related Applications are NOT allowed for VNC, SSH, SMB profiles
					logger.Error("Related applications (app_bundle) are not supported for enterprise app with profile: %s", appProfile)
					return client.ErrRelatedApplicationsNotSupportedForProfile
				case "http", "https", "tcp", "rdp":
					// Available for HTTP/HTTPS/TCP/RDP profiles
					logger.Debug("Related applications allowed for enterprise app with profile: %s", appProfile)
				default:
					// Available for other profiles
					logger.Debug("Related applications allowed for enterprise app with profile: %s", appProfile)
				}
			} else {
				logger.Debug("Related applications allowed for enterprise app (profile not specified)")
			}
		case "saas", "bookmark":
			// Advanced Settings tab hidden for SaaS and Bookmark apps
			logger.Debug("Related applications not available for app_type: %s", appType)
			return client.ErrRelatedApplicationsNotSupportedForProfile
		case "tunnel":
			// Tunnel apps - Related Applications are not available
			logger.Debug("Related applications not available for tunnel apps")
			return client.ErrRelatedApplicationsNotSupportedForProfile
		default:
			// For any other app types, related applications should not be present
			logger.Debug("Related applications not available for app_type: %s", appType)
			return client.ErrRelatedApplicationsNotSupportedForProfile
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		// but we can still validate the related applications structure
		logger.Debug("App type not provided, skipping app type validation but continuing with related applications structure validation")
		// During schema validation, we'll be more lenient and only validate the structure
		// The app type validation will happen during runtime validation (terraform apply)
	}

	logger.Debug("Related applications parameters validated successfully")
	return nil
}

// validateTunnelPoolFields validates tunnel-specific pool fields
func validateTunnelPoolFields(settings map[string]interface{}, appType string, logger hclog.Logger) error {
	// Tunnel pool fields are only available for tunnel apps with feature flag
	// Based on HTML: ng-if="$ctrl.eaaFeatures.TUNNEL_REUSE_PER_APP_FEATURE_KEY && $ctrl.application.app_type === $ctrl.ApplicationType.APP_TYPE_TUNNEL"
	tunnelPoolFields := []string{"x_wapp_pool_enabled", "x_wapp_pool_size", "x_wapp_pool_timeout"}

	for _, field := range tunnelPoolFields {
		if _, exists := settings[field]; exists {
			if appType != "tunnel" {
				return client.ErrMiscFieldOnlyForTunnel
			}
			// Note: Feature flag check would need to be implemented based on actual feature flag logic
			logger.Debug("Tunnel pool field %s validated for tunnel app (feature flag check not implemented)", field)
		}
	}

	return nil
}

// validateWSFEDNestedBlocks validates WSFED nested blocks configuration
func validateWSFEDNestedBlocks(ctx context.Context, d *schema.ResourceDiff, m interface{}, logger hclog.Logger) error {
	logger.Debug("validateWSFEDNestedBlocks called")

	// Check if wsfed is enabled
	wsfedEnabled, ok := d.GetOk("wsfed")
	if !ok || !wsfedEnabled.(bool) {
		logger.Debug("WSFED not enabled, skipping validation")
		return nil
	}

	logger.Debug("WSFED is enabled, validating nested blocks")

	// Get wsfed_settings nested blocks
	wsfedSettings, ok := d.GetOk("wsfed_settings")
	if !ok {
		logger.Debug("No wsfed_settings found")
		return nil
	}

	wsfedSettingsList, ok := wsfedSettings.([]interface{})
	if !ok || len(wsfedSettingsList) == 0 {
		logger.Debug("wsfed_settings is empty or not a list")
		return nil
	}

	// Get the first (and only) wsfed_settings block
	wsfedBlock := wsfedSettingsList[0].(map[string]interface{})

	// Check IDP block for self_signed validation
	if idpBlocks, ok := wsfedBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
		idpBlock := idpBlocks[0].(map[string]interface{})

		if selfSigned, hasSelfSigned := idpBlock["self_signed"]; hasSelfSigned {
			if selfSignedBool, ok := selfSigned.(bool); ok && !selfSignedBool {
				logger.Debug("self_signed = false, checking sign_cert")
				// When self_signed = false, sign_cert is mandatory
				if signCert, hasSignCert := idpBlock["sign_cert"]; !hasSignCert || signCert == "" {
					logger.Debug("sign_cert missing or empty: hasSignCert=%v, signCert='%v'", hasSignCert, signCert)
					return client.ErrWSFEDSignCertRequired
				}
			}
		}
	}

	logger.Info("WSFED nested blocks validation passed")
	return nil
}

// validateSAMLNestedBlocks validates SAML nested blocks configuration
func validateSAMLNestedBlocks(ctx context.Context, d *schema.ResourceDiff, m interface{}, logger hclog.Logger) error {
	logger.Debug("validateSAMLNestedBlocks called")

	// Check if saml is enabled
	samlEnabled, ok := d.GetOk("saml")
	if !ok || !samlEnabled.(bool) {
		logger.Debug("SAML not enabled, skipping validation")
		return nil
	}

	logger.Debug("SAML is enabled, validating nested blocks")

	// Get saml_settings nested blocks
	samlSettings, ok := d.GetOk("saml_settings")
	if !ok {
		logger.Debug("No saml_settings found")
		return nil
	}

	samlSettingsList, ok := samlSettings.([]interface{})
	if !ok || len(samlSettingsList) == 0 {
		logger.Debug("saml_settings is empty or not a list")
		return nil
	}

	// Get the first (and only) saml_settings block
	samlBlock := samlSettingsList[0].(map[string]interface{})

	// Check IDP block for self_signed validation
	if idpBlocks, ok := samlBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
		idpBlock := idpBlocks[0].(map[string]interface{})

		if selfSigned, hasSelfSigned := idpBlock["self_signed"]; hasSelfSigned {
			if selfSignedBool, ok := selfSigned.(bool); ok && !selfSignedBool {
				logger.Debug("self_signed = false, checking sign_cert")
				// When self_signed = false, sign_cert is mandatory
				if signCert, hasSignCert := idpBlock["sign_cert"]; !hasSignCert || signCert == "" {
					logger.Debug("sign_cert missing or empty: hasSignCert=%v, signCert='%v'", hasSignCert, signCert)
					return client.ErrSAMLSignCertRequired
				}
			}
		}
	}

	return nil
}

// validateOIDCNestedBlocks validates OIDC nested blocks configuration
func validateOIDCNestedBlocks(ctx context.Context, d *schema.ResourceDiff, m interface{}, logger hclog.Logger) error {

	// Check if oidc is enabled
	oidcEnabled, ok := d.GetOk("oidc")
	if !ok || !oidcEnabled.(bool) {
		logger.Debug("OIDC not enabled, skipping validation")
		return nil
	}

	// Get oidc_settings nested blocks
	oidcSettings, ok := d.GetOk("oidc_settings")
	if !ok {
		logger.Debug("No oidc_settings found")
		return nil
	}

	oidcSettingsList, ok := oidcSettings.([]interface{})
	if !ok || len(oidcSettingsList) == 0 {
		logger.Debug("oidc_settings is empty or not a list")
		return nil
	}

	// Get the first (and only) oidc_settings block
	oidcBlock := oidcSettingsList[0].(map[string]interface{})

	// Validate OIDC clients if present
	if oidcClients, ok := oidcBlock["oidc_clients"].([]interface{}); ok && len(oidcClients) > 0 {

		for i, clientData := range oidcClients {
			if clientMap, ok := clientData.(map[string]interface{}); ok {
				if err := validateOIDCClientNested(clientMap, i, logger); err != nil {
					return client.ErrOIDCClientValidation
				}
			} else {
				return client.ErrOIDCClientNotObject
			}
		}
	}

	return nil
}

// validateOIDCClientNested validates an OIDC client configuration in nested blocks
func validateOIDCClientNested(clientConfig map[string]interface{}, index int, logger hclog.Logger) error {
	logger.Debug("Validating OIDC client %d: %v", index, clientConfig)

	// Validate that response_type is an array if present
	if responseTypes, exists := clientConfig["response_type"]; exists {
		if _, ok := responseTypes.([]interface{}); !ok {
			return client.ErrOIDCResponseTypeNotArray
		}
	}

	// Validate that redirect_uris is an array if present
	if redirectURIs, exists := clientConfig["redirect_uris"]; exists {
		if _, ok := redirectURIs.([]interface{}); !ok {
			return client.ErrOIDCRedirectURIsNotArray
		}
	}

	// Validate that javascript_origins is an array if present
	if jsOrigins, exists := clientConfig["javascript_origins"]; exists {
		if _, ok := jsOrigins.([]interface{}); !ok {
			return client.ErrOIDCJavaScriptOriginsNotArray
		}
	}

	// Validate that post_logout_redirect_uri is an array if present
	if postLogoutURIs, exists := clientConfig["post_logout_redirect_uri"]; exists {
		if _, ok := postLogoutURIs.([]interface{}); !ok {
			return client.ErrOIDCPostLogoutURIsNotArray
		}
	}

	// Validate claims if present
	if claims, exists := clientConfig["claims"]; exists {
		if claimsList, ok := claims.([]interface{}); ok {
			for i, claim := range claimsList {
				if claimMap, ok := claim.(map[string]interface{}); ok {
					if err := validateOIDCClaimNested(claimMap, i, logger); err != nil {
						return client.ErrOIDCClaimValidation
					}
				} else {
					return client.ErrOIDCClaimNotObject
				}
			}
		} else {
			return client.ErrOIDCClaimsNotArray
		}
	}

	return nil
}

// validateOIDCClaimNested validates an OIDC claim configuration in nested blocks
func validateOIDCClaimNested(claim map[string]interface{}, index int, logger hclog.Logger) error {
	logger.Debug("Validating OIDC claim %d: %v", index, claim)

	// Only validate that it's a non-empty object
	if len(claim) == 0 {
		return client.ErrOIDCClaimEmpty
	}

	return nil
}
