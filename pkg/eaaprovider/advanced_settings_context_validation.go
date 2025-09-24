package eaaprovider

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
)

// ValidateAdvancedSettingsContext validates all context-dependent rules
func ValidateAdvancedSettingsContext(settings map[string]interface{}, appType, appProfile, clientAppMode string, logger hclog.Logger) error {
	logger.Debug("Validating context-dependent rules")

	// App Auth Special Dependencies
	if err := validateAppAuthSpecialDependencies(settings, appType, appProfile, logger); err != nil {
		return err
	}

	// Tunnel Client Parameters Restrictions
	if err := validateTunnelClientParametersRestrictions(settings, appType, clientAppMode, logger); err != nil {
		return err
	}

	// Enterprise Connectivity Parameters Restrictions
	if err := validateEnterpriseConnectivityParametersRestrictions(settings, appType, clientAppMode, logger); err != nil {
		return err
	}

	// Miscellaneous Parameters Restrictions
	if err := validateMiscellaneousParametersRestrictions(settings, appType, clientAppMode, logger); err != nil {
		return err
	}

	// RDP Configuration Restrictions
	if err := validateRDPConfigurationRestrictions(settings, appType, appProfile, logger); err != nil {
		return err
	}

	logger.Debug("Context-dependent rules validation completed")
	return nil
}

// validateAppAuthSpecialDependencies validates app_auth-specific restrictions
func validateAppAuthSpecialDependencies(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("Validating app_auth special dependencies")

	// Check if app_auth is present
	if _, exists := settings["app_auth"]; !exists {
		logger.Debug("No app_auth field found, skipping app_auth special dependencies validation")
		return nil
	}

	// Apply the same restrictions as validateAppAuthForTypeAndProfile
	switch {
	case appType == "enterprise" && appProfile == "ssh":
		logger.Warn("app_auth is disabled for enterprise SSH apps")
		return fmt.Errorf("app_auth is disabled for enterprise SSH apps")

	case appType == "saas":
		logger.Warn("app_auth should not be present in advanced_settings for SaaS apps")
		return fmt.Errorf("app_auth should not be present in advanced_settings for SaaS apps")

	case appType == "bookmark":
		logger.Warn("app_auth should not be present in advanced_settings for bookmark apps")
		return fmt.Errorf("app_auth should not be present in advanced_settings for bookmark apps")

	case appType == "tunnel":
		logger.Warn("app_auth should not be present in advanced_settings for tunnel apps")
		return fmt.Errorf("app_auth should not be present in advanced_settings for tunnel apps")

	case appType == "enterprise" && appProfile == "vnc":
		logger.Warn("app_auth is disabled for enterprise VNC apps")
		return fmt.Errorf("app_auth is disabled for enterprise VNC apps")
	}

	logger.Debug("App auth special dependencies validation completed")
	return nil
}

// validateTunnelClientParametersRestrictions validates tunnel client parameters restrictions
func validateTunnelClientParametersRestrictions(settings map[string]interface{}, appType, clientAppMode string, logger hclog.Logger) error {
	logger.Debug("Validating tunnel client parameters restrictions")

	// Define EAA Client Parameters that are only available for tunnel apps
	tunnelClientParameters := []string{
		"domain_exception_list",
		"acceleration",
		"force_ip_route",
		"x_wapp_pool_enabled",
		"x_wapp_pool_size",
		"x_wapp_pool_timeout",
	}

	// Check if any tunnel client parameters are present
	hasTunnelClientParameters := false
	for _, field := range tunnelClientParameters {
		if _, exists := settings[field]; exists {
			hasTunnelClientParameters = true
			break
		}
	}

	if !hasTunnelClientParameters {
		logger.Debug("No tunnel client parameters found, skipping restrictions validation")
		return nil // No tunnel client parameters, skip validation
	}

	// Validate app type and client app mode restrictions
	if appType != "" {
		if appType != "tunnel" {
			logger.Warn("Tunnel client parameters are not supported for app_type='%s'", appType)
			return fmt.Errorf("tunnel client parameters are not supported for app_type='%s'", appType)
		}

		if clientAppMode != "" {
			// EAA Client Parameters are only available for tunnel apps with tunnel or ZTP mode
			if clientAppMode != "tunnel" && clientAppMode != "ztp" {
				logger.Warn("Tunnel client parameters are not supported for client_app_mode='%s'", clientAppMode)
				return fmt.Errorf("tunnel client parameters are not supported for client_app_mode='%s'", clientAppMode)
			}
			logger.Debug("Tunnel client parameters allowed for tunnel app with %s mode", clientAppMode)
		} else {
			logger.Debug("Tunnel client parameters allowed for tunnel app (client_app_mode not specified)")
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		logger.Debug("App type not provided, skipping tunnel client parameters restrictions validation")
	}

	logger.Debug("Tunnel client parameters restrictions validation completed")
	return nil
}

// validateEnterpriseConnectivityParametersRestrictions validates enterprise connectivity parameters restrictions
func validateEnterpriseConnectivityParametersRestrictions(settings map[string]interface{}, appType, clientAppMode string, logger hclog.Logger) error {
	logger.Debug("Validating enterprise connectivity parameters restrictions")

	// Check if any enterprise connectivity parameters are present
	hasEnterpriseConnectivitySettings := false
	enterpriseConnectivityFields := []string{
		"idle_conn_floor", "idle_conn_ceil", "idle_conn_step",
		"idle_close_time_seconds", "app_server_read_timeout", "hsts_age",
		"max_conn_floor", "max_conn_ceil", "max_conn_step", "conn_retry_interval",
		"conn_retry_max_attempts", "conn_retry_max_interval",
	}

	for _, field := range enterpriseConnectivityFields {
		if _, exists := settings[field]; exists {
			hasEnterpriseConnectivitySettings = true
			break
		}
	}

	if !hasEnterpriseConnectivitySettings {
		logger.Debug("No enterprise connectivity settings found, skipping restrictions validation")
		return nil
	}

	// Validate app type and client app mode restrictions
	if appType != "" {
		switch appType {
		case "enterprise":
			// Enterprise apps - check client_app_mode
			if clientAppMode != "" {
				if clientAppMode != "tcp" && clientAppMode != "tunnel" {
					logger.Warn("Enterprise connectivity parameters are not supported for client_app_mode='%s'", clientAppMode)
					return fmt.Errorf("enterprise connectivity parameters are not supported for client_app_mode='%s'", clientAppMode)
				}
			}
		case "tunnel":
			// Available for tunnel apps
			logger.Debug("Enterprise connectivity allowed for tunnel app")
		case "saas", "bookmark":
			// Advanced Settings tab hidden for SaaS and Bookmark apps
			logger.Warn("Enterprise connectivity parameters are not supported for app_type='%s'", appType)
			return fmt.Errorf("enterprise connectivity parameters are not supported for app_type='%s'", appType)
		default:
			// For any other app types, enterprise connectivity should not be present
			logger.Warn("Enterprise connectivity parameters are not supported for app_type='%s'", appType)
			return fmt.Errorf("enterprise connectivity parameters are not supported for app_type='%s'", appType)
		}
	}

	logger.Debug("Enterprise connectivity parameters restrictions validation completed")
	return nil
}

// validateMiscellaneousParametersRestrictions validates miscellaneous parameters restrictions
func validateMiscellaneousParametersRestrictions(settings map[string]interface{}, appType, clientAppMode string, logger hclog.Logger) error {
	logger.Debug("Validating miscellaneous parameters restrictions")

	// Check if any miscellaneous settings are present
	hasMiscellaneousSettings := false
	miscellaneousFields := []string{
		"proxy_buffer_size_kb", "ssh_audit_enabled", "allow_cors", "cors_origin_list",
		"cors_header_list", "cors_method_list", "cors_support_credential", "cors_max_age",
		"websocket_enabled", "https_sslv3", "logging_enabled", "hidden_app",
		"saas_enabled", "sticky_agent", "x_wapp_read_timeout",
		"dynamic_ip", "sticky_cookies", "offload_onpremise_traffic",
		"custom_headers", "enable_client_side_xhr_rewrite", "is_brotli_enabled",
		"inject_ajax_javascript", "internal_host_port", "onramp", "proxy_disable_clipboard",
		"rate_limit", "request_body_rewrite", "request_parameters",
	}

	for _, field := range miscellaneousFields {
		if _, exists := settings[field]; exists {
			hasMiscellaneousSettings = true
			break
		}
	}

	if !hasMiscellaneousSettings {
		logger.Debug("No miscellaneous settings found, skipping restrictions validation")
		return nil
	}

	// Validate app type and client_app_mode restrictions
	if appType != "" {
		switch appType {
		case "enterprise":
			// Enterprise apps - check client_app_mode
			if clientAppMode != "" {
				if clientAppMode != "tcp" && clientAppMode != "tunnel" {
					logger.Warn("Miscellaneous parameters are not supported for client_app_mode='%s'", clientAppMode)
					return fmt.Errorf("miscellaneous parameters are not supported for client_app_mode='%s'", clientAppMode)
				}
			}
		case "tunnel":
			// Available for tunnel apps
			logger.Debug("Miscellaneous parameters allowed for tunnel app")
		case "saas", "bookmark":
			// Advanced Settings tab hidden for SaaS and Bookmark apps
			logger.Warn("Miscellaneous parameters are not supported for app_type='%s'", appType)
			return fmt.Errorf("miscellaneous parameters are not supported for app_type='%s'", appType)
		default:
			// For any other app types, miscellaneous parameters should not be present
			logger.Warn("Miscellaneous parameters are not supported for app_type='%s'", appType)
			return fmt.Errorf("miscellaneous parameters are not supported for app_type='%s'", appType)
		}
	}

	logger.Debug("Miscellaneous parameters restrictions validation completed")
	return nil
}

// validateRDPConfigurationRestrictions validates RDP configuration restrictions
func validateRDPConfigurationRestrictions(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("Validating RDP configuration restrictions")

	// Check if any RDP configuration settings are present
	hasRDPConfigurationSettings := false
	rdpConfigurationFields := []string{
		"rdp_initial_program", "remote_app", "remote_app_args", "remote_app_dir",
		"rdp_tls1", "remote_spark_mapClipboard", "rdp_legacy_mode", "remote_spark_audio",
		"remote_spark_mapPrinter", "remote_spark_printer", "remote_spark_mapDisk",
		"remote_spark_disk", "remote_spark_recording",
		// RDP User Preferences fields
		"rdp_keyboard_lang", "rdp_window_color_depth", "rdp_window_height", "rdp_window_width",
	}

	for _, field := range rdpConfigurationFields {
		if _, exists := settings[field]; exists {
			hasRDPConfigurationSettings = true
			break
		}
	}

	if !hasRDPConfigurationSettings {
		logger.Debug("No RDP configuration settings found, skipping restrictions validation")
		return nil
	}

	// Validate app type and profile restrictions
	if appType != "" {
		if appType != "enterprise" {
			logger.Warn("RDP configuration is not supported for app_type='%s'", appType)
			return fmt.Errorf("RDP configuration is not supported for app_type='%s'", appType)
		}

		if appProfile != "" {
			if appProfile != "rdp" {
				logger.Warn("RDP configuration is not supported for app_profile='%s'", appProfile)
				return fmt.Errorf("RDP configuration is not supported for app_profile='%s'", appProfile)
			}
		}
	}

	logger.Debug("RDP configuration restrictions validation completed")
	return nil
}
