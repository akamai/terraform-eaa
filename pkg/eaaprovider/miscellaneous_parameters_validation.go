package eaaprovider

import (
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
)

// validateMiscellaneousParameters validates miscellaneous settings
func validateMiscellaneousParameters(settings map[string]interface{}, appType, appProfile, clientAppMode string, logger hclog.Logger) error {
	logger.Debug("validateMiscellaneousParameters called with appType='%s', appProfile='%s', clientAppMode='%s'", appType, appProfile, clientAppMode)
	logger.Debug("validateMiscellaneousParameters - settings keys: %v", getMapKeys(settings))

	// Check if any miscellaneous settings are present
	hasMiscellaneousSettings := false
	miscellaneousFields := []string{
		"proxy_buffer_size_kb", "ssh_audit_enabled", "allow_cors", "cors_origin_list",
		"cors_header_list", "cors_method_list", "cors_support_credential", "cors_max_age",
		"websocket_enabled", "https_sslv3", "logging_enabled", "hidden_app",
		"saas_enabled", "sticky_agent", "x_wapp_read_timeout",
		"dynamic_ip", "sticky_cookies", "offload_onpremise_traffic",
	}

	for _, field := range miscellaneousFields {
		if _, exists := settings[field]; exists {
			hasMiscellaneousSettings = true
			break
		}
	}

	if !hasMiscellaneousSettings {
		logger.Debug("No miscellaneous settings found, skipping validation")
		return nil // No miscellaneous settings, skip validation
	}

	logger.Debug("Miscellaneous settings found, validating with app_type: %s, app_profile: %s, client_app_mode: %s", appType, appProfile, clientAppMode)

	// STEP 1: Validate app type and client_app_mode restrictions
	if appType != "" {
		switch appType {
		case "enterprise":
			// Enterprise apps - check client_app_mode
			if clientAppMode != "" {
				if clientAppMode != "tcp" && clientAppMode != "tunnel" {
					return client.ErrMiscParametersNotSupportedForClientMode
				}
				logger.Debug("Miscellaneous parameters allowed for enterprise app with client_app_mode=%s", clientAppMode)
			} else {
				logger.Debug("Miscellaneous parameters allowed for enterprise app (client_app_mode not specified)")
			}
		case "tunnel":
			// Available for tunnel apps
			logger.Debug("Miscellaneous parameters allowed for tunnel app")
		case "saas", "bookmark":
			//  Advanced Settings tab hidden for SaaS and Bookmark apps
			return client.ErrMiscParametersNotSupportedForSaaS
		default:
			// For any other app types, miscellaneous parameters should not be present
			return client.ErrMiscParametersNotSupportedForAppType
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		// but we can still validate the miscellaneous structure
		logger.Debug("App type not provided, skipping app type validation but continuing with miscellaneous structure validation")
		// During schema validation, we'll be more lenient and only validate the structure
		// The app type validation will happen during runtime validation (terraform apply)
	}

	// STEP 2: Validate individual miscellaneous parameters

	// Validate proxy_buffer_size_kb (Spinner: 4-256, Step: 4, Default: 4)
	if proxyBufferSize, exists := settings["proxy_buffer_size_kb"]; exists {
		if bufferSizeStr, ok := proxyBufferSize.(string); ok {
			if bufferSizeInt, err := strconv.Atoi(bufferSizeStr); err == nil {
				if bufferSizeInt < 4 || bufferSizeInt > 256 {
					return client.ErrProxyBufferSizeOutOfRange
				}
				if bufferSizeInt%4 != 0 {
					return client.ErrProxyBufferSizeNotMultipleOf4
				}
			} else {
				return client.ErrProxyBufferSizeInvalidNumber
			}
		} else {
			return client.ErrProxyBufferSizeNotString
		}
	}

	// Validate ssh_audit_enabled (SSH applications only)
	if sshAuditEnabled, exists := settings["ssh_audit_enabled"]; exists {
		if _, ok := sshAuditEnabled.(bool); !ok {
			return client.ErrSSHAuditNotBoolean
		}
		if appProfile != "" && appProfile != "ssh" {
			return client.ErrSSHAuditOnlyForSSH
		}
	}

	// Validate CORS parameters (Non-tunnel applications only)
	if allowCors, exists := settings["allow_cors"]; exists {
		if _, ok := allowCors.(bool); !ok {
			return client.ErrAllowCorsNotBoolean
		}
		if appType == "tunnel" {
			return client.ErrAllowCorsNotAvailableForTunnel
		}

		// If CORS is enabled, validate CORS sub-parameters
		if allowCorsBool, ok := allowCors.(bool); ok && allowCorsBool {
			// Validate string CORS parameters
			stringCorsParams := []string{"cors_origin_list", "cors_header_list", "cors_method_list", "cors_max_age"}
			for _, param := range stringCorsParams {
				if val, exists := settings[param]; exists {
					if _, ok := val.(string); !ok {
						return client.ErrCorsParameterNotString
					}
				}
			}

			// Validate boolean CORS parameters
			if corsSupportCredential, exists := settings["cors_support_credential"]; exists {
				if _, ok := corsSupportCredential.(bool); !ok {
					return client.ErrCorsSupportCredentialNotBoolean
				}
			}
		}
	}

	// Validate websocket_enabled (Non-RDP v2 applications)
	if websocketEnabled, exists := settings["websocket_enabled"]; exists {
		if _, ok := websocketEnabled.(bool); !ok {
			return client.ErrWebSocketEnabledNotBoolean
		}
		// Note: RDP v2 detection would require additional context about RDP version
		// For now, we'll allow it for all non-RDP applications
		if appProfile == "rdp" {
			logger.Debug("websocket_enabled for RDP application - validation depends on RDP version")
		}
	}

	// Validate https_sslv3 (All applications)
	if httpsSslv3, exists := settings["https_sslv3"]; exists {
		if _, ok := httpsSslv3.(bool); !ok {
			return client.ErrHTTPSSSLv3NotBoolean
		}
	}

	// Validate logging_enabled (All applications)
	if loggingEnabled, exists := settings["logging_enabled"]; exists {
		if _, ok := loggingEnabled.(bool); !ok {
			return client.ErrLoggingEnabledNotBoolean
		}
	}

	// Validate hidden_app (Non-tunnel applications)
	if hiddenApp, exists := settings["hidden_app"]; exists {
		if _, ok := hiddenApp.(bool); !ok {
			return client.ErrHiddenAppNotBoolean
		}
		if appType == "tunnel" {
			return client.ErrHiddenAppNotAvailableForTunnel
		}
	}

	// Validate saas_enabled (All applications)
	if saasEnabled, exists := settings["saas_enabled"]; exists {
		if _, ok := saasEnabled.(bool); !ok {
			return client.ErrSaasEnabledNotBoolean
		}
	}

	// Validate sticky_agent (All applications)
	if stickyAgent, exists := settings["sticky_agent"]; exists {
		if _, ok := stickyAgent.(bool); !ok {
			return client.ErrStickyAgentNotBoolean
		}
	}

	// Validate x_wapp_read_timeout (Tunnel apps only)
	if xWappReadTimeout, exists := settings["x_wapp_read_timeout"]; exists {
		if timeoutStr, ok := xWappReadTimeout.(string); ok {
			if timeoutInt, err := strconv.Atoi(timeoutStr); err == nil {
				if timeoutInt < 0 {
					return client.ErrXWappReadTimeoutNotPositive
				}
			} else {
				return client.ErrXWappReadTimeoutInvalidNumber
			}
		} else {
			return client.ErrXWappReadTimeoutNotString
		}
		if appType != "tunnel" {
			return client.ErrXWappReadTimeoutOnlyForTunnel
		}
	}

	// Validate dynamic_ip (Dynamic IP for application server)
	if dynamicIP, exists := settings["dynamic_ip"]; exists {
		if _, ok := dynamicIP.(bool); !ok {
			return client.ErrDynamicIpNotBoolean
		}
		// Dynamic IP is available for all applications
		logger.Debug("dynamic_ip parameter validated for app_type=%s", appType)
	}

	// Validate sticky_cookies (Use sticky cookies for connectors)
	if stickyCookies, exists := settings["sticky_cookies"]; exists {
		if _, ok := stickyCookies.(bool); !ok {
			return client.ErrStickyCookiesNotBoolean
		}
		// Sticky cookies are available for all applications
		logger.Debug("sticky_cookies parameter validated for app_type=%s", appType)
	}

	// Validate offload_onpremise_traffic (Offload on-premise traffic)
	if offloadOnpremiseTraffic, exists := settings["offload_onpremise_traffic"]; exists {
		if _, ok := offloadOnpremiseTraffic.(bool); !ok {
			return client.ErrOffloadOnpremiseTrafficNotBoolean
		}
		// Offload on-premise traffic is available for all applications
		logger.Debug("offload_onpremise_traffic parameter validated for app_type=%s", appType)
	}

	return nil
}
