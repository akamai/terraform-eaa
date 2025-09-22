package eaaprovider

import (
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
)

// validateEnterpriseConnectivityParameters validates enterprise connectivity parameters
func validateEnterpriseConnectivityParameters(settings map[string]interface{}, appType, clientAppMode string, logger hclog.Logger) error {

	// Check if any enterprise connectivity parameters are present
	hasEnterpriseConnectivitySettings := false
	enterpriseConnectivityFields := []string{
		"idle_conn_floor", "idle_conn_ceil", "idle_conn_step",
		"idle_close_time_seconds", "app_server_read_timeout", "hsts_age",
	}

	for _, field := range enterpriseConnectivityFields {
		if _, exists := settings[field]; exists {
			hasEnterpriseConnectivitySettings = true
			break
		}
	}

	if !hasEnterpriseConnectivitySettings {
		return nil // No enterprise connectivity settings, skip validation
	}

	// STEP 1: Validate app type and client app mode restrictions
	if appType != "" {
		switch appType {
		case "enterprise":
			// Enterprise apps - check client_app_mode
			if clientAppMode != "" {
				if clientAppMode != "tcp" && clientAppMode != "tunnel" {
					return client.ErrEnterpriseConnectivityNotSupportedForClientMode
				}
			} else {
				logger.Debug("Enterprise connectivity allowed for enterprise app (client_app_mode not specified)")
			}
		case "tunnel":
			// Available for tunnel apps
			logger.Debug("Enterprise connectivity allowed for tunnel app")
		case "saas", "bookmark":
			// Advanced Settings tab hidden for SaaS and Bookmark apps
			return client.ErrEnterpriseConnectivityNotSupportedForSaaS
		default:
			// For any other app types, enterprise connectivity should not be present
			return client.ErrEnterpriseConnectivityNotSupportedForAppType
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		// but we can still validate the enterprise connectivity structure
		logger.Debug("App type not provided, skipping app type validation but continuing with enterprise connectivity structure validation")
		// During schema validation, we'll be more lenient and only validate the structure
		// The app type validation will happen during runtime validation (terraform apply)
	}

	// STEP 2: Validate individual enterprise connectivity parameters

	// Validate idle_conn_floor (minimum idle connections)
	if idleConnFloor, exists := settings["idle_conn_floor"]; exists {
		if err := validateNumericParameter(idleConnFloor, "idle_conn_floor", "connections"); err != nil {
			return err
		}
	}

	// Validate idle_conn_ceil (maximum idle connections)
	if idleConnCeil, exists := settings["idle_conn_ceil"]; exists {
		if err := validateNumericParameter(idleConnCeil, "idle_conn_ceil", "connections"); err != nil {
			return err
		}
	}

	// Validate idle_conn_step (connection step size)
	if idleConnStep, exists := settings["idle_conn_step"]; exists {
		if err := validateNumericParameter(idleConnStep, "idle_conn_step", "connections"); err != nil {
			return err
		}
	}

	// Validate idle_close_time_seconds (idle connection timeout)
	if idleCloseTime, exists := settings["idle_close_time_seconds"]; exists {
		if err := validateNumericParameter(idleCloseTime, "idle_close_time_seconds", "seconds"); err != nil {
			return err
		}

		// Check for maximum threshold (> 1800 seconds = 30 minutes)
		if timeValue, ok := idleCloseTime.(string); ok {
			if timeInt, err := strconv.Atoi(timeValue); err == nil {
				if timeInt > 1800 {
					logger.Warn("idle_close_time_seconds (%d) exceeds maximum allowed threshold of 1800 seconds (30 minutes)", timeInt)
					return client.ErrIdleCloseTimeTooHigh
				}
			}
		}
	}

	// Validate app_server_read_timeout (application server read timeout)
	if appServerReadTimeout, exists := settings["app_server_read_timeout"]; exists {
		if err := validateNumericParameter(appServerReadTimeout, "app_server_read_timeout", "seconds"); err != nil {
			return err
		}

		// Validate minimum value (60 seconds)
		if timeoutValue, ok := appServerReadTimeout.(string); ok {
			if timeoutInt, err := strconv.Atoi(timeoutValue); err == nil {
				if timeoutInt < 60 {
					return client.ErrAppServerReadTimeoutTooLow
				}
			}
		}
	}

	// Validate hsts_age (HTTP Strict Transport Security age)
	if hstsAge, exists := settings["hsts_age"]; exists {
		if err := validateNumericParameter(hstsAge, "hsts_age", "seconds"); err != nil {
			return err
		}
	}

	logger.Debug("Enterprise connectivity parameters validated successfully")
	return nil
}

// validateNumericParameter validates that a parameter is a valid numeric string
func validateNumericParameter(value interface{}, fieldName, unit string) error {
	if value == nil {
		return client.ErrEnterpriseConnectivityFieldNull
	}

	// Convert to string first
	var strValue string
	switch v := value.(type) {
	case string:
		strValue = v
	case int:
		strValue = strconv.Itoa(v)
	case float64:
		strValue = strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return client.ErrEnterpriseConnectivityFieldInvalidType
	}

	// Validate it's a valid number
	if strValue == "" {
		return client.ErrEnterpriseConnectivityFieldEmpty
	}

	if _, err := strconv.Atoi(strValue); err != nil {
		return client.ErrEnterpriseConnectivityFieldInvalidNumber
	}

	return nil
}
