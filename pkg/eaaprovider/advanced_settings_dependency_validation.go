package eaaprovider

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
)

// ValidateAdvancedSettingsDependencies validates all field dependency rules
func ValidateAdvancedSettingsDependencies(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating field dependencies")

	// RDP Dependencies
	if err := validateRDPSpecialDependencies(settings, logger); err != nil {
		return err
	}

	// Tunnel Client Dependencies
	if err := validateTunnelClientSpecialDependencies(settings, logger); err != nil {
		return err
	}

	// JWT Dependencies
	if err := validateJWTSpecialDependencies(settings, logger); err != nil {
		return err
	}

	// Certonly Constraints
	if err := validateCertonlyConstraintsGeneric(settings, logger); err != nil {
		return err
	}

	logger.Debug("Field dependencies validation completed")
	return nil
}

// validateRDPSpecialDependencies validates RDP-specific conditional dependencies
func validateRDPSpecialDependencies(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating RDP special dependencies")

	// Remote Printer Name requires Remote Printing to be enabled
	if _, exists := settings["remote_spark_printer"]; exists {
		if _, mapPrinterExists := settings["remote_spark_mapPrinter"]; !mapPrinterExists {
			logger.Warn("remote_spark_printer is set but remote_spark_mapPrinter is not enabled")
			return fmt.Errorf("remote_spark_printer requires remote_spark_mapPrinter to be enabled")
		}
		logger.Debug("RDP printer dependency validated: remote_spark_printer requires remote_spark_mapPrinter")
	}

	// File Transfer Name requires File Transfer to be enabled
	if _, exists := settings["remote_spark_disk"]; exists {
		if _, mapDiskExists := settings["remote_spark_mapDisk"]; !mapDiskExists {
			logger.Warn("remote_spark_disk is set but remote_spark_mapDisk is not enabled")
			return fmt.Errorf("remote_spark_disk requires remote_spark_mapDisk to be enabled")
		}
		logger.Debug("RDP disk dependency validated: remote_spark_disk requires remote_spark_mapDisk")
	}

	logger.Debug("RDP special dependencies validation completed")
	return nil
}

// validateTunnelClientSpecialDependencies validates tunnel client parameters-specific conditional dependencies
func validateTunnelClientSpecialDependencies(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating tunnel client special dependencies")

	// Domain Exception List requires Wildcard Internal Hostname to be enabled
	if _, exists := settings["domain_exception_list"]; exists {
		wildcardEnabled := false
		if wildcardVal, wildcardExists := settings["wildcard_internal_hostname"]; wildcardExists {
			switch v := wildcardVal.(type) {
			case string:
				wildcardEnabled = (v == "true")
			case bool:
				wildcardEnabled = v
			}
		}

		if !wildcardEnabled {
			logger.Warn("domain_exception_list is set but wildcard_internal_hostname is not enabled")
			return fmt.Errorf("domain_exception_list requires wildcard_internal_hostname to be enabled")
		}
		logger.Debug("Tunnel client dependency validated: domain_exception_list requires wildcard_internal_hostname")
	}

	logger.Debug("Tunnel client special dependencies validation completed")
	return nil
}

// validateJWTSpecialDependencies validates JWT-specific conditional dependencies
func validateJWTSpecialDependencies(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating JWT special dependencies")

	// Check if any JWT fields are present
	jwtFields := []string{"jwt_audience", "jwt_issuers", "jwt_grace_period", "jwt_return_option", "jwt_return_url", "jwt_username"}
	hasJWTFields := false
	for _, field := range jwtFields {
		if _, exists := settings[field]; exists {
			hasJWTFields = true
			break
		}
	}

	if !hasJWTFields {
		logger.Debug("No JWT fields found, skipping JWT dependencies validation")
		return nil
	}

	// JWT fields require wapp_auth to be set to "jwt"
	wappAuthValue, wappAuthExists := settings["wapp_auth"]
	if !wappAuthExists {
		logger.Warn("JWT fields are set but wapp_auth is not specified")
		return fmt.Errorf("JWT fields require wapp_auth to be set to 'jwt'")
	}

	wappAuthStr, ok := wappAuthValue.(string)
	if !ok {
		logger.Warn("JWT fields are set but wapp_auth is not a string")
		return fmt.Errorf("JWT fields require wapp_auth to be set to 'jwt'")
	}

	if wappAuthStr != "jwt" {
		logger.Warn("JWT fields are set but wapp_auth is '%s', not 'jwt'", wappAuthStr)
		return fmt.Errorf("JWT fields require wapp_auth to be set to 'jwt', got '%s'", wappAuthStr)
	}

	logger.Debug("JWT special dependencies validation completed")
	return nil
}

// validateCertonlyConstraintsGeneric validates certonly constraints
func validateCertonlyConstraintsGeneric(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating certonly constraints")

	// Check if wapp_auth is "certonly"
	wappAuth, exists := settings["wapp_auth"]
	if !exists {
		logger.Debug("No wapp_auth found, skipping certonly constraints validation")
		return nil
	}

	wappAuthStr, ok := wappAuth.(string)
	if !ok || wappAuthStr != "certonly" {
		logger.Debug("wapp_auth is not 'certonly', skipping certonly constraints validation")
		return nil
	}

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
				logger.Warn("Invalid app_auth value for certonly: %s", appAuthStr)
				return fmt.Errorf("when wapp_auth = \"certonly\", app_auth can only be one of: %v, got: \"%s\"", validCertonlyAppAuthValues, appAuthStr)
			}
		}
	}

	logger.Debug("Certonly constraints validation completed")
	return nil
}
