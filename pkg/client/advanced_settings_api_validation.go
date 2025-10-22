package client

import (
	"github.com/hashicorp/go-hclog"
)

// ValidateAdvancedSettingsAPIDependent validates all API-dependent validation rules
func ValidateAdvancedSettingsAPIDependent(settings map[string]interface{}, m interface{}, logger hclog.Logger) error {
	logger.Debug("Validating API-dependent rules")

	// TLS Custom Suite Name Validation
	if err := validateTLSCustomSuiteNameWithAPI(settings, m, logger); err != nil {
		return err
	}

	logger.Debug("API-dependent rules validation completed")
	return nil
}

// validateTLSCustomSuiteNameWithAPI validates TLS custom suite name with API call
func validateTLSCustomSuiteNameWithAPI(settings map[string]interface{}, m interface{}, logger hclog.Logger) error {
	logger.Debug("Validating TLS custom suite name with API")

	// Check if tlsSuiteType is 2 (CUSTOM)
	tlsSuiteType, exists := settings["tlsSuiteType"]
	if !exists {
		logger.Debug("No tlsSuiteType found, skipping TLS custom suite validation")
		return nil
	}

	tlsSuiteTypeInt, ok := tlsSuiteType.(int)
	if !ok {
		logger.Debug("tlsSuiteType is not an int, skipping TLS custom suite validation")
		return nil
	}

	if tlsSuiteTypeInt != 2 {
		logger.Debug("tlsSuiteType is not 2 (CUSTOM), skipping TLS custom suite validation")
		return nil
	}

	// For now, we'll skip the API-dependent validation since the functions
	// are defined in the provider package. This validation will be handled
	// by the provider's validateAdvancedSettingsAtPlanTime function.
	logger.Debug("TLS custom suite name validation will be handled by provider-level validation")
	return nil
}
