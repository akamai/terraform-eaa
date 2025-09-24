package eaaprovider

import (
	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
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

	// Fetch valid cipher suites from API response
	cipherSuites, err := getValidCipherSuitesFromAPI(m)
	if err != nil {
		// If API call fails, skip TLS validation with a warning
		// This prevents validation from blocking when API is unavailable
		logger.Warn("Failed to fetch TLS cipher suites from API, skipping TLS custom suite validation: %v", err)
		return nil
	}

	// Validate TLS custom suite name
	if err := validateTLSCustomSuiteName(settings, cipherSuites); err != nil {
		return client.ErrTLSCustomSuiteNameValidationFailed
	}

	logger.Debug("TLS custom suite name validation completed")
	return nil
}

// Note: validateTLSCustomSuiteName and getValidCipherSuitesFromAPI functions
// are already defined in resource_eaa_application.go and will be used from there
