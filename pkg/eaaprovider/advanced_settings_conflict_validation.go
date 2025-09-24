package eaaprovider

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
)

// ValidateAdvancedSettingsConflicts validates all field conflict rules
func ValidateAdvancedSettingsConflicts(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating field conflicts")

	// Wapp Auth Field Conflicts
	if err := validateWappAuthFieldConflictsGeneric(settings, logger); err != nil {
		return err
	}

	logger.Debug("Field conflicts validation completed")
	return nil
}

// validateWappAuthFieldConflictsGeneric validates conflicts between wapp_auth and other User-facing authentication mechanism fields
func validateWappAuthFieldConflictsGeneric(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating wapp_auth field conflicts")

	// Get wapp_auth value
	wappAuth, exists := settings["wapp_auth"]
	if !exists {
		logger.Debug("No wapp_auth field found, skipping field conflicts validation")
		return nil // No wapp_auth to validate
	}

	wappAuthStr, ok := wappAuth.(string)
	if !ok {
		logger.Debug("wapp_auth is not a string, skipping field conflicts validation")
		return nil // Invalid wapp_auth type
	}

	// Define User-facing authentication mechanism field groups
	userAuthFieldGroups := map[string][]string{
		"certonly": {
			// Certificate Only fields - typically no specific fields, but could have certificate-related fields
			// For now, we'll focus on preventing other auth mechanism fields
		},
		"basic": {
			// Basic authentication fields - typically no specific fields in advanced_settings
			// Basic auth is handled at resource level
		},
		"basic_cookie": {
			// Basic + Cookie authentication fields - typically no specific fields in advanced_settings
			// Basic + Cookie auth is handled at resource level
		},
		"jwt": {
			// JWT authentication fields
			"jwt_audience", "jwt_grace_period", "jwt_issuers", "jwt_return_option",
			"jwt_return_url", "jwt_username",
		},
	}

	// Define restricted mechanisms for each wapp_auth value
	restrictedMechanisms := map[string][]string{
		"basic":        {"certonly", "basic_cookie", "jwt"},   // Basic: No Certificate Only, Basic + Cookie, JWT fields
		"certonly":     {"basic", "basic_cookie", "jwt"},      // Certificate Only: No Basic, Basic + Cookie, JWT fields
		"basic_cookie": {"basic", "certonly", "jwt"},          // Basic + Cookie: No Basic, Certificate Only, JWT fields
		"jwt":          {"basic", "certonly", "basic_cookie"}, // JWT: No Basic, Certificate Only, Basic + Cookie fields
	}

	// Check if wapp_auth has specific restrictions
	if restrictedMechanismsList, exists := restrictedMechanisms[wappAuthStr]; exists {
		for _, mechanism := range restrictedMechanismsList {
			if fields, exists := userAuthFieldGroups[mechanism]; exists {
				for _, field := range fields {
					if _, fieldExists := settings[field]; fieldExists {
						logger.Warn("Field conflict detected: wapp_auth='%s' conflicts with field '%s'", wappAuthStr, field)
						return fmt.Errorf("field conflict: wapp_auth='%s' conflicts with field '%s'", wappAuthStr, field)
					}
				}
			}
		}
	}

	logger.Debug("Wapp auth field conflicts validation completed")
	return nil
}
