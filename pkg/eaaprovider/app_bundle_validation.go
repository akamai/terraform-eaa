package eaaprovider

import (
	"fmt"
)

// validateAppBundle performs schema-level validation on app_bundle, checking that
// the value is a non-empty string. Validation against app_type and app_profile
// constraints is not performed here.
func validateAppBundle(val interface{}, key string) (warns []string, errors []error) {
	value, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", val))
		return
	}

	// Basic validation - non-empty string
	if value == "" {
		errors = append(errors, fmt.Errorf("app_bundle cannot be empty"))
		return
	}

	return
}
