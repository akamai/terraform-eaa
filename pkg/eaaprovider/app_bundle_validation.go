package eaaprovider

import (
	"context"
	"fmt"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// validateAppBundle validates app bundle based on app type and profile restrictions
func validateAppBundle(val interface{}, key string) (warns []string, errors []error) {
	// This function validates app_bundle at the schema level
	// However, we need access to app_type and app_profile to do proper validation
	// For now, we'll do basic validation and detailed validation will be done in CustomizeDiff

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

	// Note: Detailed validation based on app_type and app_profile
	// will be handled in the CustomizeDiff function
	return
}

// validateAppBundleRestrictions validates app bundle based on app type and profile restrictions
func validateAppBundleRestrictions(ctx context.Context, d *schema.ResourceDiff, m interface{}, logger hclog.Logger) error {
	logger.Debug("validateAppBundleRestrictions called")

	// Check if app_bundle is provided
	appBundle, ok := d.GetOk("app_bundle")
	if !ok {
		logger.Debug("No app_bundle found, skipping validation")
		return nil
	}

	appBundleStr, ok := appBundle.(string)
	if !ok {
		logger.Debug("app_bundle is not a string, skipping validation")
		return nil
	}

	if appBundleStr == "" {
		logger.Debug("app_bundle is empty, skipping validation")
		return nil
	}

	logger.Debug("app_bundle found: %s, validating restrictions", appBundleStr)

	// Get app_type
	appType, ok := d.GetOk("app_type")
	if !ok {
		logger.Debug("No app_type found, skipping app_bundle validation")
		return nil
	}

	appTypeStr, ok := appType.(string)
	if !ok {
		logger.Debug("app_type is not a string, skipping app_bundle validation")
		return nil
	}

	// Get app_profile
	appProfile, ok := d.GetOk("app_profile")
	if !ok {
		logger.Debug("No app_profile found, skipping app_bundle validation")
		return nil
	}

	appProfileStr, ok := appProfile.(string)
	if !ok {
		logger.Debug("app_profile is not a string, skipping app_bundle validation")
		return nil
	}

	logger.Debug("Validating app_bundle for app_type=%s, app_profile=%s", appTypeStr, appProfileStr)

	// Check app type restrictions - only enterprise apps support app bundles
	if appTypeStr != string(client.ClientAppTypeEnterprise) {
		logger.Error("app_bundle is not supported for app_type '%s'. Only enterprise apps support app bundles", appTypeStr)
		return fmt.Errorf("app_bundle is not supported for app_type '%s'. Only enterprise apps support app bundles", appTypeStr)
	}

	// Check profile restrictions - only specific profiles support app bundles
	validProfiles := []string{
		string(client.AppProfileHTTP),
		string(client.AppProfileSharePoint),
		string(client.AppProfileJira),
		string(client.AppProfileJenkins),
		string(client.AppProfileConfluence),
	}

	isValidProfile := false
	for _, validProfile := range validProfiles {
		if appProfileStr == validProfile {
			isValidProfile = true
			break
		}
	}

	if !isValidProfile {
		logger.Error("app_bundle is not supported for app_profile '%s'. Supported profiles: %v", appProfileStr, validProfiles)
		return fmt.Errorf("app_bundle is not supported for app_profile '%s'. Supported profiles: %v", appProfileStr, validProfiles)
	}

	logger.Debug("app_bundle validation passed for app_type=%s, app_profile=%s", appTypeStr, appProfileStr)
	return nil
}
