package client

import (
    "fmt"
    "github.com/hashicorp/go-hclog"
)

// handleAuthConditionalRules centralizes auth-specific conditional validations.
// It returns a non-nil error if a validation fails; otherwise nil.
func handleAuthConditionalRules(settingName string, value interface{}, settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
    // Special case: Handle wapp_auth=certonly - only allowed for RDP profile
    if settingName == "wapp_auth" {
        valueStr := fmt.Sprintf("%v", value)
        if valueStr == string(WappAuthTypeCertOnly) && appProfile != string(AppProfileRDP) {
            return fmt.Errorf("setting 'wapp_auth'='certonly' is not allowed for app_profile='%s'. certonly is only allowed for RDP profile", appProfile)
        }
        logger.Debug("wapp_auth validation passed: '%s' for profile '%s'", valueStr, appProfile)
        return nil
    }

    // Special case: Handle app_auth with wapp_auth=certonly and profile=rdp
    if settingName == "app_auth" {
        if wappAuth, hasWappAuth := settings["wapp_auth"]; hasWappAuth {
            wappAuthStr := fmt.Sprintf("%v", wappAuth)
            if wappAuthStr == string(WappAuthTypeCertOnly) && appProfile == string(AppProfileRDP) {
                valueStr := fmt.Sprintf("%v", value)
                allowedValues := []string{string(AppAuthTypeNone), string(AppAuthTypeAuto), string(AppAuthTypeServiceAccount)}
                if !contains(allowedValues, valueStr) {
                    return fmt.Errorf("when wapp_auth='certonly' and profile='rdp', app_auth must be one of %v, got '%s'", allowedValues, valueStr)
                }
                logger.Debug("Special RDP+certonly validation passed for app_auth: '%s' ∈ %v", valueStr, allowedValues)
                return nil
            }
        }
    }

    return nil
}


