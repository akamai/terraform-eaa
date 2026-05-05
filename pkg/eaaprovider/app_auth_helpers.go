package eaaprovider

import (
	"fmt"
	"slices"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// SchemaGetter is an interface for types that can get schema values
type SchemaGetter interface {
	GetOk(key string) (interface{}, bool)
}

// AuthEnableConfig holds configuration for determining if an auth type should be enabled
type AuthEnableConfig struct {
	SettingsKey   string   // Schema key for settings (e.g., "saml_settings")
	AppAuthValues []string // AppAuth values to check (e.g., ["saml", "SAML2.0"])
	CheckContent  bool     // Whether to check for actual content in settings (OIDC-specific)
}

func getSchemaStringValue(getter SchemaGetter, key string) string {
	value, ok := getter.GetOk(key)
	if !ok {
		return ""
	}

	stringValue, ok := value.(string)
	if !ok {
		return ""
	}

	return stringValue
}

func getResourceDataBool(d *schema.ResourceData, key string) bool {
	value, ok := d.GetOk(key)
	if !ok {
		return false
	}

	boolValue, ok := value.(bool)
	return ok && boolValue
}

func getResourceDiffBool(d *schema.ResourceDiff, key string) bool {
	value, ok := d.GetOk(key)
	if !ok {
		return false
	}

	boolValue, ok := value.(bool)
	return ok && boolValue
}

// getAppAuthFromSchema extracts app_auth from the advanced_settings TypeList block in the schema
func getAppAuthFromSchema(getter SchemaGetter) string {
	advSettingsData, ok := getter.GetOk("advanced_settings")
	if !ok {
		return ""
	}
	list, ok := advSettingsData.([]interface{})
	if !ok || len(list) == 0 {
		return ""
	}
	block, ok := list[0].(map[string]interface{})
	if !ok {
		return ""
	}
	appAuth, ok := block["app_auth"].(string)
	if !ok {
		return ""
	}
	return appAuth
}

// hasContentInSettings checks if settings block has actual non-empty content
func hasContentInSettings(settingsList []interface{}) bool {
	if len(settingsList) == 0 {
		return false
	}
	if settingsBlock, ok := settingsList[0].(map[string]interface{}); ok {
		for _, value := range settingsBlock {
			if value != nil {
				switch v := value.(type) {
				case string:
					if v != "" {
						return true
					}
				case int:
					if v != 0 {
						return true
					}
				case bool:
					if v {
						return true
					}
				case []interface{}:
					if len(v) > 0 {
						return true
					}
				default:
					return true
				}
			}
		}
	}
	return false
}

// shouldEnableAuthForSchema is a generic function that determines if an authentication type should be enabled
func shouldEnableAuthForSchema(getter SchemaGetter, config AuthEnableConfig) bool {
	appAuth := getAppAuthFromSchema(getter)

	// Check appAuth values
	if slices.Contains(config.AppAuthValues, appAuth) {
		return true
	}

	// Check if settings exist in schema
	if settings, ok := getter.GetOk(config.SettingsKey); ok {
		if settingsList, ok := settings.([]interface{}); ok && len(settingsList) > 0 {
			if config.CheckContent {
				// For OIDC, check if there's actual content
				return hasContentInSettings(settingsList)
			}
			// For SAML and WSFED, just check if settings exist
			return true
		}
	}

	return false
}

// shouldEnableSAML determines if SAML should be automatically enabled based on app configuration
func shouldEnableSAML(d *schema.ResourceData) bool {
	config := AuthEnableConfig{
		AppAuthValues: []string{string(client.AppAuthSAML), string(client.AppAuthSAML2)},
		SettingsKey:   "saml_settings",
		CheckContent:  false,
	}
	return shouldEnableAuthForSchema(d, config)
}

// shouldEnableOIDC determines if OIDC should be automatically enabled based on app configuration
func shouldEnableOIDC(d *schema.ResourceData) bool {
	config := AuthEnableConfig{
		AppAuthValues: []string{string(client.AppAuthOIDC), string(client.AppAuthOIDCFull)},
		SettingsKey:   "oidc_settings",
		CheckContent:  true, // OIDC requires content checking
	}
	return shouldEnableAuthForSchema(d, config)
}

// shouldEnableWSFED determines if WS-Federation should be automatically enabled based on app configuration
func shouldEnableWSFED(d *schema.ResourceData) bool {
	config := AuthEnableConfig{
		AppAuthValues: []string{string(client.AppAuthWSFED), string(client.AppAuthWSFEDFull)},
		SettingsKey:   "wsfed_settings",
		CheckContent:  false,
	}
	return shouldEnableAuthForSchema(d, config)
}

// validateAuthenticationMethodsForAppType validates that authentication method flags are appropriate for the app type
func validateAuthenticationMethodsForAppType(d *schema.ResourceData) error {
	// Get app_type for validation
	appType := getSchemaStringValue(d, "app_type")

	// Check if tunnel app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeTunnel) {
		switch {
		case getResourceDataBool(d, "saml"):
			return fmt.Errorf("saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		case getResourceDataBool(d, "oidc"):
			return fmt.Errorf("oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		case getResourceDataBool(d, "wsfed"):
			return fmt.Errorf("wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeBookmark) {
		switch {
		case getResourceDataBool(d, "saml"):
			return fmt.Errorf("saml=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		case getResourceDataBool(d, "oidc"):
			return fmt.Errorf("oidc=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		case getResourceDataBool(d, "wsfed"):
			return fmt.Errorf("wsfed=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}
	}

	return nil
}

// validateAuthenticationMethodsForAppTypeWithDiff validates authentication methods using ResourceDiff
func validateAuthenticationMethodsForAppTypeWithDiff(d *schema.ResourceDiff) error {
	// Get app_type for validation
	appType := getSchemaStringValue(d, "app_type")

	// Check if tunnel app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeTunnel) {
		switch {
		case getResourceDiffBool(d, "saml"):
			return client.ErrTunnelAppSAMLNotAllowed
		case getResourceDiffBool(d, "oidc"):
			return client.ErrTunnelAppOIDCNotAllowed
		case getResourceDiffBool(d, "wsfed"):
			return client.ErrTunnelAppWSFEDNotAllowed
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeBookmark) {
		switch {
		case getResourceDiffBool(d, "saml"):
			return client.ErrBookmarkAppSAMLNotAllowed
		case getResourceDiffBool(d, "oidc"):
			return client.ErrBookmarkAppOIDCNotAllowed
		case getResourceDiffBool(d, "wsfed"):
			return client.ErrBookmarkAppWSFEDNotAllowed
		}
	}

	return nil
}

// validateAppAuthConflictsWithResourceLevelAuth validates app_auth conflicts with resource-level auth settings
func validateAppAuthConflictsWithResourceLevelAuth(settings map[string]interface{}, diff *schema.ResourceDiff, logger hclog.Logger) error {
	// Check if app_auth is present in advanced_settings
	appAuth, exists := settings["app_auth"]
	if !exists {
		logger.Debug("No app_auth field found, skipping conflict validation")
		return nil
	}

	appAuthStr, ok := appAuth.(string)
	if !ok {
		logger.Debug("app_auth is not a string, skipping conflict validation")
		return nil
	}

	logger.Debug("Validating app_auth conflicts for value: %s", appAuthStr)

	// Additional validation: specific conflicts with SAML
	if getResourceDiffBool(diff, "saml") {
		// When SAML is enabled, app_auth cannot be kerberos, NTLMv1, or NTLMv2
		for _, conflictingValue := range client.SAMLConflictingAppAuthValues {
			if appAuthStr == conflictingValue {
				return fmt.Errorf("when saml is enabled (saml=true), app_auth cannot be '%s' in advanced_settings. Use '%s' instead", conflictingValue, string(client.AppAuthNone))
			}
		}
	}

	logger.Debug("App auth conflict validation passed")
	return nil
}

// validateAppAuthValue validates app_auth field values
func validateAppAuthValue(appAuth string) error {
	// Valid values for app_auth based on documentation
	validValues := client.AllAppAuthValidValues

	isValid := false
	for _, validValue := range validValues {
		if appAuth == validValue {
			isValid = true
			break
		}
	}

	if !isValid {
		return client.ErrInvalidAppAuthValue
	}

	return nil
}

// validateWappAuthValue validates wapp_auth field values
func validateWappAuthValue(wappAuth string) error {
	// Valid values for wapp_auth based on documentation
	validValues := client.AllWappAuthValidValues

	isValid := false
	for _, validValue := range validValues {
		if wappAuth == validValue {
			isValid = true
			break
		}
	}

	if !isValid {
		return client.ErrInvalidWappAuthValue
	}

	return nil
}
