package eaaprovider

import (
	"fmt"

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

// getAppAuthFromSchema extracts app_auth from advanced_settings in the schema
func getAppAuthFromSchema(getter SchemaGetter) string {
	var appAuth string
	if advSettingsData, ok := getter.GetOk("advanced_settings"); ok {
		if advSettingsJSON, ok := advSettingsData.(string); ok && advSettingsJSON != "" {
			advSettings, err := client.ParseAdvancedSettingsWithDefaults(advSettingsJSON)
			if err == nil && advSettings != nil {
				appAuth = advSettings.AppAuth
			}
		}
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
	for _, appAuthValue := range config.AppAuthValues {
		if appAuth == appAuthValue {
			return true
		}
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

// contains checks if a string slice contains a specific value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
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

// shouldEnableSAMLFromDiff determines if SAML should be automatically enabled based on diff data
func shouldEnableSAMLFromDiff(diff *schema.ResourceDiff) bool {
	config := AuthEnableConfig{
		AppAuthValues: []string{string(client.AppAuthSAML), string(client.AppAuthSAML2)},
		SettingsKey:   "saml_settings",
		CheckContent:  false,
	}
	return shouldEnableAuthForSchema(diff, config)
}

// shouldEnableOIDCFromDiff determines if OIDC should be automatically enabled based on diff data
func shouldEnableOIDCFromDiff(diff *schema.ResourceDiff) bool {
	config := AuthEnableConfig{
		AppAuthValues: []string{string(client.AppAuthOIDC), string(client.AppAuthOIDCFull)},
		SettingsKey:   "oidc_settings",
		CheckContent:  true, // OIDC requires content checking
	}
	return shouldEnableAuthForSchema(diff, config)
}

// shouldEnableWSFEDFromDiff determines if WS-Federation should be automatically enabled based on diff data
func shouldEnableWSFEDFromDiff(diff *schema.ResourceDiff) bool {
	config := AuthEnableConfig{
		AppAuthValues: []string{string(client.AppAuthWSFED), string(client.AppAuthWSFEDFull)},
		SettingsKey:   "wsfed_settings",
		CheckContent:  false,
	}
	return shouldEnableAuthForSchema(diff, config)
}

// validateAppAuthBasedOnTypeAndProfile validates app_auth based on app_type and app_profile
func validateAppAuthBasedOnTypeAndProfile(v interface{}, k string) (ws []string, errors []error) {
	value, ok := v.(string)
	if !ok {
		errors = append(errors, client.ErrExpectedString)
		return
	}

	// Basic validation - detailed validation will be done in the resource
	validValues := client.AllAppAuthValidValues

	isValid := false
	for _, validValue := range validValues {
		if value == validValue {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, client.ErrInvalidAppAuthValue)
		return
	}

	return
}

// validateAppAuthForTypeAndProfile validates app_auth based on app_type and app_profile
func validateAppAuthForTypeAndProfile(appAuth, appType, appProfile string) error {
	// First validate the app_auth value itself
	if err := validateAppAuthValue(appAuth); err != nil {
		return err
	}

	// All app types now support app_auth in advanced_settings
	return nil
}

// validateAuthenticationMethodsForAppType validates that authentication method flags are appropriate for the app type
func validateAuthenticationMethodsForAppType(d *schema.ResourceData) error {
	// Get app_type for validation
	appType := ""
	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	// Check if tunnel app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeTunnel) {
		switch {
		case func() bool { saml, ok := d.GetOk("saml"); return ok && saml.(bool) }():
			return fmt.Errorf("saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		case func() bool { oidc, ok := d.GetOk("oidc"); return ok && oidc.(bool) }():
			return fmt.Errorf("oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		case func() bool { wsfed, ok := d.GetOk("wsfed"); return ok && wsfed.(bool) }():
			return fmt.Errorf("wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeBookmark) {
		switch {
		case func() bool { saml, ok := d.GetOk("saml"); return ok && saml.(bool) }():
			return fmt.Errorf("saml=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		case func() bool { oidc, ok := d.GetOk("oidc"); return ok && oidc.(bool) }():
			return fmt.Errorf("oidc=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		case func() bool { wsfed, ok := d.GetOk("wsfed"); return ok && wsfed.(bool) }():
			return fmt.Errorf("wsfed=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}
	}

	return nil
}

// validateAuthenticationMethodsForAppTypeWithDiff validates authentication methods using ResourceDiff
func validateAuthenticationMethodsForAppTypeWithDiff(d *schema.ResourceDiff) error {
	// Get app_type for validation
	appType := ""
	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	// Check if tunnel app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeTunnel) {
		switch {
		case func() bool {
			saml, ok := d.GetOk("saml")
			if !ok {
				return false
			}
			samlBool, ok := saml.(bool)
			return ok && samlBool
		}():
			return client.ErrTunnelAppSAMLNotAllowed
		case func() bool {
			oidc, ok := d.GetOk("oidc")
			if !ok {
				return false
			}
			oidcBool, ok := oidc.(bool)
			return ok && oidcBool
		}():
			return client.ErrTunnelAppOIDCNotAllowed
		case func() bool {
			wsfed, ok := d.GetOk("wsfed")
			if !ok {
				return false
			}
			wsfedBool, ok := wsfed.(bool)
			return ok && wsfedBool
		}():
			return client.ErrTunnelAppWSFEDNotAllowed
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appType == string(client.ClientAppTypeBookmark) {
		switch {
		case func() bool {
			saml, ok := d.GetOk("saml")
			if !ok {
				return false
			}
			samlBool, ok := saml.(bool)
			return ok && samlBool
		}():
			return client.ErrBookmarkAppSAMLNotAllowed
		case func() bool {
			oidc, ok := d.GetOk("oidc")
			if !ok {
				return false
			}
			oidcBool, ok := oidc.(bool)
			return ok && oidcBool
		}():
			return client.ErrBookmarkAppOIDCNotAllowed
		case func() bool {
			wsfed, ok := d.GetOk("wsfed")
			if !ok {
				return false
			}
			wsfedBool, ok := wsfed.(bool)
			return ok && wsfedBool
		}():
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
	if saml, ok := diff.GetOk("saml"); ok && saml.(bool) {
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

// validateAppAuthWithResourceData validates app_auth with access to resource data for SAML/OIDC/WSFED conflicts
func validateAppAuthWithResourceData(appAuth string, d *schema.ResourceData) error {
	// First validate the app_auth value itself
	if err := validateAppAuthValue(appAuth); err != nil {
		return err
	}

	// Get app_type for tunnel app validation
	appType := ""
	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	// Check if tunnel app is trying to use advanced authentication methods
	if appType == string(client.ClientAppTypeTunnel) {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	if appType == string(client.ClientAppTypeBookmark) {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}
	}

	// Check for SAML/OIDC/WSFED conflicts - when enabled, app_auth must match or be "none"
	// EXCEPTION: Allow app_auth to match the enabled method when auto-enabled
	// Process only one auth method at a time (priority: SAML > OIDC > WSFED)
	if appAuth != string(client.AppAuthNone) {
		switch {
		case shouldEnableSAML(d):
			// Validate SAML: app_auth must be a valid SAML value
			if !contains(client.SAMLValidValues, appAuth) {
				return fmt.Errorf("when saml is enabled (saml=true), app_auth must be set to '%s' in advanced_settings, got '%s'", string(client.AppAuthNone), appAuth)
			}
			// Additional validation: SAML conflicts with kerberos, NTLMv1, or NTLMv2
			for _, conflictingValue := range client.SAMLConflictingAppAuthValues {
				if appAuth == conflictingValue {
					return fmt.Errorf("when saml is enabled (saml=true), app_auth cannot be '%s' in advanced_settings. Use '%s' instead", conflictingValue, string(client.AppAuthNone))
				}
			}
		case shouldEnableOIDC(d):
			// Validate OIDC: app_auth must be a valid OIDC value
			if !contains(client.OIDCValidValues, appAuth) {
				return fmt.Errorf("when oidc is enabled (oidc=true), app_auth must be set to '%s' in advanced_settings, got '%s'", string(client.AppAuthNone), appAuth)
			}
		case shouldEnableWSFED(d):
			// Validate WSFED: app_auth must be a valid WSFED value
			if !contains(client.WSFEDValidValues, appAuth) {
				return fmt.Errorf("when wsfed is enabled (wsfed=true), app_auth must be set to '%s' in advanced_settings, got '%s'", string(client.AppAuthNone), appAuth)
			}
		}
	}

	// Get app_profile for additional validation
	appProfile := ""

	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	if ap, ok := d.GetOk("app_profile"); ok {
		appProfile = ap.(string)
	}

	// Apply validation rules based on the requirements
	switch {
	case appType == string(client.ClientAppTypeEnterprise) && appProfile == string(client.AppProfileSSH):
		// app_auth is disabled - field should not be present in advanced_settings
		return client.ErrAppAuthDisabledForEnterpriseSSH

	case appType == string(client.ClientAppTypeSaaS):
		// app_auth should not be present in advanced_settings for SaaS apps
		// Authentication is handled at resource level using boolean flags (saml: true, oidc: true, wsfed: true)
		return client.ErrAppAuthNotAllowedForSaaS

	case appType == string(client.ClientAppTypeBookmark):
		// app_auth should not be present in advanced_settings - it's set at resource level
		return client.ErrAppAuthNotAllowedForBookmark

	case appType == string(client.ClientAppTypeTunnel):
		// app_auth should not be present in advanced_settings - it's set at resource level as "tcp"
		return client.ErrAppAuthNotAllowedForTunnel

	case appType == string(client.ClientAppTypeEnterprise) && appProfile == string(client.AppProfileVNC):
		// app_auth is disabled - field should not be present in advanced_settings
		return client.ErrAppAuthDisabledForEnterpriseVNC
	}

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
