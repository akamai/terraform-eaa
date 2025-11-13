package client

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// AuthProtocolType represents the type of authentication protocol
type AuthProtocolType string

const (
	AuthProtocolTypeSAML  AuthProtocolType = "saml"
	AuthProtocolTypeOIDC  AuthProtocolType = "oidc"
	AuthProtocolTypeWSFED AuthProtocolType = "wsfed"
)

// AuthProtocolConfig holds the protocol and appAuth values for a specific authentication type
type AuthProtocolConfig struct {
	ProtocolValues []string // Protocol values to check (e.g., ["SAML", "SAML2.0"])
	AppAuthValues  []string // AppAuth values to check (e.g., ["saml", "SAML2.0"])
	SettingsKey    string   // Schema key for settings (e.g., "saml_settings")
}

// authProtocolConfigs is a map-based registry of authentication protocol configurations
// This makes it easy to add new protocols without creating new functions
var authProtocolConfigs = map[AuthProtocolType]AuthProtocolConfig{
	AuthProtocolTypeSAML: {
		ProtocolValues: []string{ProtocolSAML, ProtocolSAML2},
		AppAuthValues:  SAMLValidValues,
		SettingsKey:    "saml_settings",
	},
	AuthProtocolTypeOIDC: {
		ProtocolValues: []string{ProtocolOIDC, ProtocolOIDCFull},
		AppAuthValues:  OIDCValidValues,
		SettingsKey:    "oidc_settings",
	},
	AuthProtocolTypeWSFED: {
		ProtocolValues: []string{ProtocolWSFed, ProtocolWSFedFull},
		AppAuthValues:  WSFEDValidValues,
		SettingsKey:    "wsfed_settings",
	},
}

// getAuthProtocolConfig returns the AuthProtocolConfig for the specified protocol type
// Returns a zero-value config if the protocol type is not found
func getAuthProtocolConfig(protocolType AuthProtocolType) AuthProtocolConfig {
	if config, ok := authProtocolConfigs[protocolType]; ok {
		return config
	}
	return AuthProtocolConfig{} // Return zero value if not found
}

// shouldEnableAuthForCreate is a generic function that determines if an authentication type should be enabled
// based on app configuration, protocol, appAuth, and settings presence
func shouldEnableAuthForCreate(d *schema.ResourceData, appAuth string, config AuthProtocolConfig) bool {
	appType := ""
	if at, ok := d.GetOk("app_type"); ok {
		if appTypeStr, ok := at.(string); ok {
			appType = appTypeStr
		}
	}

	// Check protocol for SaaS apps
	if appType == string(ClientAppTypeSaaS) {
		if protocol, ok := d.GetOk("protocol"); ok {
			if protocolStr, ok := protocol.(string); ok {
				for _, protocolValue := range config.ProtocolValues {
					if protocolStr == protocolValue {
						return true
					}
				}
			}
		}
		return false
	}

	// Check appAuth values
	for _, appAuthValue := range config.AppAuthValues {
		if appAuth == appAuthValue {
			return true
		}
	}

	// Check if settings exist in schema - defensively check type
	if settings, ok := d.GetOk(config.SettingsKey); ok {
		// Use type switch for more defensive type checking
		switch settingsList := settings.(type) {
		case []interface{}:
			if len(settingsList) > 0 {
				return true
			}
		case []map[string]interface{}:
			if len(settingsList) > 0 {
				return true
			}
		}
	}
	return false
}

// getAppAuthFromAdvancedSettings extracts app_auth from advanced_settings in the schema
// Returns the app_auth value or empty string if not found
func getAppAuthFromAdvancedSettings(d *schema.ResourceData) string {
	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		if advSettingsJSON, ok := advSettingsData.(string); ok && advSettingsJSON != "" {
			advSettings, err := ParseAdvancedSettingsWithDefaults(advSettingsJSON)
			if err == nil && advSettings != nil {
				return advSettings.AppAuth
			}
		}
	}
	return ""
}

// AuthTransformationResult holds the result of authentication transformation
type AuthTransformationResult struct {
	EnableSAML  bool
	EnableOIDC  bool
	EnableWSFED bool
	AppAuth     string // Normalized app_auth value
}

// applyAuthTransformation applies authentication transformation logic
// It determines which auth protocols should be enabled and returns the result
// This centralizes the common pattern of getting app_auth and deciding which auth to enable
func applyAuthTransformation(d *schema.ResourceData) AuthTransformationResult {
	appAuth := getAppAuthFromAdvancedSettings(d)
	enableSAML, enableOIDC, enableWSFED, normalizedAppAuth := decideAuthFromConfig(d, appAuth)

	return AuthTransformationResult{
		EnableSAML:  enableSAML,
		EnableOIDC:  enableOIDC,
		EnableWSFED: enableWSFED,
		AppAuth:     normalizedAppAuth,
	}
}

// decideAuthFromConfig centralizes auth-mode selection from schema and appAuth
// It returns which auth to enable and the normalized appAuth to send (AppAuthNone when an auth flag is used)
func decideAuthFromConfig(d *schema.ResourceData, appAuth string) (enableSAML bool, enableOIDC bool, enableWSFED bool, normalizedAppAuth string) {
	// Check protocols in priority order: SAML > OIDC > WSFED
	protocolOrder := []AuthProtocolType{
		AuthProtocolTypeSAML,
		AuthProtocolTypeOIDC,
		AuthProtocolTypeWSFED,
	}

	for _, protocolType := range protocolOrder {
		config := getAuthProtocolConfig(protocolType)
		if shouldEnableAuthForCreate(d, appAuth, config) {
			switch protocolType {
			case AuthProtocolTypeSAML:
				return true, false, false, string(AppAuthNone)
			case AuthProtocolTypeOIDC:
				// For OIDC, keep app_auth as "oidc" (not "none" like SAML)
				// Normalize OIDC full name to short name if needed
				normalizedOIDC := appAuth
				if appAuth == string(AppAuthOIDCFull) {
					normalizedOIDC = string(AppAuthOIDC)
				}
				return false, true, false, normalizedOIDC
			case AuthProtocolTypeWSFED:
				// For WSFED, set app_auth to "none" (same as SAML)
				return false, false, true, string(AppAuthNone)
			}
		}
	}
	return false, false, false, appAuth
}
