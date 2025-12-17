package client

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// getMapKeys returns the keys of a map as a slice of strings
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// validateCustomHeadersConfiguration validates custom headers configuration
func ValidateCustomHeadersConfiguration(settings map[string]interface{}, appType string, logger hclog.Logger) error {
	// Check if custom headers are present
	if customHeaders, exists := settings["custom_headers"]; exists {
		logger.Debug("Custom headers found, validating with app_type: %s", appType)

		// STEP 1: Validate app type restrictions based on Table 4: Application Types and Custom HTTP Headers Support
		if appType != "" {
			switch appType {
			case string(ClientAppTypeEnterprise):
				// Custom headers are available for Enterprise apps (Advanced Settings)
				logger.Debug("Custom headers allowed for %s app (Advanced Settings)", appType)
				logger.Debug("Continuing with structure validation for enterprise app")
			case string(ClientAppTypeSaaS), string(ClientAppTypeBookmark):
				// Custom headers are disabled for SaaS and Bookmark apps
				// Since advanced_settings are blocked for these app types, custom headers are not available
				return ErrCustomHeadersNotSupportedForSaaS
			case string(ClientAppTypeTunnel):
				//  Custom headers are disabled for tunnel applications
				return ErrCustomHeadersNotSupportedForTunnel
			default:
				// For any other app types, custom headers should not be present
				return ErrCustomHeadersNotSupportedForAppType
			}
		} else {
			// When appType is empty (schema validation), we cannot validate app type restrictions
			// but we can still validate the custom headers structure
			logger.Debug("App type not provided, skipping app type validation but continuing with custom headers structure validation")
			// During schema validation, we'll be more lenient and only validate the structure
			// The app type validation will happen during runtime validation (terraform apply)
		}

		logger.Debug("App type validation completed, proceeding to structure validation")

		// STEP 2: Sanitize and validate custom headers structure
		logger.Debug("About to validate custom headers structure")
		if headersList, ok := customHeaders.([]interface{}); ok {
			logger.Debug("Custom headers is an array with %d items", len(headersList))
			// Filter out empty headers (Table 8: Empty Headers validation)
			sanitizedHeaders := []interface{}{}
			for _, header := range headersList {
				if headerMap, ok := header.(map[string]interface{}); ok {
					// Check if header is empty (both header and attribute_type are empty)
					headerValue, hasHeader := headerMap["header"]
					attributeTypeValue, hasAttributeType := headerMap["attribute_type"]

					isEmpty := false
					if hasHeader && hasAttributeType {
						if headerStr, headerOk := headerValue.(string); headerOk {
							if attributeTypeStr, attributeTypeOk := attributeTypeValue.(string); attributeTypeOk {
								if headerStr == "" && attributeTypeStr == "" {
									isEmpty = true
								}
							}
						}
					}

					if !isEmpty {
						sanitizedHeaders = append(sanitizedHeaders, header)
					} else {
						logger.Debug("Sanitized empty custom header: %v", headerMap)
					}
				}
			}

			logger.Debug("Sanitized custom headers: %d original -> %d after sanitization", len(headersList), len(sanitizedHeaders))

			// Validate each non-empty custom header
			for i, header := range sanitizedHeaders {
				if headerMap, ok := header.(map[string]interface{}); ok {
					if err := validateCustomHeader(headerMap, i, logger); err != nil {
						return ErrCustomHeaderValidation
					}
				} else {
					return ErrCustomHeaderNotObject
				}
			}
		} else {
			return ErrCustomHeadersNotArray
		}
	}

	return nil
}

// validateCustomHeader validates a single custom header object based on Table 2-11 specifications
func validateCustomHeader(header map[string]interface{}, index int, logger hclog.Logger) error {
	logger.Debug("Validating custom header %d: %v", index, header)

	// STEP 1: Sanitize empty headers (Table 8: Empty Headers validation)
	// Remove headers with empty header and attribute_type
	headerValue, hasHeader := header["header"]
	attributeTypeValue, hasAttributeType := header["attribute_type"]

	if hasHeader && hasAttributeType {
		headerStr, headerOk := headerValue.(string)
		attributeTypeStr, attributeTypeOk := attributeTypeValue.(string)

		if headerOk && attributeTypeOk && headerStr == "" && attributeTypeStr == "" {
			logger.Debug("Skipping empty header %d (both header and attribute_type are empty)", index)
			return nil // Skip validation for empty headers
		}
	}

	// STEP 2: Validate required fields (Table 8: Required Fields validation)
	// Header name is required
	if !hasHeader {
		return ErrCustomHeaderMissingHeader
	}

	headerStr, ok := headerValue.(string)
	if !ok {
		return ErrCustomHeaderHeaderNotString
	}
	if headerStr == "" {
		return ErrCustomHeaderHeaderEmpty
	}

	// STEP 3: Validate attribute_type field (Table 3: Custom Header Attribute Types)
	if hasAttributeType {
		attributeTypeStr, ok := attributeTypeValue.(string)
		if !ok {
			return ErrCustomHeaderAttributeTypeNotString
		}

		// Validate attribute_type enum (Table 9: Custom Header Constants)
		validAttributeTypes := []string{
			string(CustomHeaderAttributeTypeUser),
			string(CustomHeaderAttributeTypeGroup),
			string(CustomHeaderAttributeTypeClientIP),
			string(CustomHeaderAttributeTypeFixed),
			string(CustomHeaderAttributeTypeCustom),
		}
		isValidAttributeType := false
		for _, validType := range validAttributeTypes {
			if attributeTypeStr == validType {
				isValidAttributeType = true
				break
			}
		}
		if !isValidAttributeType && attributeTypeStr != "" {
			return ErrCustomHeaderAttributeTypeInvalid
		}

		// STEP 4: Conditional validation for attribute field (Table 8: Attribute Input validation)
		// Attribute input is required when CUSTOM or FIXED is selected
		if attributeTypeStr == string(CustomHeaderAttributeTypeCustom) || attributeTypeStr == string(CustomHeaderAttributeTypeFixed) {
			attributeValue, hasAttribute := header["attribute"]
			if !hasAttribute {
				return ErrCustomHeaderAttributeRequired
			}

			attributeStr, ok := attributeValue.(string)
			if !ok {
				return ErrCustomHeaderAttributeNotString
			}
			if attributeStr == "" {
				return ErrCustomHeaderAttributeEmpty
			}

			logger.Debug("Custom header %d: validated %s attribute_type with attribute='%s'", index, attributeTypeStr, attributeStr)
		} else if attributeTypeStr == string(CustomHeaderAttributeTypeUser) || attributeTypeStr == string(CustomHeaderAttributeTypeGroup) || attributeTypeStr == string(CustomHeaderAttributeTypeClientIP) {
			// For user, group, clientip - attribute is not required (dropdown selection)
			logger.Debug("Custom header %d: validated %s attribute_type (no attribute input required)", index, attributeTypeStr)
		}
	} else {
		// If attribute_type is not provided, attribute should also not be provided
		if _, hasAttribute := header["attribute"]; hasAttribute {
			return ErrCustomHeaderAttributeNotAllowed
		}
	}

	// STEP 5: Validate attribute field type (if present)
	if attributeValue, hasAttribute := header["attribute"]; hasAttribute {
		if _, ok := attributeValue.(string); !ok {
			return ErrCustomHeaderAttributeNotString
		}
	}

	logger.Debug("Custom header %d validation passed", index)
	return nil
}

// AuthValidationConfig holds configuration for checking if an auth protocol is enabled
type AuthValidationConfig struct {
	FlagKey       string   // Schema key for the direct flag (e.g., "saml", "oidc", "wsfed")
	SettingsKey   string   // Schema key for settings (e.g., "saml_settings")
	ProtocolName  string   // Name for logging (e.g., "SAML", "OIDC", "WSFED")
	AppAuthValues []string // Valid app_auth values for this protocol (e.g., ["saml", "SAML2.0"])
}

// isAuthProtocolEnabled checks if an authentication protocol is enabled by checking both
// the direct flag and app_auth in advanced_settings
func isAuthProtocolEnabled(d *schema.ResourceDiff, config AuthValidationConfig, logger hclog.Logger) bool {
	// Check direct flag
	if flag, ok := d.GetOk(config.FlagKey); ok {
		if flagBool, ok := flag.(bool); ok && flagBool {
			logger.Debug("%s enabled via direct %s=true flag", config.ProtocolName, config.FlagKey)
			return true
		}
	}

	// Check if app_auth matches any of the valid values in advanced_settings
	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		if advSettingsJSON, ok := advSettingsData.(string); ok && advSettingsJSON != "" {
			advSettings, err := ParseAdvancedSettingsWithDefaults(advSettingsJSON)
			if err == nil && advSettings != nil {
				for _, validValue := range config.AppAuthValues {
					if advSettings.AppAuth == validValue {
						logger.Debug("%s enabled via app_auth=%s in advanced_settings", config.ProtocolName, advSettings.AppAuth)
						return true
					}
				}
			}
		}
	}

	return false
}

// getFirstSettingsBlock retrieves the first block from a settings list in the schema
// Returns the block map and true if found, or nil and false if not found
func getFirstSettingsBlock(d *schema.ResourceDiff, settingsKey string, logger hclog.Logger) (map[string]interface{}, bool) {
	settings, ok := d.GetOk(settingsKey)
	if !ok {
		logger.Debug("No %s found", settingsKey)
		return nil, false
	}

	settingsList, ok := settings.([]interface{})
	if !ok || len(settingsList) == 0 {
		logger.Debug("%s is empty or not a list", settingsKey)
		return nil, false
	}

	// Defensively check type of first element
	firstBlock, ok := settingsList[0].(map[string]interface{})
	if !ok {
		logger.Debug("%s[0] is not a map[string]interface{}", settingsKey)
		return nil, false
	}

	return firstBlock, true
}

// validateIDPSelfSignedCert validates that sign_cert is provided when self_signed = false
// This validation is common to both SAML and WSFED
func validateIDPSelfSignedCert(idpBlock map[string]interface{}, protocolName string, signCertError error, logger hclog.Logger) error {
	if selfSigned, hasSelfSigned := idpBlock["self_signed"]; hasSelfSigned {
		if selfSignedBool, ok := selfSigned.(bool); ok && !selfSignedBool {
			logger.Debug("self_signed = false, checking sign_cert")
			// When self_signed = false, sign_cert is mandatory
			if signCert, hasSignCert := idpBlock["sign_cert"]; !hasSignCert || signCert == "" {
				logger.Debug("sign_cert missing or empty: hasSignCert=%v, signCert='%v'", hasSignCert, signCert)
				return signCertError
			}
		}
	}
	return nil
}

// validateWSFEDNestedBlocks validates WSFED nested blocks configuration
func ValidateWSFEDNestedBlocks(ctx context.Context, d *schema.ResourceDiff, m interface{}, logger hclog.Logger) error {
	logger.Debug("validateWSFEDNestedBlocks called")

	config := AuthValidationConfig{
		FlagKey:       "wsfed",
		AppAuthValues: WSFEDValidValues,
		SettingsKey:   "wsfed_settings",
		ProtocolName:  "WSFED",
	}

	if !isAuthProtocolEnabled(d, config, logger) {
		logger.Debug("WSFED not enabled, skipping validation")
		return nil
	}

	logger.Debug("WSFED is enabled, validating nested blocks")

	wsfedBlock, ok := getFirstSettingsBlock(d, config.SettingsKey, logger)
	if !ok {
		return nil
	}

	// Check IDP block for self_signed validation
	if idpBlocks, ok := wsfedBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
		if idpBlock, ok := idpBlocks[0].(map[string]interface{}); ok {
			if err := validateIDPSelfSignedCert(idpBlock, config.ProtocolName, ErrWSFEDSignCertRequired, logger); err != nil {
				return err
			}
		}
	}

	logger.Info("WSFED nested blocks validation passed")
	return nil
}

// validateSAMLNestedBlocks validates SAML nested blocks configuration
func ValidateSAMLNestedBlocks(ctx context.Context, d *schema.ResourceDiff, m interface{}, logger hclog.Logger) error {
	logger.Debug("validateSAMLNestedBlocks called")

	config := AuthValidationConfig{
		FlagKey:       "saml",
		AppAuthValues: SAMLValidValues,
		SettingsKey:   "saml_settings",
		ProtocolName:  "SAML",
	}

	if !isAuthProtocolEnabled(d, config, logger) {
		logger.Debug("SAML not enabled, skipping validation")
		return nil
	}

	logger.Debug("SAML is enabled, validating nested blocks")

	samlBlock, ok := getFirstSettingsBlock(d, config.SettingsKey, logger)
	if !ok {
		return nil
	}

	// Check IDP block for self_signed validation
	if idpBlocks, ok := samlBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
		if idpBlock, ok := idpBlocks[0].(map[string]interface{}); ok {
			if err := validateIDPSelfSignedCert(idpBlock, config.ProtocolName, ErrSAMLSignCertRequired, logger); err != nil {
				return err
			}
		}
	}

	// Validate attrmap for unique attribute names
	if attrmapBlocks, ok := samlBlock["attrmap"].([]interface{}); ok && len(attrmapBlocks) > 0 {
		logger.Debug("Validating attrmap for unique attribute names")

		attributeNames := make(map[string]bool)
		for i, attrmapBlock := range attrmapBlocks {
			if attrmapMap, ok := attrmapBlock.(map[string]interface{}); ok {
				if name, hasName := attrmapMap["name"]; hasName {
					if nameStr, ok := name.(string); ok && nameStr != "" {
						if attributeNames[nameStr] {
							logger.Error("Duplicate attribute name '%s' found in attrmap at index %d", nameStr, i)
							return fmt.Errorf("duplicate attribute name '%s' found in attrmap. Each attribute name must be unique", nameStr)
						}
						attributeNames[nameStr] = true
						logger.Debug("Attribute name '%s' is unique", nameStr)
					}
				}
			}
		}
		logger.Debug("All attribute names in attrmap are unique")
	}

	return nil
}

// validateOIDCNestedBlocks validates OIDC nested blocks configuration
func ValidateOIDCNestedBlocks(ctx context.Context, d *schema.ResourceDiff, m interface{}, logger hclog.Logger) error {
	logger.Debug("validateOIDCNestedBlocks called")

	config := AuthValidationConfig{
		FlagKey:       "oidc",
		AppAuthValues: OIDCValidValues,
		SettingsKey:   "oidc_settings",
		ProtocolName:  "OIDC",
	}

	if !isAuthProtocolEnabled(d, config, logger) {
		logger.Debug("OIDC not enabled, skipping validation")
		return nil
	}

	logger.Debug("OIDC is enabled, validating nested blocks")

	oidcBlock, ok := getFirstSettingsBlock(d, config.SettingsKey, logger)
	if !ok {
		return nil
	}

	// Check if the oidc_settings block has any actual content
	hasContent := false
	for _, value := range oidcBlock {
		if value != nil && value != "" && value != 0 && value != false {
			hasContent = true
			break
		}
	}

	if !hasContent {
		logger.Debug("oidc_settings block is empty, skipping validation")
		return nil
	}

	// Validate OIDC clients if present
	if oidcClients, ok := oidcBlock["oidc_clients"].([]interface{}); ok && len(oidcClients) > 0 {

		for i, clientData := range oidcClients {
			if clientMap, ok := clientData.(map[string]interface{}); ok {
				if err := validateOIDCClientNested(clientMap, i, logger); err != nil {
					return ErrOIDCClientValidation
				}
			} else {
				return ErrOIDCClientNotObject
			}
		}
	}

	return nil
}

// validateOIDCClientNested validates an OIDC client configuration in nested blocks
func validateOIDCClientNested(clientConfig map[string]interface{}, index int, logger hclog.Logger) error {
	logger.Debug("Validating OIDC client %d: %v", index, clientConfig)

	// Validate that response_type is an array if present
	if responseTypes, exists := clientConfig["response_type"]; exists {
		if _, ok := responseTypes.([]interface{}); !ok {
			return ErrOIDCResponseTypeNotArray
		}
	}

	// Validate that redirect_uris is an array if present
	if redirectURIs, exists := clientConfig["redirect_uris"]; exists {
		if _, ok := redirectURIs.([]interface{}); !ok {
			return ErrOIDCRedirectURIsNotArray
		}
	}

	// Validate that javascript_origins is an array if present
	if jsOrigins, exists := clientConfig["javascript_origins"]; exists {
		if _, ok := jsOrigins.([]interface{}); !ok {
			return ErrOIDCJavaScriptOriginsNotArray
		}
	}

	// Validate that post_logout_redirect_uri is an array if present
	if postLogoutURIs, exists := clientConfig["post_logout_redirect_uri"]; exists {
		if _, ok := postLogoutURIs.([]interface{}); !ok {
			return ErrOIDCPostLogoutURIsNotArray
		}
	}

	// Validate claims if present
	if claims, exists := clientConfig["claims"]; exists {
		if claimsList, ok := claims.([]interface{}); ok {
			for i, claim := range claimsList {
				if claimMap, ok := claim.(map[string]interface{}); ok {
					if err := validateOIDCClaimNested(claimMap, i, logger); err != nil {
						return ErrOIDCClaimValidation
					}
				} else {
					return ErrOIDCClaimNotObject
				}
			}
		} else {
			return ErrOIDCClaimsNotArray
		}
	}

	return nil
}

// validateOIDCClaimNested validates an OIDC claim configuration in nested blocks
func validateOIDCClaimNested(claim map[string]interface{}, index int, logger hclog.Logger) error {
	logger.Debug("Validating OIDC claim %d: %v", index, claim)

	// Only validate that it's a non-empty object
	if len(claim) == 0 {
		return ErrOIDCClaimEmpty
	}

	return nil
}
