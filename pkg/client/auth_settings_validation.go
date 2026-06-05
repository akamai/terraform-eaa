package client

import (
	"context"
	"fmt"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

// ValidateCustomHeadersConfiguration validates custom headers configuration.
func ValidateCustomHeadersConfiguration(ctx context.Context, settings map[string]interface{}, appType string) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}

	// Check if custom headers are present
	if customHeaders, exists := settings["custom_headers"]; exists {
		logging.Debug(ctx, "validating custom headers", tags, map[string]any{"app_type": appType})

		// STEP 1: Validate app type restrictions based on Table 4: Application Types and Custom HTTP Headers Support
		if appType != "" {
			switch appType {
			case string(ClientAppTypeEnterprise):
				// Custom headers are available for Enterprise apps (Advanced Settings)
				logging.Debug(ctx, "custom headers allowed for app type", tags, map[string]any{"app_type": appType})
				logging.Debug(ctx, "continuing with structure validation for enterprise app", tags)
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
			logging.Debug(ctx, "app type not provided, skipping app type validation but continuing with custom headers structure validation", tags)
			// During schema validation, we'll be more lenient and only validate the structure
			// The app type validation will happen during runtime validation (terraform apply)
		}

		logging.Debug(ctx, "app type validation completed, proceeding to structure validation", tags)

		// STEP 2: Sanitize and validate custom headers structure
		logging.Debug(ctx, "about to validate custom headers structure", tags)
		if headersList, ok := customHeaders.([]interface{}); ok {
			logging.Debug(ctx, "custom headers array", tags, map[string]any{"count": len(headersList)})
			// Filter out empty headers (Table 8: Empty Headers validation)
			sanitizedHeaders := []interface{}{}
			for _, header := range headersList {
				headerMap, ok := header.(map[string]interface{})
				if !ok {
					continue
				}

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
					logging.Debug(ctx, "sanitized empty custom header", tags, map[string]any{"header": headerMap})
				}
			}

			logging.Debug(ctx, "sanitized custom headers", tags, map[string]any{"original_count": len(headersList), "sanitized_count": len(sanitizedHeaders)})

			// Validate each non-empty custom header
			for i, header := range sanitizedHeaders {
				headerMap, ok := header.(map[string]interface{})
				if !ok {
					return ErrCustomHeaderNotObject
				}
				if err := validateCustomHeader(ctx, headerMap, i); err != nil {
					return ErrCustomHeaderValidation
				}
			}
		} else {
			return ErrCustomHeadersNotArray
		}
	}

	return nil
}

// validateCustomHeader validates a single custom header object based on Table 2-11 specifications
func validateCustomHeader(ctx context.Context, header map[string]interface{}, index int) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}
	logging.Debug(ctx, "validating custom header", tags, map[string]any{"index": index, "header": header})

	// STEP 1: Sanitize empty headers (Table 8: Empty Headers validation)
	// Remove headers with empty header and attribute_type
	headerValue, hasHeader := header["header"]
	attributeTypeValue, hasAttributeType := header["attribute_type"]

	if hasHeader && hasAttributeType {
		headerStr, headerOk := headerValue.(string)
		attributeTypeStr, attributeTypeOk := attributeTypeValue.(string)

		if headerOk && attributeTypeOk && headerStr == "" && attributeTypeStr == "" {
			logging.Debug(ctx, "skipping empty header", tags, map[string]any{"index": index})
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

			logging.Debug(ctx, "custom header validated", tags, map[string]any{"index": index, "attribute_type": attributeTypeStr, "attribute": attributeStr})
		} else if attributeTypeStr == string(CustomHeaderAttributeTypeUser) || attributeTypeStr == string(CustomHeaderAttributeTypeGroup) || attributeTypeStr == string(CustomHeaderAttributeTypeClientIP) {
			// For user, group, clientip - attribute is not required (dropdown selection)
			logging.Debug(ctx, "custom header validated", tags, map[string]any{"index": index, "attribute_type": attributeTypeStr})
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

	logging.Debug(ctx, "custom header validation passed", tags, map[string]any{"index": index})
	return nil
}

// AuthValidationConfig holds configuration for checking if an auth protocol is enabled
type AuthValidationConfig struct {
	FlagKey       string   // Schema key for the direct flag (e.g., "saml", "oidc", "wsfed")
	SettingsKey   string   // Schema key for settings (e.g., "saml_settings")
	ProtocolName  string   // Name for logging (e.g., "SAML", "OIDC", "WSFED")
	AppAuthValues []string // Valid app_auth values for this protocol (e.g., ["saml", "SAML2.0"])
}

type authSettingsLookup interface {
	GetOk(key string) (interface{}, bool)
}

// isAuthProtocolEnabled checks if an authentication protocol is enabled by checking both
// the direct flag and app_auth in advanced_settings
func isAuthProtocolEnabled(ctx context.Context, d authSettingsLookup, config AuthValidationConfig) bool {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}

	// Check direct flag
	if flag, ok := d.GetOk(config.FlagKey); ok {
		if flagBool, ok := flag.(bool); ok && flagBool {
			logging.Debug(ctx, "auth protocol enabled via direct flag", tags, map[string]any{"protocol": config.ProtocolName, "flag": config.FlagKey})
			return true
		}
	}

	// Check if app_auth matches any of the valid values in advanced_settings
	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		if settingsMap, ok := advSettingsData.(map[string]interface{}); ok {
			if appAuthVal, ok := settingsMap["app_auth"].(string); ok && appAuthVal != "" {
				for _, validValue := range config.AppAuthValues {
					if appAuthVal == validValue {
						logging.Debug(ctx, "auth protocol enabled via app_auth", tags, map[string]any{"protocol": config.ProtocolName, "app_auth": appAuthVal})
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
func getFirstSettingsBlock(ctx context.Context, d authSettingsLookup, settingsKey string) (map[string]interface{}, bool) {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}

	settings, ok := d.GetOk(settingsKey)
	if !ok {
		logging.Debug(ctx, "settings not found", tags, map[string]any{"settings_key": settingsKey})
		return nil, false
	}

	settingsList, ok := settings.([]interface{})
	if !ok || len(settingsList) == 0 {
		logging.Debug(ctx, "settings empty or not a list", tags, map[string]any{"settings_key": settingsKey})
		return nil, false
	}

	// Defensively check type of first element
	firstBlock, ok := settingsList[0].(map[string]interface{})
	if !ok {
		logging.Debug(ctx, "settings first element is not a map", tags, map[string]any{"settings_key": settingsKey})
		return nil, false
	}

	return firstBlock, true
}

// validateIDPSelfSignedCert validates that sign_cert is provided when self_signed = false
// This validation is common to both SAML and WSFED
func validateIDPSelfSignedCert(ctx context.Context, idpBlock map[string]interface{}, protocolName string, signCertError error) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}

	if selfSigned, hasSelfSigned := idpBlock["self_signed"]; hasSelfSigned {
		if selfSignedBool, ok := selfSigned.(bool); ok && !selfSignedBool {
			logging.Debug(ctx, "self_signed = false, checking sign_cert", tags)
			// When self_signed = false, sign_cert is mandatory
			if signCert, hasSignCert := idpBlock["sign_cert"]; !hasSignCert || signCert == "" {
				logging.Debug(ctx, "sign_cert missing or empty", tags, map[string]any{"has_sign_cert": hasSignCert, "sign_cert": signCert})
				return signCertError
			}
		}
	}
	return nil
}

// ValidateWSFEDNestedBlocks validates WSFED nested blocks configuration.
func ValidateWSFEDNestedBlocks(ctx context.Context, d authSettingsLookup, m interface{}) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}
	logging.Debug(ctx, "validateWSFEDNestedBlocks called", tags)

	config := AuthValidationConfig{
		FlagKey:       "wsfed",
		AppAuthValues: WSFEDValidValues,
		SettingsKey:   "wsfed_settings",
		ProtocolName:  "WSFED",
	}

	if !isAuthProtocolEnabled(ctx, d, config) {
		logging.Debug(ctx, "WSFED not enabled, skipping validation", tags)
		return nil
	}

	logging.Debug(ctx, "WSFED is enabled, validating nested blocks", tags)

	wsfedBlock, ok := getFirstSettingsBlock(ctx, d, config.SettingsKey)
	if !ok {
		return nil
	}

	// Check IDP block for self_signed validation
	if idpBlocks, ok := wsfedBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
		if idpBlock, ok := idpBlocks[0].(map[string]interface{}); ok {
			if err := validateIDPSelfSignedCert(ctx, idpBlock, config.ProtocolName, ErrWSFEDSignCertRequired); err != nil {
				return err
			}
		}
	}

	logging.Info(ctx, "WSFED nested blocks validation passed", tags)
	return nil
}

// ValidateSAMLNestedBlocks validates SAML nested blocks configuration.
func ValidateSAMLNestedBlocks(ctx context.Context, d authSettingsLookup, m interface{}) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}
	logging.Debug(ctx, "validateSAMLNestedBlocks called", tags)

	config := AuthValidationConfig{
		FlagKey:       "saml",
		AppAuthValues: SAMLValidValues,
		SettingsKey:   "saml_settings",
		ProtocolName:  "SAML",
	}

	if !isAuthProtocolEnabled(ctx, d, config) {
		logging.Debug(ctx, "SAML not enabled, skipping validation", tags)
		return nil
	}

	logging.Debug(ctx, "SAML is enabled, validating nested blocks", tags)

	samlBlock, ok := getFirstSettingsBlock(ctx, d, config.SettingsKey)
	if !ok {
		return nil
	}

	// Check IDP block for self_signed validation
	if idpBlocks, ok := samlBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
		if idpBlock, ok := idpBlocks[0].(map[string]interface{}); ok {
			if err := validateIDPSelfSignedCert(ctx, idpBlock, config.ProtocolName, ErrSAMLSignCertRequired); err != nil {
				return err
			}
		}
	}

	// Validate attrmap for unique attribute names
	if attrmapBlocks, ok := samlBlock["attrmap"].([]interface{}); ok && len(attrmapBlocks) > 0 {
		logging.Debug(ctx, "validating attrmap for unique attribute names", tags)

		attributeNames := make(map[string]bool)
		for i, attrmapBlock := range attrmapBlocks {
			if attrmapMap, ok := attrmapBlock.(map[string]interface{}); ok {
				if name, hasName := attrmapMap["name"]; hasName {
					if nameStr, ok := name.(string); ok && nameStr != "" {
						if attributeNames[nameStr] {
							logging.Warn(ctx, "duplicate attribute name in attrmap", tags, map[string]any{"name": nameStr, "index": i})
							return fmt.Errorf("duplicate attribute name '%s' found in attrmap. Each attribute name must be unique", nameStr)
						}
						attributeNames[nameStr] = true
						logging.Debug(ctx, "attribute name is unique", tags, map[string]any{"name": nameStr})
					}
				}
			}
		}
		logging.Debug(ctx, "all attribute names in attrmap are unique", tags)
	}

	return nil
}

// ValidateOIDCNestedBlocks validates OIDC nested blocks configuration.
func ValidateOIDCNestedBlocks(ctx context.Context, d authSettingsLookup, m interface{}) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}
	logging.Debug(ctx, "validateOIDCNestedBlocks called", tags)

	config := AuthValidationConfig{
		FlagKey:       "oidc",
		AppAuthValues: OIDCValidValues,
		SettingsKey:   "oidc_settings",
		ProtocolName:  "OIDC",
	}

	if !isAuthProtocolEnabled(ctx, d, config) {
		logging.Debug(ctx, "OIDC not enabled, skipping validation", tags)
		return nil
	}

	logging.Debug(ctx, "OIDC is enabled, validating nested blocks", tags)

	oidcBlock, ok := getFirstSettingsBlock(ctx, d, config.SettingsKey)
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
		logging.Debug(ctx, "oidc_settings block is empty, skipping validation", tags)
		return nil
	}

	// Validate OIDC clients if present
	if oidcClients, ok := oidcBlock["oidc_clients"].([]interface{}); ok && len(oidcClients) > 0 {

		for i, clientData := range oidcClients {
			if clientMap, ok := clientData.(map[string]interface{}); ok {
				if err := validateOIDCClientNested(ctx, clientMap, i); err != nil {
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
func validateOIDCClientNested(ctx context.Context, clientConfig map[string]interface{}, index int) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}
	logging.Debug(ctx, "validating OIDC client", tags, map[string]any{"index": index, "config": clientConfig})

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
					if err := validateOIDCClaimNested(ctx, claimMap, i); err != nil {
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
func validateOIDCClaimNested(ctx context.Context, claim map[string]interface{}, index int) error {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagValidate}
	logging.Debug(ctx, "validating OIDC claim", tags, map[string]any{"index": index, "claim": claim})

	// Only validate that it's a non-empty object
	if len(claim) == 0 {
		return ErrOIDCClaimEmpty
	}

	return nil
}
