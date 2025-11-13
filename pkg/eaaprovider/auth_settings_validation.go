package eaaprovider

import (
	"fmt"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
)

// validateSAMLSigningAlgorithm validates SAML signing algorithm values
func validateSAMLSigningAlgorithm(val interface{}, key string) (warns []string, errors []error) {
	algo, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", val))
		return
	}

	validAlgorithms := []string{
		string(client.SAMLSigningAlgorithmSHA1),
		string(client.SAMLSigningAlgorithmSHA256),
	}

	isValid := false
	for _, validAlgo := range validAlgorithms {
		if algo == validAlgo {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, fmt.Errorf("invalid SAML signing algorithm '%s'. Valid values: %v", algo, validAlgorithms))
	}

	return
}

// validateSAMLEncryptionAlgorithm validates SAML encryption algorithm values
func validateSAMLEncryptionAlgorithm(val interface{}, key string) (warns []string, errors []error) {
	algo, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", val))
		return
	}

	validAlgorithms := []string{
		string(client.SAMLEncryptionAlgorithmAES128CBC),
		string(client.SAMLEncryptionAlgorithmAES256CBC),
	}

	isValid := false
	for _, validAlgo := range validAlgorithms {
		if algo == validAlgo {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, fmt.Errorf("invalid SAML encryption algorithm '%s'. Valid values: %v", algo, validAlgorithms))
	}

	return
}

// validateSAMLResponseBinding validates SAML response binding values
func validateSAMLResponseBinding(val interface{}, key string) (warns []string, errors []error) {
	binding, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", val))
		return
	}

	validBindings := []string{
		string(client.SAMLResponseBindingPost),
		string(client.SAMLResponseBindingRedirect),
	}

	isValid := false
	for _, validBinding := range validBindings {
		if binding == validBinding {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, fmt.Errorf("invalid SAML response binding '%s'. Valid values: %v", binding, validBindings))
	}

	return
}

// validateSAMLSubjectFormat validates SAML subject format values
func validateSAMLSubjectFormat(val interface{}, key string) (warns []string, errors []error) {
	format, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", val))
		return
	}

	validFormats := []string{
		string(client.SAMLSubjectFormatEmail),
		string(client.SAMLSubjectFormatPersistent),
		"unspecified",
		string(client.SAMLSubjectFormatTransient),
	}

	isValid := false
	for _, validFormat := range validFormats {
		if format == validFormat {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, fmt.Errorf("invalid SAML subject format '%s'. Valid values: %v", format, validFormats))
	}

	return
}

// validateOIDCClientType validates OIDC client type values
func validateOIDCClientType(val interface{}, key string) (warns []string, errors []error) {
	clientType, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", val))
		return
	}

	validTypes := []string{
		string(client.OIDCClientTypeStandard),
		string(client.OIDCClientTypeConfidential),
		string(client.OIDCClientTypePublic),
	}

	isValid := false
	for _, validType := range validTypes {
		if clientType == validType {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, fmt.Errorf("invalid OIDC client type '%s'. Valid values: %v", clientType, validTypes))
	}

	return
}

// validateOIDCResponseType validates OIDC response type values
func validateOIDCResponseType(val interface{}, key string) (warns []string, errors []error) {
	responseType, ok := val.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", val))
		return
	}

	validTypes := []string{
		string(client.OIDCResponseTypeCode),
		string(client.OIDCResponseTypeIDToken),
		string(client.OIDCResponseTypeToken),
		string(client.OIDCResponseTypeCodeIDToken),
		string(client.OIDCResponseTypeCodeToken),
		string(client.OIDCResponseTypeIDTokenToken),
		string(client.OIDCResponseTypeCodeIDTokenToken),
	}

	isValid := false
	for _, validType := range validTypes {
		if responseType == validType {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, fmt.Errorf("invalid OIDC response type '%s'. Valid values: %v", responseType, validTypes))
	}

	return
}
