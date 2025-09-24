package eaaprovider

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// ValidateAdvancedSettingsFormats validates all complex format validation rules
func ValidateAdvancedSettingsFormats(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating complex formats")

	// Domain Exception List Format
	if err := validateDomainExceptionListFormat(settings, logger); err != nil {
		return err
	}

	logger.Debug("Complex formats validation completed")
	return nil
}

// validateDomainExceptionListFormat validates the domain exception list format
func validateDomainExceptionListFormat(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("Validating domain exception list format")

	domainExceptionList, exists := settings["domain_exception_list"]
	if !exists {
		logger.Debug("No domain_exception_list found, skipping format validation")
		return nil
	}

	switch v := domainExceptionList.(type) {
	case string:
		// Handle comma-separated string format
		if v == "" {
			logger.Debug("Empty domain exception list is valid")
			return nil // Empty string is valid
		}
		domains := strings.Split(v, ",")
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if err := validateDomainNameWithExceptionGeneric(domain); err != nil {
				logger.Warn("Invalid domain in exception list: %s", domain)
				return fmt.Errorf("invalid domain '%s' in domain_exception_list: %v", domain, err)
			}
		}
	case []interface{}:
		// Handle array format
		for _, domainInterface := range v {
			domain, ok := domainInterface.(string)
			if !ok {
				logger.Warn("Domain must be a string in domain_exception_list")
				return fmt.Errorf("domain in domain_exception_list must be a string, got %T", domainInterface)
			}
			if err := validateDomainNameWithExceptionGeneric(domain); err != nil {
				logger.Warn("Invalid domain in exception list: %s", domain)
				return fmt.Errorf("invalid domain '%s' in domain_exception_list: %v", domain, err)
			}
		}
	default:
		logger.Warn("Invalid type for domain_exception_list: %T", v)
		return fmt.Errorf("domain_exception_list must be a string or array, got %T", v)
	}

	logger.Debug("Domain exception list format validation completed")
	return nil
}

// validateDomainNameWithExceptionGeneric validates individual domain names
func validateDomainNameWithExceptionGeneric(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Basic domain name validation regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain name format")
	}

	return nil
}
