package eaaprovider

import (
	"regexp"
	"strconv"
	"strings"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
)

// validateTunnelClientParameters validates EAA Client Parameters that are only available for tunnel apps
func validateTunnelClientParameters(settings map[string]interface{}, appType, clientAppMode string, logger hclog.Logger) error {

	// Define EAA Client Parameters that are only available for tunnel apps
	tunnelClientParameters := []string{
		"domain_exception_list",
		"acceleration",
		"force_ip_route",
		"x_wapp_pool_enabled",
		"x_wapp_pool_size",
		"x_wapp_pool_timeout",
	}

	// Check if any tunnel client parameters are present
	hasTunnelClientParameters := false
	for _, field := range tunnelClientParameters {
		if _, exists := settings[field]; exists {
			hasTunnelClientParameters = true
			break
		}
	}

	if !hasTunnelClientParameters {
		return nil // No tunnel client parameters, skip validation
	}

	// STEP 1: Validate app type and client app mode restrictions
	if appType != "" {
		if appType != "tunnel" {
			return client.ErrTunnelClientParametersNotSupportedForAppType
		}

		if clientAppMode != "" {
			// EAA Client Parameters are only available for tunnel apps with tunnel or ZTP mode
			if clientAppMode != "tunnel" && clientAppMode != "ztp" {
				return client.ErrTunnelClientParametersNotSupportedForClientMode
			}
			logger.Debug("EAA Client Parameters allowed for tunnel app with %s mode", clientAppMode)
		} else {
			logger.Debug("EAA Client Parameters allowed for tunnel app (client_app_mode not specified)")
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		// but we can still validate the tunnel client parameters structure
		logger.Debug("App type not provided, skipping app type validation but continuing with tunnel client parameters structure validation")
		// During schema validation, we'll be more lenient and only validate the structure
		// The app type validation will happen during runtime validation (terraform apply)
	}

	// STEP 2: Validate individual tunnel client parameters

	// Validate domain_exception_list (Tag Input - List of domain exceptions)
	// Note: domain_exception_list is only available when wildcard_internal_hostname = true
	if domainExceptionList, exists := settings["domain_exception_list"]; exists {
		// Check if wildcard_internal_hostname is enabled
		wildcardEnabled := false
		if wildcardVal, wildcardExists := settings["wildcard_internal_hostname"]; wildcardExists {
			switch v := wildcardVal.(type) {
			case string:
				wildcardEnabled = (v == "true")
			case bool:
				wildcardEnabled = v
			}
		}

		if !wildcardEnabled {
			return client.ErrDomainExceptionListRequiresWildcard
		}

		if err := validateDomainExceptionList(domainExceptionList); err != nil {
			return client.ErrDomainExceptionListValidationFailed
		}
	}

	// Validate acceleration (Checkbox - TCP optimization/acceleration)
	if acceleration, exists := settings["acceleration"]; exists {
		if err := validateAcceleration(acceleration); err != nil {
			return client.ErrAccelerationValidationFailed
		}
	}

	// Validate force_ip_route (Checkbox - Override IP route)
	// Note: This parameter requires OVERRIDE_IP_ROUTE feature flag
	if forceIPRoute, exists := settings["force_ip_route"]; exists {
		// Note: In a real implementation, we would check for OVERRIDE_IP_ROUTE feature flag
		// For now, we'll validate the structure but note that this requires the feature flag
		logger.Debug("force_ip_route found - this requires OVERRIDE_IP_ROUTE feature flag")

		if err := validateForceIPRoute(forceIPRoute); err != nil {
			return client.ErrForceIPRouteValidationFailed
		}
	}

	// Validate WebSocket pool parameters (require TUNNEL_REUSE_PER_APP_FEATURE_KEY feature flag)
	// Note: These parameters are only available when the feature flag is enabled
	hasWebSocketPoolParams := false
	webSocketPoolParams := []string{"x_wapp_pool_enabled", "x_wapp_pool_size", "x_wapp_pool_timeout"}
	for _, param := range webSocketPoolParams {
		if _, exists := settings[param]; exists {
			hasWebSocketPoolParams = true
			break
		}
	}

	if hasWebSocketPoolParams {
		// Note: In a real implementation, we would check for TUNNEL_REUSE_PER_APP_FEATURE_KEY feature flag
		// For now, we'll validate the structure but note that these require the feature flag

		// Validate x_wapp_pool_enabled (Dropdown - WebSocket pool enablement)
		if xWappPoolEnabled, exists := settings["x_wapp_pool_enabled"]; exists {
			if err := validateXWappPoolEnabled(xWappPoolEnabled); err != nil {
				return client.ErrXWappPoolEnabledValidationFailed
			}
			logger.Debug("x_wapp_pool_enabled validated")
		}

		// Validate x_wapp_pool_size (Number - WebSocket pool size)
		if xWappPoolSize, exists := settings["x_wapp_pool_size"]; exists {
			if err := validateXWappPoolSize(xWappPoolSize); err != nil {
				return client.ErrXWappPoolSizeValidationFailed
			}
			logger.Debug("x_wapp_pool_size validated")
		}

		// Validate x_wapp_pool_timeout (Number - WebSocket pool timeout)
		if xWappPoolTimeout, exists := settings["x_wapp_pool_timeout"]; exists {
			if err := validateXWappPoolTimeout(xWappPoolTimeout); err != nil {
				return client.ErrXWappPoolTimeoutValidationFailed
			}
			logger.Debug("x_wapp_pool_timeout validated")
		}
	}

	return nil
}

// validateDomainExceptionList validates the domain exception list
func validateDomainExceptionList(domainExceptionList interface{}) error {
	switch v := domainExceptionList.(type) {
	case string:
		// Handle comma-separated string format
		if v == "" {
			return nil // Empty string is valid
		}
		domains := strings.Split(v, ",")
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if err := validateDomainNameWithException(domain); err != nil {
				return client.ErrInvalidDomainInExceptionList
			}
		}
	case []interface{}:
		// Handle array format
		for _, domainInterface := range v {
			domain, ok := domainInterface.(string)
			if !ok {
				return client.ErrDomainMustBeString
			}
			if err := validateDomainNameWithException(domain); err != nil {
				return client.ErrInvalidDomainInExceptionList
			}
		}
	default:
		return client.ErrDomainExceptionListInvalidType
	}
	return nil
}

// validateDomainNameWithException validates individual domain names
func validateDomainNameWithException(domain string) error {
	if domain == "" {
		return client.ErrDomainCannotBeEmpty
	}

	// Basic domain name validation regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return client.ErrInvalidDomainNameFormat
	}

	return nil
}

// validateAcceleration validates the acceleration parameter
func validateAcceleration(acceleration interface{}) error {
	switch v := acceleration.(type) {
	case string:
		if v != "true" && v != "false" {
			return client.ErrAccelerationInvalidValue
		}
	case bool:
		// Boolean values are also acceptable
		return nil
	default:
		return client.ErrAccelerationInvalidType
	}
	return nil
}

// validateForceIPRoute validates the force_ip_route parameter
func validateForceIPRoute(forceIPRoute interface{}) error {
	switch v := forceIPRoute.(type) {
	case string:
		if v != "true" && v != "false" {
			return client.ErrForceIPRouteInvalidValue
		}
	case bool:
		// Boolean values are also acceptable
		return nil
	default:
		return client.ErrForceIPRouteInvalidType
	}
	return nil
}

// validateXWappPoolEnabled validates the x_wapp_pool_enabled parameter
func validateXWappPoolEnabled(xWappPoolEnabled interface{}) error {
	switch v := xWappPoolEnabled.(type) {
	case string:
		validValues := []string{"true", "false", "inherit"}
		for _, validValue := range validValues {
			if v == validValue {
				return nil
			}
		}
		return client.ErrXWappPoolEnabledInvalidValue
	default:
		return client.ErrXWappPoolEnabledInvalidType
	}
}

// validateXWappPoolSize validates the x_wapp_pool_size parameter
func validateXWappPoolSize(xWappPoolSize interface{}) error {
	var size int
	var err error

	switch v := xWappPoolSize.(type) {
	case string:
		if v == "" {
			return client.ErrXWappPoolSizeCannotBeEmpty
		}
		size, err = strconv.Atoi(v)
		if err != nil {
			return client.ErrXWappPoolSizeInvalidNumber
		}
	case float64:
		size = int(v)
	case int:
		size = v
	default:
		return client.ErrXWappPoolSizeInvalidType
	}

	// Validate range: Min: 1, Max: 50
	if size < 1 || size > 50 {
		return client.ErrXWappPoolSizeOutOfRange
	}

	return nil
}

// validateXWappPoolTimeout validates the x_wapp_pool_timeout parameter
func validateXWappPoolTimeout(xWappPoolTimeout interface{}) error {
	var timeout int
	var err error

	switch v := xWappPoolTimeout.(type) {
	case string:
		if v == "" {
			return client.ErrXWappPoolTimeoutCannotBeEmpty
		}
		timeout, err = strconv.Atoi(v)
		if err != nil {
			return client.ErrXWappPoolTimeoutInvalidNumber
		}
	case float64:
		timeout = int(v)
	case int:
		timeout = v
	default:
		return client.ErrXWappPoolTimeoutInvalidType
	}

	// Validate range: Min: 60, Max: 3600 (seconds)
	if timeout < 60 || timeout > 3600 {
		return client.ErrXWappPoolTimeoutOutOfRange
	}

	return nil
}
