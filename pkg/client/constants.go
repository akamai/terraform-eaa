package client

import (
	"errors"
)

const (
	STR_TRUE      = "true"
	STR_FALSE     = "false"
	STATE_ENABLED = 1
)

const (
	MGMT_POP_URL                      = "crux/v1/mgmt-pop"
	APPS_URL                          = "crux/v1/mgmt-pop/apps"
	POPS_URL                          = "crux/v1/mgmt-pop/pops"
	APPIDP_URL                        = "crux/v1/mgmt-pop/appidp"
	APPDIRECTORIES_URL                = "crux/v1/mgmt-pop/appdirectories"
	APPGROUPS_URL                     = "crux/v1/mgmt-pop/appgroups"
	AGENTS_URL                        = "crux/v1/mgmt-pop/agents"
	APP_CATEGORIES_URL                = "crux/v1/mgmt-pop/appcategories"
	IDP_URL                           = "crux/v1/mgmt-pop/idp"
	CERTIFICATES_URL                  = "crux/v1/mgmt-pop/certificates"
	SERVICES_URL                      = "crux/v1/mgmt-pop/services"
	CONNECTOR_POOLS_URL               = "crux/v1/zt/connector-pools"
	CONNECTOR_POOLS_MGMT_URL          = "crux/v1/mgmt-pop/connector-pools"
	APP_ACCESS_GROUPS_URL             = "crux/v1/mgmt-pop/app-access-groups"
	APP_CONNECTOR_POOLS_ASSOCIATE_URL = "crux/v1/mgmt-pop/apps/%s/connector-pools/associate"
	APPS_V3_URL                       = "crux/v3/mgmt-pop/apps"
	REGISTRATION_TOKEN_URL            = "crux/v1/zt/registration-token"
	REGISTRATION_TOKEN_GET_URL        = "crux/v3/mgmt-pop/registrationtokens"
	URL_SCHEME                        = "https"
)

// Token expiration constants
const (
	DEFAULT_TOKEN_EXPIRATION_DAYS = 30 // Default expiration days for registration tokens
)

var (
	ErrInvalidArgument = errors.New("invalid arguments provided")
	ErrMarshaling      = errors.New("marshaling input")
	ErrUnmarshaling    = errors.New("unmarshaling output")

	ErrAppCreate = errors.New("app creation failed")
	ErrAppUpdate = errors.New("app update failed")
	ErrAppDelete = errors.New("app delete failed")

	ErrAssignAgentsFailure    = errors.New("assigning agents to the app failed")
	ErrAssignIdpFailure       = errors.New("assigning IDP to the app failed")
	ErrAssignDirectoryFailure = errors.New("assigning directory to the app failed")
	ErrDeploy                 = errors.New("app deploy failed")
	ErrAssignGroupFailure     = errors.New("assigning groups to the app failed")
	ErrGetApp                 = errors.New("app deploy failed")

	ErrAgentAssociationCreate = errors.New("associating the connector to the connector pool failed")
	ErrAgentAssociationDelete = errors.New("disassociating the connector from the connector pool failed")

	ErrInvalidType  = errors.New("value must be of the specified type")
	ErrInvalidValue = errors.New("invalid value for a key")

	// Application validation errors
	ErrHealthCheckNotSupported         = errors.New("health check configuration is not supported for this app type")
	ErrHealthCheckEnabledMustBeBoolean = errors.New("health check enabled must be a boolean")
	ErrHealthCheckIntervalOutOfRange   = errors.New("health check interval must be between 1 and 300 seconds")
	ErrHealthCheckIntervalMustBeNumber = errors.New("health check interval must be a number")
	ErrHealthCheckMustBeObject         = errors.New("health check must be an object")
	ErrLoadBalancingNotSupported       = errors.New("server load balancing is not supported for this app type")
	ErrCustomHeadersNotSupported       = errors.New("custom headers are not supported for this app type")
	ErrAdvancedSettingsNotAllowed      = errors.New("advanced settings are not allowed for this app type")
	ErrRequiredFieldMissing            = errors.New("required field is missing")
	ErrInvalidAppType                  = errors.New("invalid app type")
	ErrInvalidAppProfile               = errors.New("invalid app profile")

	// RDP configuration validation errors
	ErrRDPNotSupportedForAppType = errors.New("RDP configuration parameters are not supported for this app type. RDP configuration is only available for Enterprise Hosted applications")
	ErrRDPNotSupportedForProfile = errors.New("RDP configuration parameters are not supported for this app profile. RDP configuration is only available for RDP applications")
	ErrRDPInvalidParameterType   = errors.New("RDP parameter must be of the specified type")
	ErrRDPInvalidParameterValue  = errors.New("invalid value for RDP parameter")

	// Health check validation errors
	ErrHealthCheckTypeInvalid            = errors.New("health_check_type must be a string")
	ErrHealthCheckTypeUnsupported        = errors.New("health_check_type must be one of: Default, HTTP, HTTPS, TLS, SSLv3, TCP, None")
	ErrHealthCheckHTTPURLRequired        = errors.New("health_check_http_url is required when health_check_type is HTTP/HTTPS (e.g., '/health')")
	ErrHealthCheckHTTPURLInvalid         = errors.New("health_check_http_url must be a string")
	ErrHealthCheckHTTPURLEmpty           = errors.New("health_check_http_url cannot be empty when health_check_type is HTTP/HTTPS (e.g., '/health')")
	ErrHealthCheckHTTPVersionRequired    = errors.New("health_check_http_version is required when health_check_type is HTTP/HTTPS (e.g., 'HTTP/1.1')")
	ErrHealthCheckHTTPVersionInvalid     = errors.New("health_check_http_version must be a string")
	ErrHealthCheckHTTPVersionEmpty       = errors.New("health_check_http_version cannot be empty when health_check_type is HTTP/HTTPS (e.g., 'HTTP/1.1')")
	ErrHealthCheckHTTPHostHeaderRequired = errors.New("health_check_http_host_header is required when health_check_type is HTTP/HTTPS (e.g., 'myapp.example.com')")
	ErrHealthCheckHTTPHostHeaderNull     = errors.New("health_check_http_host_header cannot be null when health_check_type is HTTP/HTTPS (e.g., 'myapp.example.com')")
	ErrHealthCheckHTTPHostHeaderInvalid  = errors.New("health_check_http_host_header must be a string")
	ErrHealthCheckHTTPFieldNotAllowed    = errors.New("HTTP-specific fields are only allowed for HTTP and HTTPS health check types")
	ErrHealthCheckFieldEmpty             = errors.New("health check field cannot be empty")
	ErrHealthCheckFieldNotNumeric        = errors.New("health check field must be a numeric string")
	ErrHealthCheckFieldNotString         = errors.New("health check field must be a string")

	// Server load balancing validation errors
	ErrLoadBalancingMetricInvalid     = errors.New("load_balancing_metric must be a string")
	ErrLoadBalancingMetricUnsupported = errors.New("load_balancing_metric must be one of: round-robin, ip-hash, least-conn, weighted-rr")
	ErrSessionStickyInvalid           = errors.New("session_sticky must be a boolean")
	ErrCookieAgeRequired              = errors.New("cookie_age must be a number when session_sticky is enabled")
	ErrCookieAgeNotAllowed            = errors.New("cookie_age should only be set when session_sticky is enabled")
	ErrCookieAgeNotSupportedTunnel    = errors.New("cookie_age is not supported for tunnel apps")
	ErrTCPOptimizationInvalid         = errors.New("tcp_optimization must be a boolean")
	ErrTCPOptimizationTunnelOnly      = errors.New("tcp_optimization is only available for tunnel apps")

	// Custom headers validation errors
	ErrCustomHeadersNotArray                = errors.New("custom_headers must be an array")
	ErrCustomHeaderNotObject                = errors.New("custom header must be an object")
	ErrCustomHeaderMissingHeader            = errors.New("custom header missing required field 'header'")
	ErrCustomHeaderHeaderInvalid            = errors.New("custom header header must be a string")
	ErrCustomHeaderHeaderEmpty              = errors.New("custom header header cannot be empty")
	ErrCustomHeaderAttributeTypeInvalid     = errors.New("custom header attribute_type must be a string")
	ErrCustomHeaderAttributeTypeUnsupported = errors.New("custom header attribute_type must be one of: user, group, clientip, fixed, custom")
	ErrCustomHeaderAttributeRequired        = errors.New("custom header attribute is required when attribute_type is fixed/custom")
	ErrCustomHeaderAttributeInvalid         = errors.New("custom header attribute must be a string")
	ErrCustomHeaderAttributeEmpty           = errors.New("custom header attribute cannot be empty when attribute_type is fixed/custom")
	ErrCustomHeaderAttributeNotAllowed      = errors.New("custom header attribute should not be provided when attribute_type is not specified")

	// Miscellaneous validation errors
	ErrSSHFieldNotAvailable        = errors.New("field is only available for SSH applications")
	ErrTunnelFieldNotAvailable     = errors.New("field is not available for tunnel applications")
	ErrCORSUrlRequired             = errors.New("cors_origin_list is required when allow_cors is true")
	ErrOffloadTrafficNotAvailable  = errors.New("offload_onpremise_traffic is not available for this application type")
	ErrTunnelFieldOnly             = errors.New("field is only available for tunnel applications")
	ErrWebSocketNotAvailableForRDP = errors.New("WebSocket fields are not available for RDP applications")

	// Enterprise connectivity validation errors
	ErrEnterpriseConnectivityNotSupportedForClientMode = errors.New("enterprise connectivity parameters are not supported for this app type and client app mode combination")
	ErrEnterpriseConnectivityNotSupportedForSaaS       = errors.New("enterprise connectivity parameters are not supported for SaaS and Bookmark applications")
	ErrEnterpriseConnectivityNotSupportedForAppType    = errors.New("enterprise connectivity parameters are not supported for this app type")
	ErrAppServerReadTimeoutTooLow                      = errors.New("app_server_read_timeout must be at least 60 seconds")
	ErrEnterpriseConnectivityFieldNull                 = errors.New("enterprise connectivity field cannot be null")
	ErrEnterpriseConnectivityFieldInvalidType          = errors.New("enterprise connectivity field must be a string or number")
	ErrEnterpriseConnectivityFieldEmpty                = errors.New("enterprise connectivity field cannot be empty")
	ErrEnterpriseConnectivityFieldInvalidNumber        = errors.New("enterprise connectivity field must be a valid number")
	ErrIdleCloseTimeTooHigh                            = errors.New("idle_close_time_seconds cannot exceed 1800 seconds (30 minutes)")

	// Miscellaneous parameters validation errors
	ErrMiscParametersNotSupportedForClientMode = errors.New("miscellaneous parameters are not supported for this app type and client app mode combination")
	ErrMiscParametersNotSupportedForSaaS       = errors.New("miscellaneous parameters are not supported for SaaS and Bookmark applications")
	ErrMiscParametersNotSupportedForAppType    = errors.New("miscellaneous parameters are not supported for this app type")
	ErrProxyBufferSizeOutOfRange               = errors.New("proxy_buffer_size_kb must be between 4 and 256 KB")
	ErrProxyBufferSizeNotMultipleOf4           = errors.New("proxy_buffer_size_kb must be a multiple of 4")
	ErrProxyBufferSizeInvalidNumber            = errors.New("proxy_buffer_size_kb must be a valid numeric string")
	ErrProxyBufferSizeNotString                = errors.New("proxy_buffer_size_kb must be a string")
	ErrSSHAuditNotBoolean                      = errors.New("ssh_audit_enabled must be a boolean")
	ErrSSHAuditOnlyForSSH                      = errors.New("ssh_audit_enabled is only available for SSH applications")
	ErrAllowCorsNotBoolean                     = errors.New("allow_cors must be a boolean")
	ErrAllowCorsNotAvailableForTunnel          = errors.New("allow_cors is not available for tunnel applications")
	ErrCorsParameterNotString                  = errors.New("CORS parameter must be a string")
	ErrCorsSupportCredentialNotBoolean         = errors.New("cors_support_credential must be a boolean")
	ErrWebSocketEnabledNotBoolean              = errors.New("websocket_enabled must be a boolean")
	ErrHTTPSSSLv3NotBoolean                    = errors.New("https_sslv3 must be a boolean")
	ErrLoggingEnabledNotBoolean                = errors.New("logging_enabled must be a boolean")
	ErrHiddenAppNotBoolean                     = errors.New("hidden_app must be a boolean")
	ErrHiddenAppNotAvailableForTunnel          = errors.New("hidden_app is not available for tunnel applications")
	ErrSaasEnabledNotBoolean                   = errors.New("saas_enabled must be a boolean")
	ErrStickyAgentNotBoolean                   = errors.New("sticky_agent must be a boolean")
	ErrXWappReadTimeoutNotPositive             = errors.New("x_wapp_read_timeout must be a positive number")
	ErrXWappReadTimeoutInvalidNumber           = errors.New("x_wapp_read_timeout must be a valid numeric string")
	ErrXWappReadTimeoutNotString               = errors.New("x_wapp_read_timeout must be a string")
	ErrXWappReadTimeoutOnlyForTunnel           = errors.New("x_wapp_read_timeout is only available for tunnel applications")
	ErrDynamicIpNotBoolean                     = errors.New("dynamic_ip must be a boolean")
	ErrStickyCookiesNotBoolean                 = errors.New("sticky_cookies must be a boolean")
	ErrOffloadOnpremiseTrafficNotBoolean       = errors.New("offload_onpremise_traffic must be a boolean")

	// Related Applications validation errors
	ErrRelatedApplicationsNotSupportedForProfile = errors.New("related applications (app_bundle) are not supported for this app profile")

	// RDP configuration validation errors
	ErrRDPConfigurationNotSupportedForAppType = errors.New("RDP configuration parameters are not supported for this app type")
	ErrRDPConfigurationNotSupportedForProfile = errors.New("RDP configuration parameters are not supported for this app profile")
	ErrRDPInitialProgramNotString             = errors.New("rdp_initial_program must be a string")
	ErrRDPParameterNotString                  = errors.New("RDP parameter must be a string")
	ErrRDPTLS1NotBoolean                      = errors.New("rdp_tls1 must be a boolean")
	ErrRDPParameterNotStringOrBoolean         = errors.New("RDP parameter must be a string or boolean")
	ErrRemoteSparkRecordingNotBoolean         = errors.New("remote_spark_recording must be a boolean")
	ErrRDPPrinterRequiresMapPrinter           = errors.New("remote_spark_printer requires remote_spark_mapPrinter to be enabled")
	ErrRDPDiskRequiresMapDisk                 = errors.New("remote_spark_disk requires remote_spark_mapDisk to be enabled")

	// Resource validation errors
	ErrAdvancedSettingsNotString                       = errors.New("advanced_settings must be a string")
	ErrAdvancedSettingsInvalidJSON                     = errors.New("invalid JSON format in advanced_settings")
	ErrAppTypeRequired                                 = errors.New("app_type is required")
	ErrAppProfileRequired                              = errors.New("app_profile is required")
	ErrAdvancedSettingsNotAllowedForAppType            = errors.New("advanced_settings are not allowed for this app type")
	ErrAdvancedSettingsInvalidJSONFormat               = errors.New("invalid JSON in advanced_settings")
	ErrWappAuthConflictsValidationFailed               = errors.New("wapp_auth field conflicts validation failed")
	ErrTLSSuiteRestrictionsValidationFailed            = errors.New("TLS Suite restrictions validation failed")
	ErrTLSCustomSuiteNameValidationFailed              = errors.New("TLS custom suite name validation failed")
	ErrHealthCheckValidationFailed                     = errors.New("health check validation failed")
	ErrServerLoadBalancingValidationFailed             = errors.New("server load balancing validation failed")
	ErrTunnelClientParametersValidationFailed          = errors.New("tunnel client parameters validation failed")
	ErrTunnelClientParametersNotSupportedForAppType    = errors.New("EAA Client Parameters are not supported for this app type")
	ErrTunnelClientParametersNotSupportedForClientMode = errors.New("EAA Client Parameters are not supported for this client app mode")
	ErrDomainExceptionListRequiresWildcard             = errors.New("domain_exception_list is only available when wildcard_internal_hostname is enabled")
	ErrDomainExceptionListValidationFailed             = errors.New("domain_exception_list validation failed")
	ErrAccelerationValidationFailed                    = errors.New("acceleration validation failed")
	ErrForceIPRouteValidationFailed                    = errors.New("force_ip_route validation failed")
	ErrXWappPoolEnabledValidationFailed                = errors.New("x_wapp_pool_enabled validation failed")
	ErrXWappPoolSizeValidationFailed                   = errors.New("x_wapp_pool_size validation failed")
	ErrXWappPoolTimeoutValidationFailed                = errors.New("x_wapp_pool_timeout validation failed")

	// Tunnel client parameters detailed validation errors
	ErrInvalidDomainInExceptionList   = errors.New("invalid domain in exception list")
	ErrDomainMustBeString             = errors.New("domain must be a string")
	ErrDomainExceptionListInvalidType = errors.New("domain_exception_list must be a string or array")
	ErrDomainCannotBeEmpty            = errors.New("domain cannot be empty")
	ErrInvalidDomainNameFormat        = errors.New("invalid domain name format")
	ErrAccelerationInvalidValue       = errors.New("acceleration must be 'true' or 'false'")
	ErrAccelerationInvalidType        = errors.New("acceleration must be a string or boolean")
	ErrForceIPRouteInvalidValue       = errors.New("force_ip_route must be 'true' or 'false'")
	ErrForceIPRouteInvalidType        = errors.New("force_ip_route must be a string or boolean")
	ErrXWappPoolEnabledInvalidValue   = errors.New("x_wapp_pool_enabled must be one of: 'true', 'false', 'inherit'")
	ErrXWappPoolEnabledInvalidType    = errors.New("x_wapp_pool_enabled must be a string")
	ErrXWappPoolSizeCannotBeEmpty     = errors.New("x_wapp_pool_size cannot be empty")
	ErrXWappPoolSizeInvalidNumber     = errors.New("x_wapp_pool_size must be a valid number")
	ErrXWappPoolSizeInvalidType       = errors.New("x_wapp_pool_size must be a number")
	ErrXWappPoolSizeOutOfRange        = errors.New("x_wapp_pool_size must be between 1 and 50")
	ErrXWappPoolTimeoutCannotBeEmpty  = errors.New("x_wapp_pool_timeout cannot be empty")
	ErrXWappPoolTimeoutInvalidNumber  = errors.New("x_wapp_pool_timeout must be a valid number")
	ErrXWappPoolTimeoutInvalidType    = errors.New("x_wapp_pool_timeout must be a number")
	ErrXWappPoolTimeoutOutOfRange     = errors.New("x_wapp_pool_timeout must be between 60 and 3600 seconds")

	ErrCustomHeadersValidationFailed = errors.New("custom headers validation failed")
	ErrMiscellaneousValidationFailed = errors.New("miscellaneous validation failed")

	// App authentication validation errors
	ErrAppAuthDisabledForEnterpriseSSH = errors.New("app_auth is disabled for enterprise SSH apps")
	ErrAppAuthNotAllowedForSaaS        = errors.New("app_auth should not be present in advanced_settings for SaaS apps")
	ErrAppAuthNotAllowedForBookmark    = errors.New("app_auth should not be present in advanced_settings for bookmark apps")
	ErrAppAuthNotAllowedForTunnel      = errors.New("app_auth should not be present in advanced_settings for tunnel apps")
	ErrAppAuthDisabledForEnterpriseVNC = errors.New("app_auth is disabled for enterprise VNC apps")
	ErrInvalidAppAuthValue             = errors.New("invalid app_auth value")
	ErrInvalidWappAuthValue            = errors.New("invalid wapp_auth value")
	ErrWappAuthFieldConflict           = errors.New("wapp_auth field conflicts with other authentication fields")

	// TLS Suite validation errors
	ErrTLSSuiteNotAvailableForAppType           = errors.New("TLS Suite configuration is not available for this app type")
	ErrTLSSuiteNotAvailableForSMBProfile        = errors.New("TLS Suite configuration is not available for SMB profile")
	ErrTLSSuiteNotAvailableForEnterpriseProfile = errors.New("TLS Suite configuration is not available for this enterprise profile")
	ErrTLSSuiteNameRequired                     = errors.New("tls_suite_name is required for custom TLS Suite")
	ErrTLSSuiteNameNotString                    = errors.New("tls_suite_name must be a string")
	ErrTLSSuiteNameInvalid                      = errors.New("invalid tls_suite_name for custom TLS Suite")

	// App cleanup errors
	ErrAppCleanupIncomplete           = errors.New("app may still exist in EAA and needs manual cleanup")
	ErrGetAppFailed                   = errors.New("failed to get app")
	ErrAuthSettingsVerificationFailed = errors.New("failed to verify authentication settings")

	// Authentication validation errors
	ErrSAMLSettingEmpty               = errors.New("SAML setting must have at least one field")
	ErrSAMLSPNotObject                = errors.New("SAML SP must be an object")
	ErrSAMLSPEmpty                    = errors.New("SAML SP object cannot be empty")
	ErrSAMLIDPNotObject               = errors.New("SAML IDP must be an object")
	ErrSAMLIDPEmpty                   = errors.New("SAML IDP object cannot be empty")
	ErrSAMLSubjectNotObject           = errors.New("SAML Subject must be an object")
	ErrSAMLSubjectEmpty               = errors.New("SAML Subject object cannot be empty")
	ErrSAMLSignCertRequired           = errors.New("SAML sign_cert is required when self_signed = false")
	ErrSAMLAttrMapNotArray            = errors.New("SAML AttrMap must be an array")
	ErrWSFEDSettingEmpty              = errors.New("WS-Federation setting must have at least one field")
	ErrWSFEDSPNotObject               = errors.New("WS-Federation SP must be an object")
	ErrWSFEDSPEmpty                   = errors.New("WS-Federation SP object cannot be empty")
	ErrWSFEDIDPNotObject              = errors.New("WS-Federation IDP must be an object")
	ErrWSFEDIDPEmpty                  = errors.New("WS-Federation IDP object cannot be empty")
	ErrWSFEDSubjectNotObject          = errors.New("WS-Federation Subject must be an object")
	ErrWSFEDSubjectEmpty              = errors.New("WS-Federation Subject object cannot be empty")
	ErrWSFEDSignCertRequired          = errors.New("WS-Federation sign_cert is required when self_signed = false")
	ErrWSFEDAttrMapNotArray           = errors.New("WS-Federation AttrMap must be an array")
	ErrWSFEDSettingValidation         = errors.New("WS-Federation setting validation failed")
	ErrOIDCClientNotObject            = errors.New("OIDC client must be an object")
	ErrOIDCClientEmpty                = errors.New("OIDC client cannot be empty")
	ErrOIDCClientValidation           = errors.New("OIDC client validation failed")
	ErrOIDCClientsNotArray            = errors.New("oidc_clients must be an array")
	ErrOIDCResponseTypeNotArray       = errors.New("response_type must be an array")
	ErrOIDCRedirectURIsNotArray       = errors.New("redirect_uris must be an array")
	ErrOIDCJavaScriptOriginsNotArray  = errors.New("javascript_origins must be an array")
	ErrOIDCPostLogoutRedirectNotArray = errors.New("post_logout_redirect_uri must be an array")
	ErrOIDCPostLogoutURIsNotArray     = errors.New("post_logout_redirect_uri must be an array")
	ErrOIDCClaimsNotArray             = errors.New("claims must be an array")
	ErrOIDCClaimNotObject             = errors.New("OIDC claim must be an object")
	ErrOIDCClaimEmpty                 = errors.New("OIDC claim cannot be empty")
	ErrOIDCClaimValidation            = errors.New("OIDC claim validation failed")

	// General validation errors
	ErrInvalidJSONFormat    = errors.New("invalid JSON format")
	ErrExpectedString       = errors.New("expected string, got different type")
	ErrMissingRequiredField = errors.New("missing required field")

	// Tunnel app authentication validation errors
	ErrTunnelAppSAMLNotAllowed  = errors.New("saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
	ErrTunnelAppOIDCNotAllowed  = errors.New("oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
	ErrTunnelAppWSFEDNotAllowed = errors.New("wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication")

	// Bookmark app authentication validation errors
	ErrBookmarkAppSAMLNotAllowed  = errors.New("saml=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
	ErrBookmarkAppOIDCNotAllowed  = errors.New("oidc=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
	ErrBookmarkAppWSFEDNotAllowed = errors.New("wsfed=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
)

type Domain string

const (
	AppDomainCustom Domain = "custom"
	AppDomainWapp   Domain = "wapp"
)

func (d Domain) ToInt() (int, error) {
	switch d {
	case AppDomainCustom:
		return int(APP_DOMAIN_CUSTOM), nil
	case AppDomainWapp:
		return int(APP_DOMAIN_WAPP), nil
	default:
		return 0, errors.New("unknown domain value")
	}
}

type DomainInt int

const (
	APP_DOMAIN_CUSTOM DomainInt = 1 + iota
	APP_DOMAIN_WAPP
)

func (cam DomainInt) String() (string, error) {
	switch cam {
	case APP_DOMAIN_CUSTOM:
		return string(AppDomainCustom), nil
	case APP_DOMAIN_WAPP:
		return string(AppDomainWapp), nil
	default:
		return "", errors.New("unknown domain value")
	}
}

type AppProfile string

const (
	AppProfileHTTP       AppProfile = "http"
	AppProfileSharePoint AppProfile = "sharepoint"
	AppProfileJira       AppProfile = "jira"
	AppProfileRDP        AppProfile = "rdp"
	AppProfileVNC        AppProfile = "vnc"
	AppProfileSSH        AppProfile = "ssh"
	AppProfileJenkins    AppProfile = "jenkins"
	AppProfileConfluence AppProfile = "confluence"
	AppProfileTCP        AppProfile = "tcp"
	AppProfileSMB        AppProfile = "smb"
)

func (ap AppProfile) ToInt() (int, error) {
	switch ap {
	case AppProfileHTTP:
		return int(APP_PROFILE_HTTP), nil
	case AppProfileSharePoint:
		return int(APP_PROFILE_SHAREPOINT), nil
	case AppProfileJira:
		return int(APP_PROFILE_JIRA), nil
	case AppProfileRDP:
		return int(APP_PROFILE_RDP), nil
	case AppProfileVNC:
		return int(APP_PROFILE_VNC), nil
	case AppProfileSSH:
		return int(APP_PROFILE_SSH), nil
	case AppProfileJenkins:
		return int(APP_PROFILE_JENKINS), nil
	case AppProfileConfluence:
		return int(APP_PROFILE_CONFLUENCE), nil
	case AppProfileTCP:
		return int(APP_PROFILE_TCP), nil
	case AppProfileSMB:
		return int(APP_PROFILE_SMB), nil
	default:
		return 0, errors.New("unknown App_Profile value")
	}
}

type AppProfileInt int

const (
	APP_PROFILE_HTTP AppProfileInt = 1 + iota
	APP_PROFILE_SHAREPOINT
	APP_PROFILE_JIRA
	APP_PROFILE_RDP
	APP_PROFILE_VNC
	APP_PROFILE_SSH
	APP_PROFILE_JENKINS
	APP_PROFILE_CONFLUENCE
	APP_PROFILE_TCP
	APP_PROFILE_SMB
)

func (cam AppProfileInt) String() (string, error) {
	switch cam {
	case APP_PROFILE_HTTP:
		return string(AppProfileHTTP), nil
	case APP_PROFILE_SHAREPOINT:
		return string(AppProfileSharePoint), nil
	case APP_PROFILE_JIRA:
		return string(AppProfileJira), nil
	case APP_PROFILE_RDP:
		return string(AppProfileRDP), nil
	case APP_PROFILE_VNC:
		return string(AppProfileVNC), nil
	case APP_PROFILE_SSH:
		return string(AppProfileSSH), nil
	case APP_PROFILE_JENKINS:
		return string(AppProfileJenkins), nil
	case APP_PROFILE_CONFLUENCE:
		return string(AppProfileConfluence), nil
	case APP_PROFILE_TCP:
		return string(AppProfileTCP), nil
	case APP_PROFILE_SMB:
		return string(AppProfileSMB), nil
	default:
		return "", errors.New("unknown app_profile value")
	}
}

type ClientAppMode string

const (
	ClientAppModeTCP    ClientAppMode = "tcp"
	ClientAppModeTunnel ClientAppMode = "tunnel"
)

func (cam ClientAppMode) ToInt() (int, error) {
	switch cam {
	case ClientAppModeTCP:
		return int(CLIENT_APP_MODE_TCP), nil
	case ClientAppModeTunnel:
		return int(CLIENT_APP_MODE_TUNNEL), nil
	default:
		return 0, errors.New("unknown ClientAppMode value")
	}
}

type ClientAppModeInt int

const (
	CLIENT_APP_MODE_TCP ClientAppModeInt = 1 + iota
	CLIENT_APP_MODE_TUNNEL
)

func (cam ClientAppModeInt) String() (string, error) {
	switch cam {
	case CLIENT_APP_MODE_TCP:
		return string(ClientAppModeTCP), nil
	case CLIENT_APP_MODE_TUNNEL:
		return string(ClientAppModeTunnel), nil
	default:
		return "", errors.New("unknown ClientAppMode value")
	}
}

type ClientAppType string

const (
	ClientAppTypeEnterprise ClientAppType = "enterprise"
	ClientAppTypeSaaS       ClientAppType = "saas"
	ClientAppTypeBookmark   ClientAppType = "bookmark"
	ClientAppTypeTunnel     ClientAppType = "tunnel"
)

func (cat ClientAppType) ToInt() (int, error) {
	switch cat {
	case ClientAppTypeEnterprise:
		return int(APP_TYPE_ENTERPRISE_HOSTED), nil
	case ClientAppTypeSaaS:
		return int(APP_TYPE_SAAS), nil
	case ClientAppTypeBookmark:
		return int(APP_TYPE_BOOKMARK), nil
	case ClientAppTypeTunnel:
		return int(APP_TYPE_TUNNEL), nil
	default:
		return 0, errors.New("unknown ClientAppType value")
	}
}

type ClientAppTypeInt int

const (
	APP_TYPE_ENTERPRISE_HOSTED ClientAppTypeInt = 1 + iota
	APP_TYPE_SAAS
	APP_TYPE_BOOKMARK
	APP_TYPE_TUNNEL
)

func (cat ClientAppTypeInt) String() (string, error) {
	switch cat {
	case APP_TYPE_ENTERPRISE_HOSTED:
		return string(ClientAppTypeEnterprise), nil
	case APP_TYPE_SAAS:
		return string(ClientAppTypeSaaS), nil
	case APP_TYPE_BOOKMARK:
		return string(ClientAppTypeBookmark), nil
	case APP_TYPE_TUNNEL:
		return string(ClientAppTypeTunnel), nil
	default:
		return "", errors.New("unknown ClientAppType value")
	}
}

type CertType string

const (
	CertSelfSigned CertType = "self_signed"
	CertUploaded   CertType = "uploaded"
)
const (
	CERT_TYPE_APP = 1 + iota
	CERT_TYPE_AGENT
	CERT_TYPE_INTERNAL
	CERT_TYPE_USER
	CERT_TYPE_APP_SSC
	CERT_TYPE_CA
)

const (
	ACCESS_RULE_SETTING_BROWSER               = "browser"
	ACCESS_RULE_SETTING_URL                   = "url"
	ACCESS_RULE_SETTING_GROUP                 = "group"
	ACCESS_RULE_SETTING_USER                  = "user"
	ACCESS_RULE_SETTING_CLIENTIP              = "clientip"
	ACCESS_RULE_SETTING_OS                    = "os"
	ACCESS_RULE_SETTING_DEVICE                = "device"
	ACCESS_RULE_SETTING_COUNTRY               = "country"
	ACCESS_RULE_SETTING_TIME                  = "time"
	ACCESS_RULE_SETTING_METHOD                = "method"
	ACCESS_RULE_SETTING_EAACLIENT_APPHOST     = "EAAClientAppHost"
	ACCESS_RULE_SETTING_EAACLIENT_APPPORT     = "EAAClientAppPort"
	ACCESS_RULE_SETTING_EAACLIENT_APPPROTOCOL = "EAAClientAppProtocol"
	ACCESS_RULE_SETTING_DEVICE_POSTURE        = "DevicePostureRiskAssessment"
	ACCESS_RULE_SETTING_DEVICE_TIER           = "device_risk_tier"
	ACCESS_RULE_SETTING_DEVICE_TAG            = "device_risk_tag"
)

type ServiceTypeInt int

const (
	SERVICE_TYPE_WAF = 1 + iota
	SERVICE_TYPE_ACCELERATION
	SERVICE_TYPE_AV
	SERVICE_TYPE_IPS
	SERVICE_TYPE_SLB
	SERVICE_TYPE_ACCESS_CTRL
	SERVICE_TYPE_REWRITE
)

type ServiceType string

const (
	ServiceTypeWAF          ServiceType = "waf"
	ServiceTypeAcceleration ServiceType = "acceleration"
	ServiceTypeAV           ServiceType = "av"
	ServiceTypeIPS          ServiceType = "ips"
	ServiceTypeSLB          ServiceType = "slb"
	ServiceTypeAccessCtrl   ServiceType = "access"
	ServiceTypeRewrite      ServiceType = "rewrite"
)

func (s ServiceType) ToInt() (int, error) {
	switch s {
	case ServiceTypeWAF:
		return int(SERVICE_TYPE_WAF), nil
	case ServiceTypeAcceleration:
		return int(SERVICE_TYPE_ACCELERATION), nil
	case ServiceTypeAV:
		return int(SERVICE_TYPE_AV), nil
	case ServiceTypeIPS:
		return int(SERVICE_TYPE_IPS), nil
	case ServiceTypeSLB:
		return int(SERVICE_TYPE_SLB), nil
	case ServiceTypeAccessCtrl:
		return int(SERVICE_TYPE_ACCESS_CTRL), nil
	case ServiceTypeRewrite:
		return int(SERVICE_TYPE_REWRITE), nil
	default:
		return 0, errors.New("unknown service type value")
	}
}

type RuleTypeInt int

const (
	RULE_TYPE_ACCESS_CTRL = 1 + iota
	RULE_TYPE_CONTENT_REWRITE
	RULE_TYPE_POST_REWRITE
	RULE_TYPE_QUERY_REWRITE
	RULE_TYPE_COOKIE_REWRITE
	RULE_TYPE_LOCATION_REWRITE
	RULE_TYPE_GROUP_BASED_REWRITE
)

const (
	ADMIN_STATE_ENABLED  = 1
	ADMIN_STATE_DISABLED = 0
	RULE_ACTION_DENY     = 1
	OPERATOR_IS          = "=="
	OPERATOR_IS_NOT      = "!="
	RULE_ON              = "on"
	RULE_OFF             = "off"
)

type ConnPackageType string

const (
	ConnPackageTypeVmware     ConnPackageType = "vmware"
	ConnPackageTypeVbox       ConnPackageType = "vbox"
	ConnPackageTypeAWS        ConnPackageType = "aws"
	ConnPackageTypeKVM        ConnPackageType = "kvm"
	ConnPackageTypeHyperv     ConnPackageType = "hyperv"
	ConnPackageTypeDocker     ConnPackageType = "docker"
	ConnPackageTypeAWSClassic ConnPackageType = "aws_classic"
	ConnPackageTypeAzure      ConnPackageType = "azure"
	ConnPackageTypeGoogle     ConnPackageType = "google"
	ConnPackageTypeSoftLayer  ConnPackageType = "softlayer"
	ConnPackageTypeFujitsu_k5 ConnPackageType = "fujitsu_k5"
)

func (cat ConnPackageType) ToInt() (int, error) {
	switch cat {
	case ConnPackageTypeVmware:
		return int(AGENT_PACKAGE_VMWARE), nil
	case ConnPackageTypeVbox:
		return int(AGENT_PACKAGE_VBOX), nil
	case ConnPackageTypeAWS:
		return int(AGENT_PACKAGE_AWS), nil
	case ConnPackageTypeKVM:
		return int(AGENT_PACKAGE_KVM), nil
	case ConnPackageTypeHyperv:
		return int(AGENT_PACKAGE_HYPERV), nil
	case ConnPackageTypeDocker:
		return int(AGENT_PACKAGE_DOCKER), nil
	case ConnPackageTypeAWSClassic:
		return int(AGENT_PACKAGE_AWS_CLASSIC), nil
	case ConnPackageTypeAzure:
		return int(AGENT_PACKAGE_AZURE), nil
	case ConnPackageTypeGoogle:
		return int(AGENT_PACKAGE_GOOGLE), nil
	case ConnPackageTypeSoftLayer:
		return int(AGENT_PACKAGE_SOFTLAYER), nil
	case ConnPackageTypeFujitsu_k5:
		return int(AGENT_PACKAGE_FUJITSU_K5), nil
	default:
		return 0, errors.New("unknown connector package value")
	}
}

type ConnPackageTypeInt int

const (
	AGENT_PACKAGE_VMWARE ConnPackageTypeInt = 1 + iota
	AGENT_PACKAGE_VBOX
	AGENT_PACKAGE_AWS
	AGENT_PACKAGE_KVM
	AGENT_PACKAGE_HYPERV
	AGENT_PACKAGE_DOCKER
	AGENT_PACKAGE_AWS_CLASSIC
	AGENT_PACKAGE_AZURE
	AGENT_PACKAGE_GOOGLE
	AGENT_PACKAGE_SOFTLAYER
	AGENT_PACKAGE_FUJITSU_K5
)

func (cat ConnPackageTypeInt) String() (string, error) {
	switch cat {
	case AGENT_PACKAGE_VMWARE:
		return string(ConnPackageTypeVmware), nil
	case AGENT_PACKAGE_VBOX:
		return string(ConnPackageTypeVbox), nil
	case AGENT_PACKAGE_AWS:
		return string(ConnPackageTypeAWS), nil
	case AGENT_PACKAGE_KVM:
		return string(ConnPackageTypeKVM), nil
	case AGENT_PACKAGE_HYPERV:
		return string(ConnPackageTypeHyperv), nil
	case AGENT_PACKAGE_DOCKER:
		return string(ConnPackageTypeDocker), nil
	case AGENT_PACKAGE_AWS_CLASSIC:
		return string(ConnPackageTypeAWSClassic), nil
	case AGENT_PACKAGE_AZURE:
		return string(ConnPackageTypeAzure), nil
	case AGENT_PACKAGE_GOOGLE:
		return string(ConnPackageTypeGoogle), nil
	case AGENT_PACKAGE_SOFTLAYER:
		return string(ConnPackageTypeSoftLayer), nil
	case AGENT_PACKAGE_FUJITSU_K5:
		return string(ConnPackageTypeFujitsu_k5), nil
	default:
		return "", errors.New("unknown connector package value")
	}
}

type ConnPackageState string

const (
	ConnPackageStateNotCreated    ConnPackageState = "not_created "
	ConnPackageStateCreated       ConnPackageState = "created"
	ConnPackageStateNotInstalled  ConnPackageState = "not_installed"
	ConnPackageStateNotVerified   ConnPackageState = "not_verified"
	ConnPackageStateVerified      ConnPackageState = "verified"
	ConnPackageStateUnenrolled    ConnPackageState = "unenrolled"
	ConnPackageStateEnrolled      ConnPackageState = "enrolled"
	ConnPackageStateNotConfigured ConnPackageState = "not_configured"
	ConnPackageStateConfigured    ConnPackageState = "configured"
)

type ConnPackageStateInt int

const (
	AGENT_STATE_NOT_CREATED = 0 + iota
	AGENT_STATE_CREATED
	AGENT_STATE_NOT_INSTALLED
	AGENT_STATE_NOT_VERIFIED
	AGENT_STATE_VERIFIED
	AGENT_STATE_UNENROLLED
	AGENT_STATE_ENROLLED
	AGENT_STATE_NOT_CONFIGURED
	AGENT_STATE_CONFIGURED
)

func (cat ConnPackageStateInt) String() (string, error) {
	switch cat {
	case AGENT_STATE_NOT_CREATED:
		return string(ConnPackageStateNotCreated), nil
	case AGENT_STATE_CREATED:
		return string(ConnPackageStateCreated), nil
	case AGENT_STATE_NOT_INSTALLED:
		return string(ConnPackageStateNotInstalled), nil
	case AGENT_STATE_NOT_VERIFIED:
		return string(ConnPackageStateNotVerified), nil
	case AGENT_STATE_VERIFIED:
		return string(ConnPackageStateVerified), nil
	case AGENT_STATE_UNENROLLED:
		return string(ConnPackageStateUnenrolled), nil
	case AGENT_STATE_NOT_CONFIGURED:
		return string(ConnPackageStateNotConfigured), nil
	case AGENT_STATE_CONFIGURED:
		return string(ConnPackageStateConfigured), nil
	default:
		return "", errors.New("unknown connector state value")
	}
}

type HealthCheckType string

const (
	HealthCheckTypeDefault HealthCheckType = "Default"
	HealthCheckTypeHTTP    HealthCheckType = "HTTP"
	HealthCheckTypeHTTPS   HealthCheckType = "HTTPS"
	HealthCheckTypeTLS     HealthCheckType = "TLS"
	HealthCheckTypeSSLv3   HealthCheckType = "SSLv3"
	HealthCheckTypeTCP     HealthCheckType = "TCP"
	HealthCheckTypeNone    HealthCheckType = "None"
)

type AppAuthType string

const (
	AppAuthNone           AppAuthType = "none"
	AppAuthKerberos       AppAuthType = "kerberos"
	AppAuthBasic          AppAuthType = "basic"
	AppAuthNTLMv1         AppAuthType = "NTLMv1"
	AppAuthNTLMv2         AppAuthType = "NTLMv2"
	AppAuthAuto           AppAuthType = "auto"
	AppAuthServiceAccount AppAuthType = "service account"
)

type WappAuthType string

const (
	WappAuthForm       WappAuthType = "form"
	WappAuthBasic      WappAuthType = "basic"
	WappAuthBasicCookie WappAuthType = "basic_cookie"
	WappAuthJWT        WappAuthType = "jwt"
	WappAuthCertOnly   WappAuthType = "certonly"
)

type HTTPVersion string

const (
	HTTPVersion1_0 HTTPVersion = "1.0"
	HTTPVersion1_1 HTTPVersion = "1.1"
)

type LoadBalancingMetric string

const (
	LoadBalancingRoundRobin LoadBalancingMetric = "round-robin"
	LoadBalancingIPHash    LoadBalancingMetric = "ip-hash"
	LoadBalancingLeastConn LoadBalancingMetric = "least-conn"
	LoadBalancingWeightedRR LoadBalancingMetric = "weighted-rr"
)

type TLSSuiteType string

const (
	TLSSuiteTypeDefault TLSSuiteType = "default"
	TLSSuiteTypeCustom  TLSSuiteType = "custom"
)

type CORSValue string

const (
	CORSValueOn  CORSValue = "on"
	CORSValueOff CORSValue = "off"
)

type HTTPStatusCode string

const (
	HTTPStatus401 HTTPStatusCode = "401"
	HTTPStatus302 HTTPStatusCode = "302"
)

func (hct HealthCheckType) ToNumeric() string {
	switch hct {
	case HealthCheckTypeDefault:
		return "0"
	case HealthCheckTypeHTTP:
		return "1"
	case HealthCheckTypeHTTPS:
		return "2"
	case HealthCheckTypeTLS:
		return "3"
	case HealthCheckTypeSSLv3:
		return "4"
	case HealthCheckTypeTCP:
		return "5"
	case HealthCheckTypeNone:
		return "6"
	default:
		return string(hct) // fallback to original value (assumes it's already numeric)
	}
}

type HealthCheckTypeInt int

const (
	HEALTH_CHECK_TYPE_DEFAULT HealthCheckTypeInt = 0 + iota
	HEALTH_CHECK_TYPE_HTTP
	HEALTH_CHECK_TYPE_HTTPS
	HEALTH_CHECK_TYPE_TLS
	HEALTH_CHECK_TYPE_SSLV3
	HEALTH_CHECK_TYPE_TCP
	HEALTH_CHECK_TYPE_NONE
)

func (hct HealthCheckTypeInt) ToDescriptive() string {
	switch hct {
	case HEALTH_CHECK_TYPE_DEFAULT:
		return string(HealthCheckTypeDefault)
	case HEALTH_CHECK_TYPE_HTTP:
		return string(HealthCheckTypeHTTP)
	case HEALTH_CHECK_TYPE_HTTPS:
		return string(HealthCheckTypeHTTPS)
	case HEALTH_CHECK_TYPE_TLS:
		return string(HealthCheckTypeTLS)
	case HEALTH_CHECK_TYPE_SSLV3:
		return string(HealthCheckTypeSSLv3)
	case HEALTH_CHECK_TYPE_TCP:
		return string(HealthCheckTypeTCP)
	case HEALTH_CHECK_TYPE_NONE:
		return string(HealthCheckTypeNone)
	default:
		return "" // fallback to empty string
	}
}

// MapHealthCheckTypeToDescriptive converts numeric health check type values to descriptive values
func MapHealthCheckTypeToDescriptive(numericValue string) string {
	switch numericValue {
	case "0":
		return string(HealthCheckTypeDefault)
	case "1":
		return string(HealthCheckTypeHTTP)
	case "2":
		return string(HealthCheckTypeHTTPS)
	case "3":
		return string(HealthCheckTypeTLS)
	case "4":
		return string(HealthCheckTypeSSLv3)
	case "5":
		return string(HealthCheckTypeTCP)
	case "6":
		return string(HealthCheckTypeNone)
	default:
		return numericValue // fallback to original value
	}
}

// MapHealthCheckTypeToNumeric converts descriptive health check type values to numeric values
func MapHealthCheckTypeToNumeric(descriptiveValue string) string {
	switch descriptiveValue {
	case string(HealthCheckTypeDefault):
		return "0"
	case string(HealthCheckTypeHTTP):
		return "1"
	case string(HealthCheckTypeHTTPS):
		return "2"
	case string(HealthCheckTypeTLS):
		return "3"
	case string(HealthCheckTypeSSLv3):
		return "4"
	case string(HealthCheckTypeTCP):
		return "5"
	case string(HealthCheckTypeNone):
		return "6"
	default:
		return descriptiveValue // fallback to original value (assumes it's already numeric)
	}
}

// Load balancing validation errors
var (
	ErrLoadBalancingNotSupportedForRDP       = errors.New("load balancing is not supported for RDP profile")
	ErrLoadBalancingNotSupportedForSaaS      = errors.New("load balancing is not supported for SaaS apps")
	ErrLoadBalancingNotSupportedForTunnelSMB = errors.New("load balancing is not supported for tunnel apps with SMB profile")
	ErrLoadBalancingNotSupportedForAppType   = errors.New("load balancing is not supported for this app type")
	ErrLoadBalancingMetricNotString          = errors.New("load balancing metric must be a string")

	// Session sticky validation errors
	ErrSessionStickyNotBoolean        = errors.New("session_sticky must be a boolean")
	ErrCookieAgeNotNumber             = errors.New("cookie_age must be a number")
	ErrCookieAgeRequiresStickySession = errors.New("cookie_age requires session_sticky to be true")
	ErrCookieAgeNotSupportedForTunnel = errors.New("cookie_age is not supported for tunnel apps")
	ErrTCPOptimizationNotBoolean      = errors.New("tcp_optimization must be a boolean")
	ErrTCPOptimizationOnlyForTunnel   = errors.New("tcp_optimization is only supported for tunnel apps")

	// Custom headers validation errors
	ErrCustomHeadersNotSupportedForSaaS    = errors.New("custom headers are not supported for SaaS apps")
	ErrCustomHeadersNotSupportedForTunnel  = errors.New("custom headers are not supported for tunnel apps")
	ErrCustomHeadersNotSupportedForAppType = errors.New("custom headers are not supported for this app type")
	ErrCustomHeaderValidation              = errors.New("custom header validation failed")
	ErrCustomHeaderHeaderNotString         = errors.New("custom header name must be a string")
	ErrCustomHeaderAttributeTypeNotString  = errors.New("custom header attribute_type must be a string")
	ErrCustomHeaderAttributeNotString      = errors.New("custom header attribute must be a string")

	// Miscellaneous validation errors
	ErrMiscFieldOnlyForSSH               = errors.New("this field is only available for SSH profile")
	ErrMiscFieldNotAvailableForTunnel    = errors.New("this field is not available for tunnel apps")
	ErrMiscCORSFieldRequired             = errors.New("CORS field is required when CORS is enabled")
	ErrMiscOffloadNotAvailableForProfile = errors.New("offload_onpremise_traffic is not available for this profile")
	ErrMiscOffloadNotAvailableForType    = errors.New("offload_onpremise_traffic is not available for this app type")
	ErrMiscFieldOnlyForTunnel            = errors.New("this field is only available for tunnel apps")
)

// InfraType represents the infrastructure type for connector pools
type InfraType string

const (
	InfraTypeEAA     InfraType = "eaa"
	InfraTypeUnified InfraType = "unified"
	InfraTypeBroker  InfraType = "broker"
	InfraTypeCPAG    InfraType = "cpag"
)

func (it InfraType) ToInt() (int, error) {
	switch it {
	case InfraTypeEAA:
		return int(INFRA_TYPE_EAA), nil
	case InfraTypeUnified:
		return int(INFRA_TYPE_UNIFIED), nil
	case InfraTypeBroker:
		return int(INFRA_TYPE_BROKER), nil
	case InfraTypeCPAG:
		return int(INFRA_TYPE_CPAG), nil
	default:
		return 0, errors.New("unknown infra type value")
	}
}

type InfraTypeInt int

const (
	INFRA_TYPE_EAA InfraTypeInt = 1 + iota
	INFRA_TYPE_UNIFIED
	INFRA_TYPE_BROKER
	INFRA_TYPE_CPAG
)

func (it InfraTypeInt) String() (string, error) {
	switch it {
	case INFRA_TYPE_EAA:
		return string(InfraTypeEAA), nil
	case INFRA_TYPE_UNIFIED:
		return string(InfraTypeUnified), nil
	case INFRA_TYPE_BROKER:
		return string(InfraTypeBroker), nil
	case INFRA_TYPE_CPAG:
		return string(InfraTypeCPAG), nil
	default:
		return "", errors.New("unknown infra type value")
	}
}

// OperatingMode represents the operating mode for connector pools
type OperatingMode string

const (
	OperatingModeConnector               OperatingMode = "connector"
	OperatingModePEB                     OperatingMode = "peb"
	OperatingModeCombined                OperatingMode = "combined"
	OperatingModeCPAGPublic              OperatingMode = "cpag_public"
	OperatingModeCPAGPrivate             OperatingMode = "cpag_private"
	OperatingModeConnectorWithChinaAccel OperatingMode = "connector_with_china_acceleration"
)

func (om OperatingMode) ToInt() (int, error) {
	switch om {
	case OperatingModeConnector:
		return int(OPERATING_MODE_CONNECTOR), nil
	case OperatingModePEB:
		return int(OPERATING_MODE_PEB), nil
	case OperatingModeCombined:
		return int(OPERATING_MODE_COMBINED), nil
	case OperatingModeCPAGPublic:
		return int(OPERATING_MODE_CPAG_PUBLIC), nil
	case OperatingModeCPAGPrivate:
		return int(OPERATING_MODE_CPAG_PRIVATE), nil
	case OperatingModeConnectorWithChinaAccel:
		return int(OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION), nil
	default:
		return 0, errors.New("unknown operating mode value")
	}
}

type OperatingModeInt int

const (
	OPERATING_MODE_CONNECTOR OperatingModeInt = 1 + iota
	OPERATING_MODE_PEB
	OPERATING_MODE_COMBINED
	OPERATING_MODE_CPAG_PUBLIC
	OPERATING_MODE_CPAG_PRIVATE
	OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION
)

func (om OperatingModeInt) String() (string, error) {
	switch om {
	case OPERATING_MODE_CONNECTOR:
		return string(OperatingModeConnector), nil
	case OPERATING_MODE_PEB:
		return string(OperatingModePEB), nil
	case OPERATING_MODE_COMBINED:
		return string(OperatingModeCombined), nil
	case OPERATING_MODE_CPAG_PUBLIC:
		return string(OperatingModeCPAGPublic), nil
	case OPERATING_MODE_CPAG_PRIVATE:
		return string(OperatingModeCPAGPrivate), nil
	case OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION:
		return string(OperatingModeConnectorWithChinaAccel), nil
	default:
		return "", errors.New("unknown operating mode value")
	}
}

// Health check field names for validation
var HealthCheckFields = []string{
	"health_check_type",
	"health_check_rise", 
	"health_check_fall",
	"health_check_timeout",
	"health_check_interval",
	"health_check_http_url",
	"health_check_http_version",
	"health_check_http_host_header",
}

// Numeric health check field names for validation
var NumericHealthCheckFields = []string{
	"health_check_rise",
	"health_check_fall", 
	"health_check_timeout",
	"health_check_interval",
}
