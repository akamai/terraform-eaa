package client

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// ParseAdvancedSettingsWithDefaults parses JSON advanced settings and applies sensible defaults
func ParseAdvancedSettingsWithDefaults(jsonStr string) (*AdvancedSettings, error) {
	var userSettings map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &userSettings); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Create advanced settings with defaults matching the exact payload values
	advSettings := &AdvancedSettings{
		// Core defaults matching your payload exactly
		Acceleration:                 "false",
		AllowCORS:                    "true",
		AnonymousServerConnLimit:     "50",
		AnonymousServerReqLimit:      "100",
		AppAuth:                      "none",
		AppAuthDomain:                nil,
		AppCookieDomain:              nil,
		AppClientCertAuth:            "false",
		AppLocation:                  nil,
		AppServerReadTimeout:         "60",
		AuthenticatedServerConnLimit: "50",
		AuthenticatedServerReqLimit:  "100",
		ClientCertAuth:               "false",
		ClientCertUserParam:          "",
		CookieDomain:                 nil,
		CORSHeaderList:               "header1,header2,header3",
		CORSMaxAge:                   "86400",
		CORSMethodList:               "method1,method2",
		CORSOriginList:               "origin1,origin2,orign3",
		CORSSupportCredential:        "off",
		CustomHeaders:                []CustomHeader{},
		DisableUserAgentCheck:        "false",
		EdgeAuthenticationEnabled:    "false",
		EdgeCookieKey:                nil,
		EdgeTransportManualMode:      "",
		EdgeTransportPropertyID:      nil,
		EnableClientSideXHRRewrite:   "false",
		ExternalCookieDomain:         nil,
		ForceIPRoute:                 "false",
		ForceMFA:                     "off",
		FormPostAttributes:           []string{},
		FormPostURL:                  "",
		ForwardTicketGrantingTicket:  "false",
		G2OEnabled:                   "",
		G2OKey:                       nil,
		G2ONonce:                     nil,
		HealthCheckFall:              "3",
		HealthCheckHTTPURL:           "/",
		HealthCheckHTTPVersion:       "1.1",
		HealthCheckInterval:          "30000",
		HealthCheckRise:              "2",
		HealthCheckTimeout:           "50000",
		HealthCheckType:              "0",
		HealthCheckHTTPHostHeader:    nil,
		HiddenApp:                    "false",
		HostKey:                      nil,
		HSTSage:                      "15552000",
		HTTPOnlyCookie:               "true",
		HTTPSSSLV3:                   "false",
		IdleCloseTimeSeconds:         "1200",
		IdleConnCeil:                 "75",
		IdleConnFloor:                "50",
		IdleConnStep:                 "10",
		IDPIdleExpiry:                nil,
		IDPMaxExpiry:                 nil,
		IgnoreBypassMFA:              "off",
		IgnoreCnameResolution:        "",
		InjectAjaxJavascript:         "off",
		InterceptURL:                 "",
		InternalHostPort:             "0",

		// JWT defaults
		JWTAudience:              "",
		JWTGracePeriod:           "60",
		JWTIssuers:               "",
		JWTReturnOption:          "401",
		JWTReturnURL:             "",
		JWTUsername:              "",
		IPAccessAllow:            "false",
		IsBrotliEnabled:          "false",
		IsSSLVerificationEnabled: "false",
		KeepaliveConnectionPool:  "50",
		KeepaliveEnable:          "true",
		KeepaliveTimeout:         "300",

		LoadBalancingMetric:     "round-robin",
		LoggingEnabled:          "true",
		LoginTimeout:            "5",
		LoginURL:                nil,
		MDCEnable:               "false",
		OffloadOnpremiseTraffic: "false",
		Onramp:                  "inherit",
		PassPhrase:              nil,
		PreauthConsent:          "false",
		PreauthEnforceURL:       "",
		PrivateKey:              nil,

		RDPKeyboardLang: "",

		RDPRemoteApps:       []RemoteApp{},
		RDPWindowColorDepth: "",
		RDPWindowHeight:     "",
		RDPWindowWidth:      "",

		RemoteSparkAudio:          "true",
		RemoteSparkDisk:           "LOCALSHARE",
		RemoteSparkMapClipboard:   "on",
		RemoteSparkMapDisk:        "true",
		RemoteSparkMapPrinter:     "true",
		RemoteSparkPrinter:        "LOCALPRINTER",
		RemoteSparkRecording:      "false",
		RequestBodyRewrite:        "false",
		RequestParameters:         nil,
		SaaSEnabled:               "false",
		SegmentationPolicyEnable:  "false",
		SentryRedirect401:         "off",
		SentryRestoreFormPost:     "off",
		ServerCertValidate:        "true",
		ServerRequestBurst:        "100",
		ServicePrincipleName:      nil,
		RefreshStickyCookie:       "on",
		SessionSticky:             "false",
		SessionStickyCookieMaxAge: "0",
		SessionStickyServerCookie: nil,
		SlaObjectUrl:              nil,
		SingleHostContentRW:       "false",
		SingleHostCookieDomain:    "single.example.com",
		SingleHostEnable:          "false",
		SingleHostFQDN:            "",
		SingleHostPath:            "",
		SPDYEnabled:               "true",
		SSHAuditEnabled:           "false",
		SSO:                       "true",
		StickyAgent:               "false",
		UserName:                  nil,
		WappAuth:                  "form",
		WebSocketEnabled:          "false",
		WildcardInternalHostname:  "false",
		XWappPoolEnabled:          "inherit",
		XWappPoolSize:             "20",
		XWappPoolTimeout:          "120",
		XWappReadTimeout:          "900",
		DynamicIP:                 "false",
		StickyCookies:             "false",
		RDPInitialProgram:         "",
		RDPLegacyMode:             "false",
		RDPTLS1:                   "false",
	}

	// Apply user-specified values, overriding defaults using reflection
	applyAdvancedSettingsWithReflection(advSettings, userSettings)

	return advSettings, nil
}

// applyAdvancedSettingsWithReflection applies user settings to the advanced settings struct using reflection
// This eliminates the need for the massive switch statement and makes the code much more maintainable
func applyAdvancedSettingsWithReflection(advSettings *AdvancedSettings, userSettings map[string]interface{}) {

	// Field mapping: JSON key -> struct field name
	fieldMapping := map[string]string{
		"is_ssl_verification_enabled":        "IsSSLVerificationEnabled",
		"g2o_enabled":                        "G2OEnabled",
		"edge_authentication_enabled":        "EdgeAuthenticationEnabled",
		"ignore_cname_resolution":            "IgnoreCnameResolution",
		"allow_cors":                         "AllowCORS",
		"cors_origin_list":                   "CORSOriginList",
		"cors_method_list":                   "CORSMethodList",
		"cors_header_list":                   "CORSHeaderList",
		"cors_max_age":                       "CORSMaxAge",
		"cors_support_credential":            "CORSSupportCredential",
		"websocket_enabled":                  "WebSocketEnabled",
		"sticky_agent":                       "StickyAgent",
		"acceleration":                       "Acceleration",
		"spdy_enabled":                       "SPDYEnabled",
		"keepalive_enable":                   "KeepaliveEnable",
		"keepalive_timeout":                  "KeepaliveTimeout",
		"keepalive_connection_pool":          "KeepaliveConnectionPool",
		"health_check_type":                  "HealthCheckType",
		"health_check_http_url":              "HealthCheckHTTPURL",
		"health_check_interval":              "HealthCheckInterval",
		"health_check_timeout":               "HealthCheckTimeout",
		"kerberos_negotiate_once":            "KerberosNegotiateOnce",
		"health_check_rise":                  "HealthCheckRise",
		"health_check_fall":                  "HealthCheckFall",
		"health_check_http_version":          "HealthCheckHTTPVersion",
		"anonymous_server_conn_limit":        "AnonymousServerConnLimit",
		"anonymous_server_request_limit":     "AnonymousServerReqLimit",
		"app_auth":                           "AppAuth",
		"authenticated_server_conn_limit":    "AuthenticatedServerConnLimit",
		"authenticated_server_request_limit": "AuthenticatedServerReqLimit",
		"sso":                                "SSO",
		"mfa":                                "MFA",
		"logging_enabled":                    "LoggingEnabled",
		"login_timeout":                      "LoginTimeout",
		"hidden_app":                         "HiddenApp",
		"http_only_cookie":                   "HTTPOnlyCookie",
		"hsts_age":                           "HSTSage",
		"server_cert_validate":               "ServerCertValidate",
		"server_request_burst":               "ServerRequestBurst",
		"load_balancing_metric":              "LoadBalancingMetric",
		"idle_close_time_seconds":            "IdleCloseTimeSeconds",
		"idle_conn_ceil":                     "IdleConnCeil",
		"rate_limit":                         "RateLimit",
		"refresh_sticky_cookie":              "RefreshStickyCookie",
		"idle_conn_floor":                    "IdleConnFloor",
		"idle_conn_step":                     "IdleConnStep",
		"x_wapp_pool_size":                   "XWappPoolSize",
		"x_wapp_pool_timeout":                "XWappPoolTimeout",
		"x_wapp_pool_enabled":                "XWappPoolEnabled",
		"x_wapp_read_timeout":                "XWappReadTimeout",
		"edge_transport_manual_mode":         "EdgeTransportManualMode",
		"edge_cookie_key":                    "EdgeCookieKey",
		"force_mfa":                          "ForceMFA",
		"ignore_bypass_mfa":                  "IgnoreBypassMFA",
		"inject_ajax_javascript":             "InjectAjaxJavascript",
		"is_brotli_enabled":                  "IsBrotliEnabled",
		"mdc_enable":                         "MDCEnable",
		"offload_onpremise_traffic":          "OffloadOnpremiseTraffic",
		"onramp":                             "Onramp",
		"preauth_consent":                    "PreauthConsent",
		"remote_spark_audio":                 "RemoteSparkAudio",
		"remote_spark_disk":                  "RemoteSparkDisk",
		"remote_spark_mapClipboard":          "RemoteSparkMapClipboard",
		"remote_spark_mapDisk":               "RemoteSparkMapDisk",
		"remote_spark_mapPrinter":            "RemoteSparkMapPrinter",
		"remote_spark_recording":             "RemoteSparkRecording",
		"request_body_rewrite":               "RequestBodyRewrite",
		"saas_enabled":                       "SaaSEnabled",
		"segmentation_policy_enable":         "SegmentationPolicyEnable",
		"sentry_restore_form_post":           "SentryRestoreFormPost",
		"sentry_redirect_401":                "SentryRedirect401",
		"single_host_content_rw":             "SingleHostContentRW",
		"single_host_cookie_domain":          "SingleHostCookieDomain",
		"single_host_enable":                 "SingleHostEnable",
		"ssh_audit_enabled":                  "SSHAuditEnabled",
		// Additional fields
		"app_auth_domain":                "AppAuthDomain",
		"app_client_cert_auth":           "AppClientCertAuth",
		"app_cookie_domain":              "AppCookieDomain",
		"app_server_read_timeout":        "AppServerReadTimeout",
		"client_cert_auth":               "ClientCertAuth",
		"client_cert_user_param":         "ClientCertUserParam",
		"cookie_domain":                  "CookieDomain",
		"disable_user_agent_check":       "DisableUserAgentCheck",
		"domain_exception_list":          "DomainExceptionList",
		"enable_client_side_xhr_rewrite": "EnableClientSideXHRRewrite",
		"external_cookie_domain":         "ExternalCookieDomain",
		"force_ip_route":                 "ForceIPRoute",
		"form_post_attributes":           "FormPostAttributes",
		"form_post_url":                  "FormPostURL",
		"keyed_keepalive_enable":         "KeyedKeepaliveEnable",
		"keytab":                         "Keytab",
		"forward_ticket_granting_ticket": "ForwardTicketGrantingTicket",
		"health_check_http_host_header":  "HealthCheckHTTPHostHeader",
		"host_key":                       "HostKey",
		"https_sslv3":                    "HTTPSSSLV3",
		"idp_idle_expiry":                "IDPIdleExpiry",
		"idp_max_expiry":                 "IDPMaxExpiry",
		"intercept_url":                  "InterceptURL",
		"internal_host_port":             "InternalHostPort",
		"ip_access_allow":                "IPAccessAllow",
		"login_url":                      "LoginURL",
		"logout_url":                     "LogoutURL",
		"pass_phrase":                    "PassPhrase",
		"preauth_enforce_url":            "PreauthEnforceURL",
		"private_key":                    "PrivateKey",
		"proxy_buffer_size_kb":           "ProxyBufferSizeKB",
		"proxy_disable_clipboard":        "ProxyDisableClipboard",
		"rdp_keyboard_lang":              "RDPKeyboardLang",
		"custom_headers":                 "CustomHeaders",
		"rdp_remote_apps":                "RDPRemoteApps",
		"rdp_window_color_depth":         "RDPWindowColorDepth",
		"rdp_window_height":              "RDPWindowHeight",
		"rdp_window_width":               "RDPWindowWidth",
		"rdp_initial_program":            "RDPInitialProgram",
		"rdp_legacy_mode":                "RDPLegacyMode",
		"rdp_tls1":                       "RDPTLS1",
		"remote_spark_printer":           "RemoteSparkPrinter",
		"request_parameters":             "RequestParameters",
		"service_principle_name":         "ServicePrincipleName",
		"session_sticky":                 "SessionSticky",
		"session_sticky_cookie_maxage":   "SessionStickyCookieMaxAge",
		"session_sticky_server_cookie":   "SessionStickyServerCookie",
		"single_host_fqdn":               "SingleHostFQDN",
		"single_host_path":               "SingleHostPath",
		"user_name":                      "UserName",
		"wildcard_internal_hostname":     "WildcardInternalHostname",
		"tlsSuiteType":                   "TLSSuiteType",
		"tls_suite_name":                 "TLSSuiteName",

		// JWT fields
		"jwt_audience":      "JWTAudience",
		"jwt_grace_period":  "JWTGracePeriod",
		"jwt_issuers":       "JWTIssuers",
		"jwt_return_option": "JWTReturnOption",
		"jwt_return_url":    "JWTReturnURL",
		"jwt_username":      "JWTUsername",
		"wapp_auth":         "WappAuth",
		"dynamic_ip":        "DynamicIP",
		"sticky_cookies":    "StickyCookies",
	}

	// Special handling for remote_app fields - convert individual fields to RDPRemoteApps array
	var remoteApp RemoteApp
	var hasRemoteApp bool

	if remoteAppVal, exists := userSettings["remote_app"]; exists {
		if strVal, ok := remoteAppVal.(string); ok && strVal != "" {
			remoteApp.RemoteApp = strVal
			hasRemoteApp = true
		}
	}
	if remoteAppArgsVal, exists := userSettings["remote_app_args"]; exists {
		if strVal, ok := remoteAppArgsVal.(string); ok {
			remoteApp.RemoteAppArgs = strVal
		}
	}
	if remoteAppDirVal, exists := userSettings["remote_app_dir"]; exists {
		if strVal, ok := remoteAppDirVal.(string); ok {
			remoteApp.RemoteAppDir = strVal
		}
	}

	// Set RDPRemoteApps if we have remote_app data
	if hasRemoteApp {
		advSettings.RDPRemoteApps = []RemoteApp{remoteApp}
	}

	// Use reflection to set fields dynamically - handle both string and *string types
	val := reflect.ValueOf(advSettings).Elem()

	for jsonKey, value := range userSettings {
		if fieldName, exists := fieldMapping[jsonKey]; exists {
			field := val.FieldByName(fieldName)

			if field.IsValid() && field.CanSet() {
				// Special handling for health_check_type mapping
				if jsonKey == "health_check_type" {
					if strVal, ok := value.(string); ok {
						// Convert descriptive values to numeric values for health_check_type
						value = MapHealthCheckTypeToNumeric(strVal)
					}
				}

				// Handle different field types
				switch field.Kind() {
				case reflect.String:
					// For string fields, check if automatic conversion is allowed
					if jsonKey == "app_auth" {
						// Strict validation for app_auth: only accept strings
						if strVal, ok := value.(string); ok {
							field.SetString(strVal)
						} else {
							// Reject non-string values for app_auth
							continue // Skip this field
						}
					} else {
						// For other string fields, allow automatic conversion (handle both string and numeric inputs)
						var strVal string
						switch v := value.(type) {
						case string:
							strVal = v
						case int, int32, int64:
							strVal = fmt.Sprintf("%v", v)
						case float32, float64:
							strVal = fmt.Sprintf("%v", v)
						default:
							strVal = fmt.Sprintf("%v", v)
						}
						field.SetString(strVal)
					}
				case reflect.Ptr:
					// For pointer fields (like *string), create a pointer to the value
					if field.Type().Elem().Kind() == reflect.String {
						var strVal string
						switch v := value.(type) {
						case string:
							strVal = v
						case int, int32, int64:
							strVal = fmt.Sprintf("%v", v)
						case float32, float64:
							strVal = fmt.Sprintf("%v", v)
						default:
							strVal = fmt.Sprintf("%v", v)
						}
						field.Set(reflect.ValueOf(&strVal))
					}
				case reflect.Int, reflect.Int32, reflect.Int64:
					// For integer fields, convert from various numeric types
					var intVal int64
					switch v := value.(type) {
					case int:
						intVal = int64(v)
					case int32:
						intVal = int64(v)
					case int64:
						intVal = v
					case float32:
						intVal = int64(v)
					case float64:
						intVal = int64(v)
					case string:
						if parsedInt, err := strconv.ParseInt(v, 10, 64); err == nil {
							intVal = parsedInt
						} else {
							continue
						}
					default:
						continue
					}
					field.SetInt(intVal)
				case reflect.Slice:
					// Special handling for CustomHeaders slice
					if jsonKey == "custom_headers" {
						if interfaceSlice, ok := value.([]interface{}); ok {
							// Convert []interface{} to []CustomHeader
							customHeaders := make([]CustomHeader, len(interfaceSlice))
							for i, v := range interfaceSlice {
								if headerMap, ok := v.(map[string]interface{}); ok {
									customHeader := CustomHeader{}
									if attrType, exists := headerMap["attribute_type"]; exists {
										if str, ok := attrType.(string); ok {
											customHeader.AttributeType = str
										}
									}
									if header, exists := headerMap["header"]; exists {
										if str, ok := header.(string); ok {
											customHeader.Header = str
										}
									}
									if attr, exists := headerMap["attribute"]; exists {
										if str, ok := attr.(string); ok {
											customHeader.Attribute = str
										}
									}
									customHeaders[i] = customHeader
								}
							}
							field.Set(reflect.ValueOf(customHeaders))
							continue
						}
					}

					// For slice fields, handle type conversion properly
					if field.Type().Elem().Kind() == reflect.String {
						// Special handling for form_post_attributes: convert string to string slice
						if jsonKey == "form_post_attributes" {
							if strVal, ok := value.(string); ok {
								// Split the comma-separated string into a slice
								stringSlice := strings.Split(strVal, ",")
								// Trim whitespace from each element
								for i, s := range stringSlice {
									stringSlice[i] = strings.TrimSpace(s)
								}
								field.Set(reflect.ValueOf(stringSlice))
								continue
							}
						}

						// Convert []interface{} to []string
						if interfaceSlice, ok := value.([]interface{}); ok {
							stringSlice := make([]string, len(interfaceSlice))
							for i, v := range interfaceSlice {
								if strVal, ok := v.(string); ok {
									stringSlice[i] = strVal
								} else {
									stringSlice[i] = fmt.Sprintf("%v", v)
								}
							}
							field.Set(reflect.ValueOf(stringSlice))
						} else if stringSlice, ok := value.([]string); ok {
							// Already a string slice
							field.Set(reflect.ValueOf(stringSlice))
						} else {
							// For form_post_attributes, default to empty slice if conversion fails
							if jsonKey == "form_post_attributes" {

								field.Set(reflect.ValueOf([]string{}))
							} else {
							}
							continue
						}
					} else {
						// For non-string slices, handle type conversion properly
						if reflect.TypeOf(value).AssignableTo(field.Type()) {
							field.Set(reflect.ValueOf(value))
						} else {
							continue
						}
					}
				}
			}
		}
	}
}
