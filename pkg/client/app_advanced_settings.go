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
		Acceleration:                 string(DefaultAcceleration),
		AllowCORS:                    string(DefaultAllowCORS),
		AnonymousServerConnLimit:     "50",
		AnonymousServerReqLimit:      "100",
		AppAuth:                      string(DefaultAppAuth),
		AppAuthDomain:                nil,
		AppCookieDomain:              nil,
		AppClientCertAuth:            string(DefaultAppClientCertAuth),
		AppLocation:                  nil,
		AppServerReadTimeout:         FlexString("60"),
		AuthenticatedServerConnLimit: "50",
		AuthenticatedServerReqLimit:  "100",
		ClientCertAuth:               string(DefaultClientCertAuth),
		ClientCertUserParam:          "",
		CookieDomain:                 nil,
		CORSHeaderList:               "unbounded",
		CORSMaxAge:                   "86400",
		CORSMethodList:               "unbounded",
		CORSOriginList:               "unbounded",
		CORSSupportCredential:        string(DefaultCORSSupportCredential),
		CustomHeaders:                []CustomHeader{},
		DisableUserAgentCheck:        string(DefaultDisableUserAgentCheck),
		EdgeAuthenticationEnabled:    string(DefaultEdgeAuthenticationEnabled),
		EdgeCookieKey:                nil,
		EdgeTransportManualMode:      "",
		EdgeTransportPropertyID:      nil,
		EnableClientSideXHRRewrite:   string(DefaultEnableClientSideXHRRewrite),
		ExternalCookieDomain:         nil,
		ForceIPRoute:                 string(DefaultForceIPRoute),
		ForceMFA:                     string(DefaultForceMFA),
		FormPostAttributes:           []string{},
		FormPostURL:                  "",
		ForwardTicketGrantingTicket:  string(DefaultForwardTicketGrantingTicket),
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
		HiddenApp:                    string(DefaultHiddenApp),
		HostKey:                      nil,
		HSTSage:                      "15552000",
		HTTPOnlyCookie:               string(DefaultHTTPOnlyCookie),
		HTTPSSSLV3:                   string(DefaultHTTPSSSLV3),
		IdleCloseTimeSeconds:         "1200",
		IdleConnCeil:                 "75",
		IdleConnFloor:                "50",
		IdleConnStep:                 "10",
		IDPIdleExpiry:                nil,
		IDPMaxExpiry:                 nil,
		IgnoreBypassMFA:              string(DefaultIgnoreBypassMFA),
		IgnoreCnameResolution:        "",
		InjectAjaxJavascript:         string(DefaultInjectAjaxJavascript),
		InterceptURL:                 "",
		InternalHostPort:             "0",

		// JWT defaults
		JWTAudience:              "",
		JWTGracePeriod:           "60",
		JWTIssuers:               "",
		JWTReturnOption:          "401",
		JWTReturnURL:             "",
		JWTUsername:              "",
		IPAccessAllow:            string(DefaultIPAccessAllow),
		IsBrotliEnabled:          string(DefaultIsBrotliEnabled),
		IsSSLVerificationEnabled: string(DefaultIsSSLVerificationEnabled),
		KeepaliveConnectionPool:  "50",
		KeepaliveEnable:          string(DefaultKeepaliveEnable),
		KeepaliveTimeout:         string(DefaultKeepAliveTimeout),
		KeyedKeepaliveEnable:     string(DefaultKeyedKeepaliveEnable),
		KerberosNegotiateOnce:    string(DefaultKerberosNegotiateOnce),
		ProxyBufferSizeKB:        string(DefaultProxyBufferSizeKB),
		ProxyDisableClipboard:    string(DefaultProxyDisableClipboard),
		RateLimit:                string(DefaultRateLimit),

		LoadBalancingMetric:     "round-robin",
		LoggingEnabled:          string(DefaultLoggingEnabled),
		LoginTimeout:            "5",
		LoginURL:                nil,
		MDCEnable:               string(DefaultMDCEnable),
		OffloadOnPremiseTraffic: string(DefaultOffloadOnpremiseTraffic),
		Onramp:                  string(DefaultOnramp),
		PassPhrase:              nil,
		PreauthConsent:          string(DefaultPreauthConsent),
		PreauthEnforceURL:       "",
		PrivateKey:              nil,

		RDPKeyboardLang: "",

		RDPRemoteApps:       []RemoteApp{},
		RDPWindowColorDepth: "",
		RDPWindowHeight:     "",
		RDPWindowWidth:      "",

		RemoteSparkAudio:          string(DefaultRemoteSparkAudio),
		RemoteSparkDisk:           "LOCALSHARE",
		RemoteSparkMapClipboard:   string(DefaultRemoteSparkMapClipboard),
		RemoteSparkMapDisk:        string(DefaultRemoteSparkMapDisk),
		RemoteSparkMapPrinter:     string(DefaultRemoteSparkMapPrinter),
		RemoteSparkPrinter:        "LOCALPRINTER",
		RemoteSparkRecording:      string(DefaultRemoteSparkRecording),
		RequestBodyRewrite:        string(DefaultRequestBodyRewrite),
		RequestParameters:         nil,
		SaaSEnabled:               string(DefaultSaaSEnabled),
		SegmentationPolicyEnable:  string(DefaultSegmentationPolicyEnable),
		SentryRedirect401:         string(DefaultSentryRedirect401),
		SentryRestoreFormPost:     string(DefaultSentryRestoreFormPost),
		ServerCertValidate:        string(DefaultServerCertValidate),
		ServerRequestBurst:        "100",
		ServicePrincipalName:      nil,
		RefreshStickyCookie:       string(DefaultRefreshStickyCookie),
		SessionSticky:             string(DefaultSessionSticky),
		SessionStickyCookieMaxAge: "0",
		SessionStickyServerCookie: nil,
		SLAObjectURL:              nil,
		SingleHostContentRW:       string(DefaultSingleHostContentRW),
		SingleHostCookieDomain:    string(DefaultSingleHostCookieDomain),
		SingleHostEnable:          string(DefaultSingleHostEnable),
		SingleHostFQDN:            "",
		SingleHostPath:            "",
		SPDYEnabled:               string(DefaultSPDYEnabled),
		SSHAuditEnabled:           string(DefaultSSHAuditEnabled),
		SSO:                       string(DefaultSSO),
		StickyAgent:               string(DefaultStickyAgent),
		UserName:                  nil,
		WappAuth:                  string(DefaultWappAuth),
		WebSocketEnabled:          string(DefaultWebSocketEnabled),
		WildcardInternalHostname:  string(DefaultWildcardInternalHostname),
		XWappPoolEnabled:          string(DefaultXWappPoolEnabled),
		XWappPoolSize:             FlexString("20"),
		XWappPoolTimeout:          FlexString("120"),
		XWappReadTimeout:          FlexString("900"),
		RDPInitialProgram:         "",
		RDPLegacyMode:             string(DefaultRDPLegacyMode),
		RDPTLS1:                   string(DefaultRDPTLS1),
	}

	// Apply user-specified values, overriding defaults using reflection
	if err := applyAdvancedSettingsWithReflection(advSettings, userSettings); err != nil {
		return nil, err
	}

	return advSettings, nil
}

// advancedSettingsFromBlock builds an *AdvancedSettings from the Terraform TypeMap
// value for advanced_settings (a map[string]interface{} from d.GetOk("advanced_settings")).
// It normalises the special-typed fields (TypeList of strings, TypeMap, JSON-string complex fields)
// and then delegates to ParseAdvancedSettingsWithDefaults for everything else.
func advancedSettingsFromBlock(block map[string]interface{}) (*AdvancedSettings, error) {
	// Build a flat map[string]interface{} that ParseAdvancedSettingsWithDefaults understands.
	// Most fields are already TypeString so they pass through unchanged.
	flat := make(map[string]interface{}, len(block))
	for k, v := range block {
		flat[k] = v
	}

	// form_post_attributes: stored as JSON string in TypeMap; decode to []interface{} for reflection.
	if fpaStr, ok := block["form_post_attributes"].(string); ok && fpaStr != "" {
		var decoded []interface{}
		if err := json.Unmarshal([]byte(fpaStr), &decoded); err != nil {
			return nil, fmt.Errorf("invalid form_post_attributes JSON: %w", err)
		}
		flat["form_post_attributes"] = decoded
	} else {
		flat["form_post_attributes"] = []interface{}{}
	}

	// custom_headers: stored as JSON string in state; decode back to []interface{} for reflection.
	if chStr, ok := block["custom_headers"].(string); ok && chStr != "" {
		var decoded []interface{}
		if err := json.Unmarshal([]byte(chStr), &decoded); err != nil {
			return nil, fmt.Errorf("invalid custom_headers JSON: %w", err)
		}
		flat["custom_headers"] = decoded
	} else {
		flat["custom_headers"] = []interface{}{}
	}

	// rdp_remote_apps: stored as JSON string; decode and set on struct after ParseWithDefaults.
	var rdpRemoteApps []RemoteApp
	if rdpStr, ok := block["rdp_remote_apps"].(string); ok {
		rdpRemoteApps = []RemoteApp{}
		if rdpStr != "" {
			if err := json.Unmarshal([]byte(rdpStr), &rdpRemoteApps); err != nil {
				return nil, fmt.Errorf("invalid rdp_remote_apps JSON: %w", err)
			}
		}
	}
	// Remove from flat map so applyAdvancedSettingsWithReflection doesn't try to handle the string.
	delete(flat, "rdp_remote_apps")

	// tls_suite_type / tls_suite_name are handled at the call site (CREATE/UPDATE flows),
	// not inside AdvancedSettings struct. Remove them so reflection doesn't try to find them.
	delete(flat, "tls_suite_type")
	delete(flat, "tls_suite_name")

	// Marshal to JSON and reuse ParseAdvancedSettingsWithDefaults so all defaults are applied.
	jsonBytes, err := json.Marshal(flat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal advanced settings block: %w", err)
	}

	advSettings, err := ParseAdvancedSettingsWithDefaults(string(jsonBytes))
	if err != nil {
		return nil, err
	}

	// Restore rdp_remote_apps that was excluded from the flat map.
	if _, ok := block["rdp_remote_apps"]; ok {
		advSettings.RDPRemoteApps = rdpRemoteApps
	}

	return advSettings, nil
}

// applyAdvancedSettingsWithReflection applies user settings to the advanced settings struct using reflection
// This eliminates the need for the massive switch statement and makes the code much more maintainable
func applyAdvancedSettingsWithReflection(advSettings *AdvancedSettings, userSettings map[string]interface{}) error {

	// Field mapping: JSON key -> struct field name
	// #nosec G101 -- static field-name mapping includes auth/key labels but does not contain secrets
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
		"offload_onpremise_traffic":          "OffloadOnPremiseTraffic",
		"onramp":                             "Onramp",
		"preauth_consent":                    "PreauthConsent",
		"remote_spark_audio":                 "RemoteSparkAudio",
		"remote_spark_disk":                  "RemoteSparkDisk",
		"remote_spark_map_clipboard":         "RemoteSparkMapClipboard",
		"remote_spark_map_disk":              "RemoteSparkMapDisk",
		"remote_spark_map_printer":           "RemoteSparkMapPrinter",
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
		"service_principle_name":         "ServicePrincipalName",
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

	// Keys handled via the pre-loop special logic above; not real API fields.
	internalOnlyKeys := map[string]bool{
		"remote_app":      true,
		"remote_app_args": true,
		"remote_app_dir":  true,
	}

	for jsonKey, value := range userSettings {
		if fieldName, exists := fieldMapping[jsonKey]; exists {
			field := val.FieldByName(fieldName)

			if field.IsValid() && field.CanSet() {
				// Special handling for health_check_type mapping
				if jsonKey == "health_check_type" {
					if strVal, ok := value.(string); ok {
						// Convert descriptive values to numeric values for health_check_type
						mappedValue, err := MapHealthCheckTypeToNumeric(strVal)
						if err != nil {
							return fmt.Errorf("invalid health_check_type %q: %w", strVal, err)
						}
						value = mappedValue
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
						case int, int32, int64, float32, float64, bool:
							strVal = fmt.Sprintf("%v", v)
						default:
							continue
						}
						field.SetString(strVal)
					}
				case reflect.Int, reflect.Int32, reflect.Int64:
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
				case reflect.Pointer:
					if value == nil {
						field.Set(reflect.Zero(field.Type()))
						continue
					}

					if field.Type().Elem().Kind() != reflect.String {
						continue
					}

					var strVal string
					switch v := value.(type) {
					case string:
						strVal = v
					case int, int32, int64, float32, float64, bool:
						strVal = fmt.Sprintf("%v", v)
					default:
						continue
					}

					ptrVal := reflect.New(field.Type().Elem())
					ptrVal.Elem().SetString(strVal)
					field.Set(ptrVal)
				case reflect.Slice:
					// Special handling for CustomHeaders slice
					if jsonKey == "custom_headers" {
						interfaceSlice, ok := value.([]interface{})
						if !ok {
							continue
						}
						// Convert []interface{} to []CustomHeader
						customHeaders := make([]CustomHeader, len(interfaceSlice))
						for i, v := range interfaceSlice {
							headerMap, ok := v.(map[string]interface{})
							if !ok {
								continue
							}

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
						field.Set(reflect.ValueOf(customHeaders))
						continue
					}

					// For slice fields, handle type conversion properly
					switch typedValue := value.(type) {
					case []interface{}:
						if field.Type().Elem().Kind() == reflect.String {
							stringSlice := make([]string, len(typedValue))
							for i, v := range typedValue {
								if strVal, ok := v.(string); ok {
									stringSlice[i] = strVal
								} else {
									stringSlice[i] = fmt.Sprintf("%v", v)
								}
							}
							field.Set(reflect.ValueOf(stringSlice))
							continue
						}
					case []string:
						if field.Type().Elem().Kind() == reflect.String {
							field.Set(reflect.ValueOf(typedValue))
							continue
						}
					}

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

						// For form_post_attributes, default to empty slice if conversion fails
						if jsonKey == "form_post_attributes" {
							field.Set(reflect.ValueOf([]string{}))
						}
						continue
					} else {
						// For non-string slices, handle type conversion properly
						if reflect.TypeOf(value).AssignableTo(field.Type()) {
							field.Set(reflect.ValueOf(value))
						} else {
							continue
						}
					}
				case reflect.Map:
					rv := reflect.ValueOf(value)
					if rv.IsValid() && rv.Type().AssignableTo(field.Type()) {
						field.Set(rv)
					}
				}
			}
		} else if !internalOnlyKeys[jsonKey] {
			if advSettings.ExtraFields == nil {
				advSettings.ExtraFields = make(map[string]interface{})
			}
			advSettings.ExtraFields[jsonKey] = value
		}
	}

	return nil
}
