package eaaprovider

import (
	"encoding/json"
	"fmt"
	"maps"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// mapBasicAttributesFromResponse maps basic application attributes from API response to schema
func mapBasicAttributesFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse, eaaclient *client.EaaClient) diag.Diagnostics {
	attrs := make(map[string]interface{})
	attrs["name"] = appResp.Name
	if appResp.Description != nil {
		attrs["description"] = *appResp.Description
	}

	aProfile := client.AppProfileInt(appResp.AppProfile)
	profileString, err := aProfile.String()
	if err != nil {
		eaaclient.Logger.Info("error converting app_profile")
	}
	attrs["app_profile"] = profileString

	aType := client.AppTypeInt(appResp.AppType)
	typeString, err := aType.String()
	if err != nil {
		eaaclient.Logger.Info("error converting app_type")
	}
	attrs["app_type"] = typeString

	aMode := client.AppModeInt(appResp.ClientAppMode)
	modeString, err := aMode.String()
	if err != nil {
		eaaclient.Logger.Info("error converting client_app_mode")
	}
	attrs["client_app_mode"] = modeString

	appDomain := client.DomainInt(appResp.Domain)
	domainString, err := appDomain.String()
	if err != nil {
		eaaclient.Logger.Info("error converting domain")
		attrs["domain"] = ""
	} else {
		attrs["domain"] = domainString
	}
	attrs["domain_suffix"] = appResp.DomainSuffix

	if appResp.Host != nil {
		attrs["host"] = *appResp.Host
	}
	if appResp.BookmarkURL != "" {
		attrs["bookmark_url"] = appResp.BookmarkURL
	}

	if appResp.OriginHost != nil && *appResp.OriginHost != "" {
		attrs["origin_host"] = *appResp.OriginHost
		attrs["orig_tls"] = appResp.OrigTLS
		attrs["origin_port"] = appResp.OriginPort
	}

	attrs["pop"] = appResp.POP
	attrs["popname"] = appResp.POPName
	attrs["popregion"] = appResp.POPRegion

	attrs["auth_enabled"] = appResp.AuthEnabled
	attrs["app_deployed"] = appResp.AppDeployed
	attrs["app_operational"] = appResp.AppOperational
	attrs["app_status"] = appResp.AppStatus

	// Compute auth flags mutually exclusively (SAML > OIDC > WSFED)
	samlEnabled := shouldEnableSAML(d)
	oidcEnabled := false
	wsfedEnabled := false
	if !samlEnabled {
		oidcEnabled = shouldEnableOIDC(d)
		if !oidcEnabled {
			wsfedEnabled = shouldEnableWSFED(d)
		}
	}
	attrs["saml"] = samlEnabled
	attrs["oidc"] = oidcEnabled
	attrs["wsfed"] = wsfedEnabled

	if appResp.CName != nil {
		attrs["cname"] = *appResp.CName
	}

	// Always set app_category, even if empty, to avoid null in state
	if appResp.AppCategory.Name != "" {
		attrs["app_category"] = appResp.AppCategory.Name
	} else {
		attrs["app_category"] = ""
	}

	// Always set cert, even if empty, to avoid null in state
	if appResp.Cert != nil {
		attrs["cert"] = *appResp.Cert
	} else {
		attrs["cert"] = ""
	}

	attrs["uuid_url"] = appResp.UUIDURL

	var diags diag.Diagnostics
	if appResp.AppBundle != "" {
		bundleName, err := eaaclient.GetAppBundleNameByUUID(appResp.AppBundle)
		if err != nil {
			attrs["app_bundle"] = ""
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Could not resolve app_bundle UUID to name",
				Detail:   "Failed to look up the app_bundle name for UUID " + appResp.AppBundle + ": " + err.Error() + ". app_bundle has been set to empty to avoid a perpetual diff. Check that the bundle exists and is accessible.",
			})
		} else {
			attrs["app_bundle"] = bundleName
		}
	} else {
		attrs["app_bundle"] = ""
	}

	if err := client.SetAttrs(d, attrs); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

// mapServersAndTunnelHostsFromResponse maps servers and tunnel internal hosts from API response to schema
func mapServersAndTunnelHostsFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse) diag.Diagnostics {
	servers := make([]map[string]interface{}, len(appResp.Servers))
	for i, server := range appResp.Servers {
		servers[i] = map[string]interface{}{
			"origin_host":     server.OriginHost,
			"orig_tls":        server.OrigTLS,
			"origin_port":     server.OriginPort,
			"origin_protocol": server.OriginProtocol,
		}
	}

	err := d.Set("servers", servers)
	if err != nil {
		return diag.FromErr(err)
	}

	if client.AppTypeInt(appResp.AppType) == client.APP_TYPE_TUNNEL {
		tunnelInternalHosts := make([]map[string]interface{}, len(appResp.TunnelInternalHosts))
		for i, host := range appResp.TunnelInternalHosts {
			tunnelInternalHosts[i] = map[string]interface{}{
				"host":       host.Host,
				"port_range": host.PortRange,
				"proto_type": host.ProtoType,
			}
		}
		err = d.Set("tunnel_internal_hosts", tunnelInternalHosts)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

// derefStr returns the dereferenced string or "" for nil.
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// serverComputedAdvancedSettingsKeys are keys the API auto-populates. They are used
// only by the DiffSuppressFunc to prevent perpetual diffs when present in state but
// absent from config (e.g. after an import or refresh-only).
var serverComputedAdvancedSettingsKeys = map[string]bool{
	"g2o_key":                    true,
	"g2o_nonce":                  true,
	"edge_cookie_key":            true,
	"sla_object_url":             true,
	"edge_transport_property_id": true,
}

// mapAdvancedSettingsFromResponse writes advanced_settings back into Terraform state.
// All keys behave the same: on import/refresh-only (no prior state) every non-empty
// API value is surfaced; on normal reads only keys already tracked in state are
// refreshed. The DiffSuppressFunc handles suppressing diffs for server-computed keys
// that the user never added to their config.
func mapAdvancedSettingsFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse) diag.Diagnostics {
	// Capture existing state values and key set.
	existingState := map[string]string{}
	existingKeys := map[string]bool{}
	if raw, ok := d.GetOk("advanced_settings"); ok {
		if m, ok := raw.(map[string]interface{}); ok {
			for k, v := range m {
				existingKeys[k] = true
				if s, ok := v.(string); ok {
					existingState[k] = s
				}
			}
		}
	}

	full := map[string]string{
		"acceleration":                       appResp.AdvancedSettings.Acceleration,
		"allow_cors":                         appResp.AdvancedSettings.AllowCORS,
		"anonymous_server_conn_limit":        appResp.AdvancedSettings.AnonymousServerConnLimit,
		"anonymous_server_request_limit":     appResp.AdvancedSettings.AnonymousServerReqLimit,
		"app_auth":                           appResp.AdvancedSettings.AppAuth,
		"app_auth_domain":                    appResp.AdvancedSettings.AppAuthDomain,
		"app_bundle":                         appResp.AppBundle,
		"app_client_cert_auth":               appResp.AdvancedSettings.AppClientCertAuth,
		"app_cookie_domain":                  derefStr(appResp.AdvancedSettings.AppCookieDomain),
		"app_location":                       derefStr(appResp.AdvancedSettings.AppLocation),
		"app_server_read_timeout":            appResp.AdvancedSettings.AppServerReadTimeout,
		"authenticated_server_conn_limit":    appResp.AdvancedSettings.AuthenticatedServerConnLimit,
		"authenticated_server_request_limit": appResp.AdvancedSettings.AuthenticatedServerReqLimit,
		"client_cert_auth":                   appResp.AdvancedSettings.ClientCertAuth,
		"client_cert_user_param":             appResp.AdvancedSettings.ClientCertUserParam,
		"cookie_domain":                      derefStr(appResp.AdvancedSettings.CookieDomain),
		"cors_header_list":                   appResp.AdvancedSettings.CORSHeaderList,
		"cors_max_age":                       appResp.AdvancedSettings.CORSMaxAge,
		"cors_method_list":                   appResp.AdvancedSettings.CORSMethodList,
		"cors_origin_list":                   appResp.AdvancedSettings.CORSOriginList,
		"cors_support_credential":            appResp.AdvancedSettings.CORSSupportCredential,
		"disable_user_agent_check":           appResp.AdvancedSettings.DisableUserAgentCheck,
		"domain_exception_list":              appResp.AdvancedSettings.DomainExceptionList,
		"edge_authentication_enabled":        appResp.AdvancedSettings.EdgeAuthenticationEnabled,
		"edge_cookie_key":                    appResp.AdvancedSettings.EdgeCookieKey,
		"edge_transport_manual_mode":         appResp.AdvancedSettings.EdgeTransportManualMode,
		"edge_transport_property_id":         derefStr(appResp.AdvancedSettings.EdgeTransportPropertyID),
		"enable_client_side_xhr_rewrite":     appResp.AdvancedSettings.EnableClientSideXHRRewrite,
		"external_cookie_domain":             derefStr(appResp.AdvancedSettings.ExternalCookieDomain),
		"force_ip_route":                     appResp.AdvancedSettings.ForceIPRoute,
		"force_mfa":                          appResp.AdvancedSettings.ForceMFA,
		"form_post_url":                      appResp.AdvancedSettings.FormPostURL,
		"forward_ticket_granting_ticket":     appResp.AdvancedSettings.ForwardTicketGrantingTicket,
		"g2o_enabled":                        appResp.AdvancedSettings.G2OEnabled,
		"g2o_key":                            derefStr(appResp.AdvancedSettings.G2OKey),
		"g2o_nonce":                          derefStr(appResp.AdvancedSettings.G2ONonce),
		"health_check_fall":                  appResp.AdvancedSettings.HealthCheckFall,
		"health_check_http_host_header":      derefStr(appResp.AdvancedSettings.HealthCheckHTTPHostHeader),
		"health_check_http_url":              appResp.AdvancedSettings.HealthCheckHTTPURL,
		"health_check_http_version":          appResp.AdvancedSettings.HealthCheckHTTPVersion,
		"health_check_interval":              appResp.AdvancedSettings.HealthCheckInterval,
		"health_check_rise":                  appResp.AdvancedSettings.HealthCheckRise,
		"health_check_timeout":               appResp.AdvancedSettings.HealthCheckTimeout,
		"health_check_type":                  client.MapHealthCheckTypeToDescriptive(appResp.AdvancedSettings.HealthCheckType),
		"hidden_app":                         appResp.AdvancedSettings.HiddenApp,
		"host_key":                           derefStr(appResp.AdvancedSettings.HostKey),
		"hsts_age":                           appResp.AdvancedSettings.HSTSage,
		"http_only_cookie":                   appResp.AdvancedSettings.HTTPOnlyCookie,
		"https_sslv3":                        appResp.AdvancedSettings.HTTPSSSLV3,
		"idle_close_time_seconds":            appResp.AdvancedSettings.IdleCloseTimeSeconds,
		"idle_conn_ceil":                     appResp.AdvancedSettings.IdleConnCeil,
		"idle_conn_floor":                    appResp.AdvancedSettings.IdleConnFloor,
		"idle_conn_step":                     appResp.AdvancedSettings.IdleConnStep,
		"idp_idle_expiry":                    derefStr(appResp.AdvancedSettings.IDPIdleExpiry),
		"idp_max_expiry":                     derefStr(appResp.AdvancedSettings.IDPMaxExpiry),
		"ignore_bypass_mfa":                  appResp.AdvancedSettings.IgnoreBypassMFA,
		"ignore_cname_resolution":            appResp.AdvancedSettings.IgnoreCnameResolution,
		"inject_ajax_javascript":             appResp.AdvancedSettings.InjectAjaxJavascript,
		"intercept_url":                      appResp.AdvancedSettings.InterceptURL,
		"internal_host_port":                 appResp.AdvancedSettings.InternalHostPort,
		"internal_hostname":                  derefStr(appResp.AdvancedSettings.InternalHostname),
		"ip_access_allow":                    appResp.AdvancedSettings.IPAccessAllow,
		"is_brotli_enabled":                  appResp.AdvancedSettings.IsBrotliEnabled,
		"is_ssl_verification_enabled":        appResp.AdvancedSettings.IsSSLVerificationEnabled,
		"jwt_audience":                       appResp.AdvancedSettings.JWTAudience,
		"jwt_grace_period":                   appResp.AdvancedSettings.JWTGracePeriod,
		"jwt_issuers":                        appResp.AdvancedSettings.JWTIssuers,
		"jwt_return_option":                  appResp.AdvancedSettings.JWTReturnOption,
		"jwt_return_url":                     appResp.AdvancedSettings.JWTReturnURL,
		"jwt_username":                       appResp.AdvancedSettings.JWTUsername,
		"keepalive_connection_pool":          appResp.AdvancedSettings.KeepaliveConnectionPool,
		"keepalive_enable":                   appResp.AdvancedSettings.KeepaliveEnable,
		"keepalive_timeout":                  appResp.AdvancedSettings.KeepaliveTimeout,
		"keytab":                             appResp.AdvancedSettings.Keytab,
		"load_balancing_metric":              appResp.AdvancedSettings.LoadBalancingMetric,
		"logging_enabled":                    appResp.AdvancedSettings.LoggingEnabled,
		"login_timeout":                      appResp.AdvancedSettings.LoginTimeout,
		"login_url":                          derefStr(appResp.AdvancedSettings.LoginURL),
		"logout_url":                         derefStr(appResp.AdvancedSettings.LogoutURL),
		"mdc_enable":                         appResp.AdvancedSettings.MDCEnable,
		"mfa":                                appResp.AdvancedSettings.MFA,
		"offload_onpremise_traffic":          appResp.AdvancedSettings.OffloadOnPremiseTraffic,
		"onramp":                             appResp.AdvancedSettings.Onramp,
		"pass_phrase":                        derefStr(appResp.AdvancedSettings.PassPhrase),
		"preauth_consent":                    appResp.AdvancedSettings.PreauthConsent,
		"preauth_enforce_url":                appResp.AdvancedSettings.PreauthEnforceURL,
		"private_key":                        derefStr(appResp.AdvancedSettings.PrivateKey),
		"rdp_initial_program":                derefStr(appResp.AdvancedSettings.RDPInitialProgram),
		"rdp_keyboard_lang":                  appResp.AdvancedSettings.RDPKeyboardLang,
		"rdp_legacy_mode":                    appResp.AdvancedSettings.RDPLegacyMode,
		"rdp_tls1":                           appResp.AdvancedSettings.RDPTLS1,
		"rdp_window_color_depth":             appResp.AdvancedSettings.RDPWindowColorDepth,
		"rdp_window_height":                  appResp.AdvancedSettings.RDPWindowHeight,
		"rdp_window_width":                   appResp.AdvancedSettings.RDPWindowWidth,
		"refresh_sticky_cookie":              appResp.AdvancedSettings.RefreshStickyCookie,
		"remote_spark_audio":                 appResp.AdvancedSettings.RemoteSparkAudio,
		"remote_spark_disk":                  appResp.AdvancedSettings.RemoteSparkDisk,
		"remote_spark_map_clipboard":         appResp.AdvancedSettings.RemoteSparkMapClipboard,
		"remote_spark_map_disk":              appResp.AdvancedSettings.RemoteSparkMapDisk,
		"remote_spark_map_printer":           appResp.AdvancedSettings.RemoteSparkMapPrinter,
		"remote_spark_printer":               appResp.AdvancedSettings.RemoteSparkPrinter,
		"remote_spark_recording":             appResp.AdvancedSettings.RemoteSparkRecording,
		"request_body_rewrite":               appResp.AdvancedSettings.RequestBodyRewrite,
		"saas_enabled":                       appResp.AdvancedSettings.SaaSEnabled,
		"segmentation_policy_enable":         appResp.AdvancedSettings.SegmentationPolicyEnable,
		"sentry_redirect_401":                appResp.AdvancedSettings.SentryRedirect401,
		"sentry_restore_form_post":           appResp.AdvancedSettings.SentryRestoreFormPost,
		"server_cert_validate":               appResp.AdvancedSettings.ServerCertValidate,
		"server_request_burst":               appResp.AdvancedSettings.ServerRequestBurst,
		"service_principle_name":             derefStr(appResp.AdvancedSettings.ServicePrincipalName),
		"session_sticky":                     appResp.AdvancedSettings.SessionSticky,
		"session_sticky_cookie_maxage":       appResp.AdvancedSettings.SessionStickyCookieMaxAge,
		"session_sticky_server_cookie":       derefStr(appResp.AdvancedSettings.SessionStickyServerCookie),
		"single_host_content_rw":             appResp.AdvancedSettings.SingleHostContentRW,
		"single_host_cookie_domain":          appResp.AdvancedSettings.SingleHostCookieDomain,
		"single_host_enable":                 appResp.AdvancedSettings.SingleHostEnable,
		"single_host_fqdn":                   appResp.AdvancedSettings.SingleHostFQDN,
		"single_host_path":                   appResp.AdvancedSettings.SingleHostPath,
		"sla_object_url":                     appResp.AdvancedSettings.SLAObjectURL,
		"spdy_enabled":                       appResp.AdvancedSettings.SPDYEnabled,
		"ssh_audit_enabled":                  appResp.AdvancedSettings.SSHAuditEnabled,
		"sso":                                appResp.AdvancedSettings.SSO,
		"sticky_agent":                       appResp.AdvancedSettings.StickyAgent,
		"tls_suite_name":                     derefStr(appResp.AdvancedSettings.TLSSuiteName),
		"user_name":                          derefStr(appResp.AdvancedSettings.UserName),
		"wapp_auth":                          appResp.AdvancedSettings.WappAuth,
		"websocket_enabled":                  appResp.AdvancedSettings.WebSocketEnabled,
		"wildcard_internal_hostname":         appResp.AdvancedSettings.WildcardInternalHostname,
		"x_wapp_pool_enabled":                appResp.AdvancedSettings.XWappPoolEnabled,
		"x_wapp_pool_size":                   appResp.AdvancedSettings.XWappPoolSize,
		"x_wapp_pool_timeout":                appResp.AdvancedSettings.XWappPoolTimeout,
		"x_wapp_read_timeout":                appResp.AdvancedSettings.XWappReadTimeout,
	}

	// tls_suite_type: int -> descriptive string; always set so nil clears state.
	switch {
	case appResp.AdvancedSettings.TLSSuiteType == nil:
		full["tls_suite_type"] = ""
	case *appResp.AdvancedSettings.TLSSuiteType == 1:
		full["tls_suite_type"] = "default"
	case *appResp.AdvancedSettings.TLSSuiteType == 2:
		full["tls_suite_type"] = "custom"
	default:
		full["tls_suite_type"] = ""
	}

	// form_post_attributes: []string -> JSON string.
	// Write "[]" only when the key is already tracked in state, so clearing is reflected.
	// On import (no prior state) omit the key entirely to avoid noisy diffs.
	if len(appResp.AdvancedSettings.FormPostAttributes) > 0 {
		fpaJSON, err := json.Marshal(appResp.AdvancedSettings.FormPostAttributes)
		if err != nil {
			return diag.Errorf("failed to marshal form_post_attributes to JSON: %v", err)
		}
		full["form_post_attributes"] = string(fpaJSON)
	} else if existingKeys["form_post_attributes"] {
		full["form_post_attributes"] = "[]"
	}

	// request_parameters: *string from API; set as-is when non-empty (nil means absent).
	// Write "" only when already tracked in state; omit on import.
	if appResp.AdvancedSettings.RequestParameters != nil && *appResp.AdvancedSettings.RequestParameters != "" {
		full["request_parameters"] = *appResp.AdvancedSettings.RequestParameters
	} else if existingKeys["request_parameters"] {
		full["request_parameters"] = ""
	}

	// custom_headers: []CustomHeader -> JSON string.
	// Write "[]" only when already tracked in state; omit on import.
	if len(appResp.AdvancedSettings.CustomHeaders) > 0 {
		chJSON, err := json.Marshal(appResp.AdvancedSettings.CustomHeaders)
		if err != nil {
			return diag.Errorf("failed to marshal custom_headers to JSON: %v", err)
		}
		full["custom_headers"] = string(chJSON)
	} else if existingKeys["custom_headers"] {
		full["custom_headers"] = "[]"
	}

	// rdp_remote_apps: []RemoteApp -> JSON string.
	// Write "[]" only when already tracked in state; omit on import.
	if len(appResp.AdvancedSettings.RDPRemoteApps) > 0 {
		rdpJSON, err := json.Marshal(appResp.AdvancedSettings.RDPRemoteApps)
		if err != nil {
			return diag.Errorf("failed to marshal rdp_remote_apps to JSON: %v", err)
		}
		full["rdp_remote_apps"] = string(rdpJSON)
	} else if existingKeys["rdp_remote_apps"] {
		full["rdp_remote_apps"] = "[]"
	}

	result := make(map[string]string)
	if len(existingKeys) == 0 {
		// Import / refresh-only: surface all non-empty API values.
		for k, v := range full {
			if v != "" {
				result[k] = v
			}
		}
	} else {
		// Normal read: preserve all existing state (including unknown/passthrough
		// keys), then overwrite only the keys we know how to map from the API.
		maps.Copy(result, existingState)
		for k, v := range full {
			if existingKeys[k] {
				result[k] = v
			}
		}
	}

	if err := d.Set("advanced_settings", result); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// mapAgentsAndAuthFromResponse maps agents, authentication, cert, and service from API response to schema
func mapAgentsAndAuthFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse, eaaclient *client.EaaClient) diag.Diagnostics {
	app := client.Application{}
	app.FromResponse(appResp)

	appAgents, err := app.GetAppAgents(eaaclient)
	if err == nil {
		err = d.Set("agents", appAgents)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	if appResp.AuthEnabled == "true" {
		appAuthData, authErr := app.CreateAppAuthenticationStruct(eaaclient)
		if authErr != nil {
			eaaclient.Logger.Error(fmt.Sprintf("failed to read app_authentication: %s", authErr.Error()))
		} else {
			err = d.Set("app_authentication", appAuthData)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	} else {
		err = d.Set("app_authentication", []map[string]interface{}{{
			"app_idp":         "",
			"app_directories": []map[string]interface{}{},
		}})
		if err != nil {
			return diag.FromErr(err)
		}
	}

	if appResp.Cert != nil {
		appCertData, certErr := client.GetCertificate(eaaclient, *appResp.Cert)
		if certErr == nil {
			err = d.Set("cert", appCertData.Cert)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	aclSrv, err := client.GetACLService(eaaclient, appResp.UUIDURL)
	if err != nil {
		return diag.FromErr(err)
	}
	appSvcData, err := aclSrv.CreateAppServiceStruct(eaaclient)
	if err == nil && appSvcData != nil {
		err = d.Set("service", appSvcData)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

// mapSAMLSettingsFromResponse maps SAML settings from API response to schema
func mapSAMLSettingsFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse) diag.Diagnostics {
	var samlSettings []map[string]interface{}

	if len(appResp.SAMLSettings) > 0 {
		for i := range appResp.SAMLSettings {
			samlConfig := &appResp.SAMLSettings[i]
			samlBlock := make(map[string]interface{})

			// Convert SP block
			spBlock := make(map[string]interface{})
			spBlock["entity_id"] = samlConfig.SP.EntityID
			spBlock["acs_url"] = samlConfig.SP.ACSURL
			spBlock["slo_url"] = samlConfig.SP.SLOURL
			spBlock["dst_url"] = samlConfig.SP.DSTURL
			spBlock["resp_bind"] = samlConfig.SP.ReqBind
			spBlock["encr_algo"] = samlConfig.SP.EncrAlgo
			samlBlock["sp"] = []map[string]interface{}{spBlock}

			// Convert IDP block
			idpBlock := make(map[string]interface{})
			idpBlock["entity_id"] = samlConfig.IDP.EntityID
			idpBlock["sign_algo"] = samlConfig.IDP.SignAlgo
			if samlConfig.IDP.SignCert != nil {
				idpBlock["sign_cert"] = *samlConfig.IDP.SignCert
			}
			idpBlock["sign_key"] = samlConfig.IDP.SignKey
			idpBlock["self_signed"] = samlConfig.IDP.SelfSigned
			samlBlock["idp"] = []map[string]interface{}{idpBlock}

			// Convert Subject block
			subjectBlock := make(map[string]interface{})
			subjectBlock["fmt"] = samlConfig.Subject.Fmt
			subjectBlock["src"] = samlConfig.Subject.Src
			samlBlock["subject"] = []map[string]interface{}{subjectBlock}

			// Convert Attrmap blocks
			var attrmapBlocks []map[string]interface{}
			for _, attr := range samlConfig.Attrmap {
				attrmapBlock := make(map[string]interface{})
				attrmapBlock["name"] = attr.Name
				attrmapBlock["fname"] = attr.Fname
				attrmapBlock["fmt"] = attr.Fmt
				attrmapBlock["val"] = attr.Val
				attrmapBlock["src"] = attr.Src
				attrmapBlock["rule"] = attr.Rule
				attrmapBlocks = append(attrmapBlocks, attrmapBlock)
			}
			samlBlock["attrmap"] = attrmapBlocks

			samlSettings = append(samlSettings, samlBlock)
		}
	}

	err := d.Set("saml_settings", samlSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// mapWSFEDSettingsFromResponse maps WS-Federation settings from API response to schema
func mapWSFEDSettingsFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse) diag.Diagnostics {
	var wsfedSettings []map[string]interface{}

	if len(appResp.WSFEDSettings) > 0 {
		for i := range appResp.WSFEDSettings {
			wsfedConfig := &appResp.WSFEDSettings[i]
			wsfedBlock := make(map[string]interface{})

			// SP block
			if wsfedConfig.SP.EntityID != "" || wsfedConfig.SP.SLOURL != "" || wsfedConfig.SP.DSTURL != "" ||
				wsfedConfig.SP.RespBind != "" || wsfedConfig.SP.TokenLife != 0 || wsfedConfig.SP.EncrAlgo != "" {
				spBlock := map[string]interface{}{
					"entity_id":  wsfedConfig.SP.EntityID,
					"slo_url":    wsfedConfig.SP.SLOURL,
					"dst_url":    wsfedConfig.SP.DSTURL,
					"resp_bind":  wsfedConfig.SP.RespBind,
					"token_life": wsfedConfig.SP.TokenLife,
					"encr_algo":  wsfedConfig.SP.EncrAlgo,
				}
				wsfedBlock["sp"] = []map[string]interface{}{spBlock}
			}

			// IDP block
			if wsfedConfig.IDP.EntityID != "" || wsfedConfig.IDP.SignAlgo != "" || wsfedConfig.IDP.SignCert != "" ||
				wsfedConfig.IDP.SignKey != "" || wsfedConfig.IDP.SelfSigned {
				idpBlock := map[string]interface{}{
					"entity_id":   wsfedConfig.IDP.EntityID,
					"sign_algo":   wsfedConfig.IDP.SignAlgo,
					"sign_cert":   wsfedConfig.IDP.SignCert,
					"sign_key":    wsfedConfig.IDP.SignKey,
					"self_signed": wsfedConfig.IDP.SelfSigned,
				}
				wsfedBlock["idp"] = []map[string]interface{}{idpBlock}
			}

			// Subject block
			if wsfedConfig.Subject.Fmt != "" || wsfedConfig.Subject.CustomFmt != "" || wsfedConfig.Subject.Src != "" ||
				wsfedConfig.Subject.Val != "" || wsfedConfig.Subject.Rule != "" {
				subjectBlock := map[string]interface{}{
					"fmt":        wsfedConfig.Subject.Fmt,
					"custom_fmt": wsfedConfig.Subject.CustomFmt,
					"src":        wsfedConfig.Subject.Src,
					"val":        wsfedConfig.Subject.Val,
					"rule":       wsfedConfig.Subject.Rule,
				}
				wsfedBlock["subject"] = []map[string]interface{}{subjectBlock}
			}

			// Attrmap block
			if len(wsfedConfig.Attrmap) > 0 {
				attrmapBlocks := make([]map[string]interface{}, len(wsfedConfig.Attrmap))
				for i, attr := range wsfedConfig.Attrmap {
					attrmapBlocks[i] = map[string]interface{}{
						"name":       attr.Name,
						"fmt":        attr.Fmt,
						"custom_fmt": attr.CustomFmt,
						"val":        attr.Val,
						"src":        attr.Src,
						"rule":       attr.Rule,
					}
				}
				wsfedBlock["attrmap"] = attrmapBlocks
			}

			wsfedSettings = append(wsfedSettings, wsfedBlock)
		}
	}

	err := d.Set("wsfed_settings", wsfedSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// mapOIDCSettingsFromResponse maps OIDC settings from API response to schema
func mapOIDCSettingsFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse) diag.Diagnostics {
	var oidcSettings []map[string]interface{}

	if appResp.OIDCSettings != nil {
		oidcBlock := make(map[string]interface{})

		// Convert OIDC endpoints
		if appResp.OIDCSettings.AuthorizationEndpoint != "" {
			oidcBlock["authorization_endpoint"] = appResp.OIDCSettings.AuthorizationEndpoint
		}
		if appResp.OIDCSettings.TokenEndpoint != "" {
			oidcBlock["token_endpoint"] = appResp.OIDCSettings.TokenEndpoint
		}
		if appResp.OIDCSettings.UserinfoEndpoint != "" {
			oidcBlock["userinfo_endpoint"] = appResp.OIDCSettings.UserinfoEndpoint
		}
		if appResp.OIDCSettings.JWKSURI != "" {
			oidcBlock["jwks_uri"] = appResp.OIDCSettings.JWKSURI
		}
		if appResp.OIDCSettings.DiscoveryURL != "" {
			oidcBlock["discovery_url"] = appResp.OIDCSettings.DiscoveryURL
		}
		if appResp.OIDCSettings.CertsURI != "" {
			oidcBlock["certs_uri"] = appResp.OIDCSettings.CertsURI
		}
		if appResp.OIDCSettings.CheckSessionIframe != "" {
			oidcBlock["check_session_iframe"] = appResp.OIDCSettings.CheckSessionIframe
		}
		if appResp.OIDCSettings.EndSessionEndpoint != "" {
			oidcBlock["end_session_endpoint"] = appResp.OIDCSettings.EndSessionEndpoint
		}
		if appResp.OIDCSettings.OpenIDMetadata != "" {
			oidcBlock["openid_metadata"] = appResp.OIDCSettings.OpenIDMetadata
		}

		// Convert OIDC clients
		if len(appResp.OIDCClients) > 0 {
			var oidcClients []map[string]interface{}
			for i := range appResp.OIDCClients {
				oidcClient := &appResp.OIDCClients[i]
				clientBlock := make(map[string]interface{})
				clientBlock["client_name"] = oidcClient.ClientName
				clientBlock["client_id"] = oidcClient.ClientID
				clientBlock["response_type"] = oidcClient.ResponseType
				clientBlock["implicit_grant"] = oidcClient.ImplicitGrant
				clientBlock["type"] = oidcClient.Type
				clientBlock["redirect_uris"] = oidcClient.RedirectURIs
				clientBlock["javascript_origins"] = oidcClient.JavaScriptOrigins

				// Convert claims
				var claims []map[string]interface{}
				for _, claim := range oidcClient.Claims {
					claimBlock := make(map[string]interface{})
					claimBlock["name"] = claim.Name
					claimBlock["scope"] = claim.Scope
					claimBlock["val"] = claim.Val
					claimBlock["src"] = claim.Src
					claimBlock["rule"] = claim.Rule
					claims = append(claims, claimBlock)
				}
				clientBlock["claims"] = claims

				oidcClients = append(oidcClients, clientBlock)
			}
			oidcBlock["oidc_clients"] = oidcClients
		}

		oidcSettings = append(oidcSettings, oidcBlock)
	}

	// Only set oidc_settings if OIDC is actually enabled
	if appResp.Oidc {
		err := d.Set("oidc_settings", oidcSettings)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}
