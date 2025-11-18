package eaaprovider

import (
	"encoding/json"
	"strconv"

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

	aType := client.ClientAppTypeInt(appResp.AppType)
	typeString, err := aType.String()
	if err != nil {
		eaaclient.Logger.Info("error converting app_type")
	}
	attrs["app_type"] = typeString

	aMode := client.ClientAppModeInt(appResp.ClientAppMode)
	modeString, err := aMode.String()
	if err != nil {
		eaaclient.Logger.Info("error converting client_app_mode")
	}
	attrs["client_app_mode"] = modeString

	attrs["domain"] = appResp.DomainSuffix

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
	attrs["app_bundle"] = appResp.AppBundle

	if err := client.SetAttrs(d, attrs); err != nil {
		return diag.FromErr(err)
	}

	return nil
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

	if client.ClientAppTypeInt(appResp.AppType) == client.APP_TYPE_TUNNEL {
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

// mapAdvancedSettingsFromResponse maps advanced settings from API response to schema
func mapAdvancedSettingsFromResponse(d *schema.ResourceData, appResp *client.ApplicationResponse) diag.Diagnostics {
	advSettingsMap := make(map[string]interface{})

	// Add all the advanced settings fields
	advSettingsMap["g2o_enabled"] = appResp.AdvancedSettings.G2OEnabled
	if appResp.AdvancedSettings.G2ONonce != nil {
		advSettingsMap["g2o_nonce"] = *appResp.AdvancedSettings.G2ONonce
	}
	if appResp.AdvancedSettings.G2OKey != nil {
		advSettingsMap["g2o_key"] = *appResp.AdvancedSettings.G2OKey
	}
	advSettingsMap["is_ssl_verification_enabled"] = appResp.AdvancedSettings.IsSSLVerificationEnabled
	advSettingsMap["ignore_cname_resolution"] = appResp.AdvancedSettings.IgnoreCnameResolution
	advSettingsMap["edge_authentication_enabled"] = appResp.AdvancedSettings.EdgeAuthenticationEnabled
	advSettingsMap["edge_cookie_key"] = appResp.AdvancedSettings.EdgeCookieKey
	advSettingsMap["sla_object_url"] = appResp.AdvancedSettings.SLAObjectURL
	advSettingsMap["x_wapp_read_timeout"] = appResp.AdvancedSettings.XWappReadTimeout
	if appResp.AdvancedSettings.InternalHostname != nil {
		advSettingsMap["internal_hostname"] = *appResp.AdvancedSettings.InternalHostname
	}
	advSettingsMap["internal_host_port"] = appResp.AdvancedSettings.InternalHostPort
	advSettingsMap["wildcard_internal_hostname"] = appResp.AdvancedSettings.WildcardInternalHostname
	advSettingsMap["ip_access_allow"] = appResp.AdvancedSettings.IPAccessAllow
	advSettingsMap["allow_cors"] = appResp.AdvancedSettings.AllowCORS
	advSettingsMap["cors_origin_list"] = appResp.AdvancedSettings.CORSOriginList
	advSettingsMap["cors_method_list"] = appResp.AdvancedSettings.CORSMethodList
	advSettingsMap["cors_header_list"] = appResp.AdvancedSettings.CORSHeaderList
	advSettingsMap["cors_support_credential"] = appResp.AdvancedSettings.CORSSupportCredential
	advSettingsMap["websocket_enabled"] = appResp.AdvancedSettings.WebSocketEnabled
	advSettingsMap["sticky_agent"] = appResp.AdvancedSettings.StickyAgent
	if appResp.AdvancedSettings.AppCookieDomain != nil {
		advSettingsMap["app_cookie_domain"] = *appResp.AdvancedSettings.AppCookieDomain
	}
	if appResp.AdvancedSettings.LogoutURL != nil {
		advSettingsMap["logout_url"] = *appResp.AdvancedSettings.LogoutURL
	}
	advSettingsMap["sentry_redirect_401"] = appResp.AdvancedSettings.SentryRedirect401
	advSettingsMap["acceleration"] = appResp.AdvancedSettings.Acceleration
	advSettingsMap["anonymous_server_conn_limit"] = appResp.AdvancedSettings.AnonymousServerConnLimit
	advSettingsMap["anonymous_server_request_limit"] = appResp.AdvancedSettings.AnonymousServerReqLimit
	advSettingsMap["app_auth"] = appResp.AdvancedSettings.AppAuth
	advSettingsMap["app_auth_domain"] = appResp.AdvancedSettings.AppAuthDomain
	advSettingsMap["app_client_cert_auth"] = appResp.AdvancedSettings.AppClientCertAuth
	advSettingsMap["app_bundle"] = appResp.AppBundle
	advSettingsMap["app_location"] = appResp.AdvancedSettings.AppLocation
	advSettingsMap["app_server_read_timeout"] = appResp.AdvancedSettings.AppServerReadTimeout
	advSettingsMap["authenticated_server_conn_limit"] = appResp.AdvancedSettings.AuthenticatedServerConnLimit
	advSettingsMap["authenticated_server_request_limit"] = appResp.AdvancedSettings.AuthenticatedServerReqLimit
	advSettingsMap["client_cert_auth"] = appResp.AdvancedSettings.ClientCertAuth
	advSettingsMap["client_cert_user_param"] = appResp.AdvancedSettings.ClientCertUserParam
	advSettingsMap["cookie_domain"] = convertStringPointerToString(appResp.AdvancedSettings.CookieDomain)
	advSettingsMap["disable_user_agent_check"] = appResp.AdvancedSettings.DisableUserAgentCheck
	advSettingsMap["domain_exception_list"] = appResp.AdvancedSettings.DomainExceptionList
	advSettingsMap["edge_transport_manual_mode"] = appResp.AdvancedSettings.EdgeTransportManualMode
	advSettingsMap["edge_transport_property_id"] = appResp.AdvancedSettings.EdgeTransportPropertyID
	advSettingsMap["enable_client_side_xhr_rewrite"] = appResp.AdvancedSettings.EnableClientSideXHRRewrite
	advSettingsMap["external_cookie_domain"] = appResp.AdvancedSettings.ExternalCookieDomain
	advSettingsMap["force_ip_route"] = appResp.AdvancedSettings.ForceIPRoute
	advSettingsMap["force_mfa"] = appResp.AdvancedSettings.ForceMFA
	advSettingsMap["form_post_attributes"] = appResp.AdvancedSettings.FormPostAttributes
	advSettingsMap["form_post_url"] = appResp.AdvancedSettings.FormPostURL
	advSettingsMap["forward_ticket_granting_ticket"] = appResp.AdvancedSettings.ForwardTicketGrantingTicket
	advSettingsMap["health_check_fall"] = appResp.AdvancedSettings.HealthCheckFall
	advSettingsMap["health_check_http_host_header"] = appResp.AdvancedSettings.HealthCheckHTTPHostHeader
	advSettingsMap["health_check_http_url"] = appResp.AdvancedSettings.HealthCheckHTTPURL
	advSettingsMap["health_check_http_version"] = appResp.AdvancedSettings.HealthCheckHTTPVersion
	advSettingsMap["health_check_interval"] = appResp.AdvancedSettings.HealthCheckInterval
	advSettingsMap["health_check_rise"] = appResp.AdvancedSettings.HealthCheckRise
	advSettingsMap["health_check_timeout"] = appResp.AdvancedSettings.HealthCheckTimeout
	advSettingsMap["health_check_type"] = client.MapHealthCheckTypeToDescriptive(appResp.AdvancedSettings.HealthCheckType)
	advSettingsMap["hidden_app"] = appResp.AdvancedSettings.HiddenApp
	advSettingsMap["host_key"] = appResp.AdvancedSettings.HostKey
	advSettingsMap["hsts_age"] = appResp.AdvancedSettings.HSTSage
	advSettingsMap["http_only_cookie"] = appResp.AdvancedSettings.HTTPOnlyCookie
	advSettingsMap["https_sslv3"] = appResp.AdvancedSettings.HTTPSSSLV3
	advSettingsMap["idle_close_time_seconds"] = appResp.AdvancedSettings.IdleCloseTimeSeconds
	advSettingsMap["idle_conn_ceil"] = appResp.AdvancedSettings.IdleConnCeil
	advSettingsMap["idle_conn_floor"] = appResp.AdvancedSettings.IdleConnFloor
	advSettingsMap["idle_conn_step"] = appResp.AdvancedSettings.IdleConnStep
	advSettingsMap["idp_idle_expiry"] = appResp.AdvancedSettings.IDPIdleExpiry
	advSettingsMap["idp_max_expiry"] = appResp.AdvancedSettings.IDPMaxExpiry
	advSettingsMap["ignore_bypass_mfa"] = appResp.AdvancedSettings.IgnoreBypassMFA
	advSettingsMap["inject_ajax_javascript"] = appResp.AdvancedSettings.InjectAjaxJavascript
	advSettingsMap["intercept_url"] = appResp.AdvancedSettings.InterceptURL
	advSettingsMap["is_brotli_enabled"] = appResp.AdvancedSettings.IsBrotliEnabled
	advSettingsMap["keepalive_connection_pool"] = appResp.AdvancedSettings.KeepaliveConnectionPool
	advSettingsMap["keepalive_enable"] = appResp.AdvancedSettings.KeepaliveEnable
	advSettingsMap["keepalive_timeout"] = appResp.AdvancedSettings.KeepaliveTimeout
	advSettingsMap["load_balancing_metric"] = appResp.AdvancedSettings.LoadBalancingMetric
	advSettingsMap["logging_enabled"] = appResp.AdvancedSettings.LoggingEnabled
	advSettingsMap["login_timeout"] = appResp.AdvancedSettings.LoginTimeout
	advSettingsMap["login_url"] = appResp.AdvancedSettings.LoginURL
	advSettingsMap["mdc_enable"] = appResp.AdvancedSettings.MDCEnable
	advSettingsMap["mfa"] = appResp.AdvancedSettings.MFA
	advSettingsMap["offload_onpremise_traffic"] = appResp.AdvancedSettings.OffloadOnPremiseTraffic
	advSettingsMap["onramp"] = appResp.AdvancedSettings.Onramp
	advSettingsMap["pass_phrase"] = appResp.AdvancedSettings.PassPhrase
	advSettingsMap["preauth_consent"] = appResp.AdvancedSettings.PreauthConsent
	advSettingsMap["preauth_enforce_url"] = appResp.AdvancedSettings.PreauthEnforceURL
	advSettingsMap["private_key"] = appResp.AdvancedSettings.PrivateKey
	advSettingsMap["remote_spark_audio"] = appResp.AdvancedSettings.RemoteSparkAudio
	advSettingsMap["remote_spark_disk"] = appResp.AdvancedSettings.RemoteSparkDisk
	advSettingsMap["remote_spark_map_clipboard"] = appResp.AdvancedSettings.RemoteSparkMapClipboard
	advSettingsMap["remote_spark_map_disk"] = appResp.AdvancedSettings.RemoteSparkMapDisk
	advSettingsMap["remote_spark_map_printer"] = appResp.AdvancedSettings.RemoteSparkMapPrinter
	advSettingsMap["remote_spark_printer"] = appResp.AdvancedSettings.RemoteSparkPrinter
	advSettingsMap["remote_spark_recording"] = appResp.AdvancedSettings.RemoteSparkRecording
	advSettingsMap["request_body_rewrite"] = appResp.AdvancedSettings.RequestBodyRewrite
	advSettingsMap["request_parameters"] = appResp.AdvancedSettings.RequestParameters
	advSettingsMap["saas_enabled"] = appResp.AdvancedSettings.SaaSEnabled
	advSettingsMap["segmentation_policy_enable"] = appResp.AdvancedSettings.SegmentationPolicyEnable
	advSettingsMap["sentry_restore_form_post"] = appResp.AdvancedSettings.SentryRestoreFormPost
	advSettingsMap["server_cert_validate"] = appResp.AdvancedSettings.ServerCertValidate
	advSettingsMap["server_request_burst"] = appResp.AdvancedSettings.ServerRequestBurst
	advSettingsMap["service_principle_name"] = appResp.AdvancedSettings.ServicePrincipalName
	advSettingsMap["session_sticky"] = appResp.AdvancedSettings.SessionSticky
	advSettingsMap["session_sticky_cookie_maxage"] = appResp.AdvancedSettings.SessionStickyCookieMaxAge
	advSettingsMap["session_sticky_server_cookie"] = appResp.AdvancedSettings.SessionStickyServerCookie
	advSettingsMap["single_host_content_rw"] = appResp.AdvancedSettings.SingleHostContentRW
	advSettingsMap["single_host_cookie_domain"] = appResp.AdvancedSettings.SingleHostCookieDomain
	advSettingsMap["single_host_enable"] = appResp.AdvancedSettings.SingleHostEnable
	advSettingsMap["single_host_fqdn"] = appResp.AdvancedSettings.SingleHostFQDN
	advSettingsMap["single_host_path"] = appResp.AdvancedSettings.SingleHostPath
	advSettingsMap["spdy_enabled"] = appResp.AdvancedSettings.SPDYEnabled
	advSettingsMap["ssh_audit_enabled"] = appResp.AdvancedSettings.SSHAuditEnabled
	advSettingsMap["sso"] = appResp.AdvancedSettings.SSO
	advSettingsMap["user_name"] = appResp.AdvancedSettings.UserName
	advSettingsMap["wapp_auth"] = appResp.AdvancedSettings.WappAuth
	advSettingsMap["x_wapp_pool_enabled"] = appResp.AdvancedSettings.XWappPoolEnabled
	advSettingsMap["x_wapp_pool_size"] = convertStringToInt(appResp.AdvancedSettings.XWappPoolSize)
	advSettingsMap["x_wapp_pool_timeout"] = convertStringToInt(appResp.AdvancedSettings.XWappPoolTimeout)
	advSettingsMap["rdp_keyboard_lang"] = appResp.AdvancedSettings.RDPKeyboardLang
	advSettingsMap["rdp_remote_apps"] = appResp.AdvancedSettings.RDPRemoteApps
	advSettingsMap["rdp_window_color_depth"] = appResp.AdvancedSettings.RDPWindowColorDepth
	advSettingsMap["rdp_window_height"] = appResp.AdvancedSettings.RDPWindowHeight
	advSettingsMap["rdp_window_width"] = appResp.AdvancedSettings.RDPWindowWidth

	// Handle CORS max age
	if appResp.AdvancedSettings.CORSMaxAge != "" {
		if corsAge, err := strconv.Atoi(appResp.AdvancedSettings.CORSMaxAge); err == nil {
			advSettingsMap["cors_max_age"] = corsAge
		}
	}

	// Handle custom headers
	if len(appResp.AdvancedSettings.CustomHeaders) > 0 {
		advSettingsMap["custom_headers"] = appResp.AdvancedSettings.CustomHeaders
	}

	// Convert to JSON string
	advSettingsJSON, err := json.Marshal(advSettingsMap)
	if err != nil {
		return diag.Errorf("failed to marshal advanced settings to JSON: %v", err)
	}

	err = d.Set("advanced_settings", string(advSettingsJSON))
	if err != nil {
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
		appAuthData, err := app.CreateAppAuthenticationStruct(eaaclient)
		if err == nil {
			err = d.Set("app_authentication", appAuthData)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	if appResp.Cert != nil {
		appCertData, err := client.GetCertificate(eaaclient, *appResp.Cert)
		if err == nil {
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
		for _, samlConfig := range appResp.SAMLSettings {
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
		for _, wsfedConfig := range appResp.WSFEDSettings {
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
			for _, oidcClient := range appResp.OIDCClients {
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
