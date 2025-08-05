package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type CreateAppRequest struct {
	Name          string  `json:"name"`
	Description   *string `json:"description"`
	AppProfile    int     `json:"app_profile"`
	AppType       int     `json:"app_type"`
	ClientAppMode int     `json:"client_app_mode"`
}

func (car *CreateAppRequest) CreateAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	logger := ec.Logger
	if name, ok := d.GetOk("name"); ok {
		nameStr, ok := name.(string)
		if ok && nameStr != "" {
			car.Name = name.(string)
		}
	} else {
		logger.Error("create Application failed. name is invalid")
		return ErrInvalidValue
	}

	if description, ok := d.GetOk("description"); ok {
		descriptionStr, ok := description.(string)
		if ok && descriptionStr != "" {
			car.Description = &descriptionStr
		}
	}

	if appType, ok := d.GetOk("app_type"); ok {
		strAppType, ok := appType.(string)
		if !ok {
			logger.Error("create Application failed. app_type is invalid")
			return ErrInvalidType
		}
		atype := ClientAppType(strAppType)
		value, err := atype.ToInt()
		if err != nil {
			logger.Error("create Application failed. app_type is invalid")
			return ErrInvalidValue
		}
		car.AppType = value
		logger.Info("appType", appType)
		logger.Info("car.AppType", car.AppType)
	} else {
		logger.Info("appType is not present, defaulting to enterprise")
		car.AppType = int(APP_TYPE_ENTERPRISE_HOSTED)
	}

	if appProfile, ok := d.GetOk("app_profile"); ok {
		strappProfile, ok := appProfile.(string)
		if !ok {
			logger.Error("create Application failed. app_profile is invalid")
			return ErrInvalidType
		}
		aProfile := AppProfile(strappProfile)
		value, err := aProfile.ToInt()
		if err != nil {
			logger.Error("create Application failed. app_profile is invalid")
			return ErrInvalidValue
		}
		car.AppProfile = value
		logger.Info("appProfile", appProfile)
		logger.Info("car.AppProfile", car.AppProfile)
	} else {
		logger.Info("appProfile is not present, defaulting to http")
		car.AppProfile = int(APP_PROFILE_HTTP)
	}

	if clientAppMode, ok := d.GetOk("client_app_mode"); ok {
		appMode, ok := clientAppMode.(string)
		if !ok {
			logger.Error("create Application failed. clientAppMode is invalid")
			return ErrInvalidType
		}
		aMode := ClientAppMode(appMode)
		value, err := aMode.ToInt()
		if err != nil {
			logger.Error("create Application failed. clientAppMode is invalid")
			return ErrInvalidValue
		}
		car.ClientAppMode = value
		logger.Info("appMode", clientAppMode)
		logger.Info("car.ClientAppMode", car.ClientAppMode)
	} else {
		logger.Info("appMode is not present, defaulting to tcp")
		car.ClientAppMode = int(CLIENT_APP_MODE_TCP)
	}
	return nil
}

func (car *CreateAppRequest) CreateApplication(ctx context.Context, ec *EaaClient) (*ApplicationResponse, error) {
	ec.Logger.Info("create application")
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, APPS_URL)
	var appResp ApplicationResponse
	createAppResp, err := ec.SendAPIRequest(apiURL, "POST", car, &appResp, false)

	if err != nil {
		ec.Logger.Error("create Application failed. err", err)
		return nil, err
	}

	if createAppResp.StatusCode != http.StatusOK {
		desc, _ := FormatErrorResponse(createAppResp)
		createErrMsg := fmt.Errorf("%w: %s", ErrAppCreate, desc)

		ec.Logger.Error("create Application failed. StatusCode %d %s", createAppResp.StatusCode, desc)
		return nil, createErrMsg
	}
	ec.Logger.Info("create Application succeeded.", "name", car.Name)
	return &appResp, nil
}

type Application struct {
	Name          string  `json:"name"`
	Description   *string `json:"description"`
	AppProfile    int     `json:"app_profile"`
	AppType       int     `json:"app_type"`
	ClientAppMode int     `json:"client_app_mode"`

	Host        *string `json:"host"`
	BookmarkURL string  `json:"bookmark_url"`
	AppLogo     *string `json:"app_logo"`

	OrigTLS             string               `json:"orig_tls"`
	OriginHost          *string              `json:"origin_host"`
	OriginPort          int                  `json:"origin_port"`
	TunnelInternalHosts []TunnelInternalHost `json:"tunnel_internal_hosts"`
	Servers             []Server             `json:"servers"`

	POP       string `json:"pop"`
	POPName   string `json:"popName"`
	POPRegion string `json:"popRegion"`

	AuthType    int     `json:"auth_type"`
	Cert        *string `json:"cert"`
	AuthEnabled string  `json:"auth_enabled"`
	SSLCACert   string  `json:"ssl_ca_cert"`

	AppDeployed    bool    `json:"app_deployed"`
	AppOperational int     `json:"app_operational"`
	AppStatus      int     `json:"app_status"`
	CName          *string `json:"cname"`
	Status         int     `json:"status"`

	AppCategory AppCategory `json:"app_category"`

	UUIDURL string `json:"uuid_url"`

	TLSSuiteName           *string `json:"tls_suite_name"`
	AppProfileID           *string `json:"app_profile_id"`
	RDPVersion             string  `json:"rdp_version"`
	SupportedClientVersion int     `json:"supported_client_version"`

	SAML              bool        `json:"saml"`
	SAMLSettings      []SAMLConfig `json:"saml_settings,omitempty"`
	Oidc              bool        `json:"oidc"`
	OIDCSettings      *OIDCConfig `json:"oidc_settings,omitempty"`
	FQDNBridgeEnabled bool        `json:"fqdn_bridge_enabled"`
	WSFED             bool        `json:"wsfed"`
	WSFEDSettings     []WSFEDConfig `json:"wsfed_settings,omitempty"`
}

func (app *Application) FromResponse(ar *ApplicationResponse) {
	app.Name = ar.Name
	if ar.Description != nil {
		app.Description = ar.Description
	}
	app.AppProfile = ar.AppProfile
	app.AppType = ar.AppType
	app.ClientAppMode = ar.ClientAppMode

	if ar.Host != nil {
		app.Host = ar.Host
	}
	app.BookmarkURL = ar.BookmarkURL
	if ar.AppLogo != nil {
		app.AppLogo = ar.AppLogo
	}
	app.OrigTLS = ar.OrigTLS
	if ar.OriginHost != nil {
		app.OriginHost = ar.OriginHost
	}

	app.OriginPort = ar.OriginPort
	app.TunnelInternalHosts = ar.TunnelInternalHosts
	app.Servers = ar.Servers

	app.POP = ar.POP
	app.POPName = ar.POPName
	app.POPRegion = ar.POPRegion

	app.AuthType = ar.AuthType
	if ar.Cert != nil {
		app.Cert = ar.Cert
	}
	app.AuthEnabled = ar.AuthEnabled
	app.SSLCACert = ar.SSLCACert

	app.AppDeployed = ar.AppDeployed
	app.AppOperational = ar.AppOperational
	app.AppStatus = ar.AppStatus
	if ar.CName != nil {
		app.CName = ar.CName
	}
	app.Status = ar.Status
	app.AppCategory = ar.AppCategory

	app.UUIDURL = ar.UUIDURL
	if ar.TLSSuiteName != nil {
		app.TLSSuiteName = ar.TLSSuiteName
	}
	if ar.AppProfileID != nil {
		app.AppProfileID = ar.AppProfileID
	}
	app.RDPVersion = ar.RDPVersion
	app.SupportedClientVersion = ar.SupportedClientVersion

	app.SAML = ar.SAML
	app.SAMLSettings = ar.SAMLSettings
	app.Oidc = ar.Oidc
	app.FQDNBridgeEnabled = ar.FQDNBridgeEnabled
	app.WSFED = ar.WSFED
}

func (app *Application) UpdateG2O(ec *EaaClient) (*G2O_Response, error) {
	ec.Logger.Info("updateG2O")
	apiURL := fmt.Sprintf("%s://%s/%s/%s/g2o", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)

	var g2oResp G2O_Response
	g2ohttpResp, err := ec.SendAPIRequest(apiURL, "POST", nil, &g2oResp, false)
	if err != nil {
		ec.Logger.Error("g2o request failed. err: ", err)
		return nil, err
	}
	if g2ohttpResp.StatusCode < http.StatusOK || g2ohttpResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(g2ohttpResp)
		g2oErrMsg := fmt.Errorf("%w: %s", ErrAppUpdate, desc)

		ec.Logger.Error("g2o request failed. g2ohttpResp.StatusCode: desc: ", g2ohttpResp.StatusCode, desc)
		return nil, g2oErrMsg
	}
	return &g2oResp, nil
}

func (app *Application) UpdateEdgeAuthentication(ec *EaaClient) (*EdgeAuth_Response, error) {
	ec.Logger.Info("UpdateEdgeAuthentication")
	apiURL := fmt.Sprintf("%s://%s/%s/%s/edgekey", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)

	var edgeAuthResp EdgeAuth_Response
	edgeAuthhttpResp, err := ec.SendAPIRequest(apiURL, "POST", nil, &edgeAuthResp, false)
	if err != nil {
		ec.Logger.Error("edge auth request failed. err: ", err)
		return nil, err
	}
	if edgeAuthhttpResp.StatusCode < http.StatusOK || edgeAuthhttpResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(edgeAuthhttpResp)
		edgeuthErrMsg := fmt.Errorf("%w: %s", ErrAppUpdate, desc)

		ec.Logger.Error("edge authentication cookie request failed. edgeAuthhttpResp.StatusCode: desc: ", edgeAuthhttpResp.StatusCode, desc)
		return nil, edgeuthErrMsg
	}
	return &edgeAuthResp, nil
}

func (app *Application) DeployApplication(ec *EaaClient) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s/deploy", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)
	data := map[string]interface{}{
		"deploy_note": "deploying the app managed through terraform",
	}
	deployResp, err := ec.SendAPIRequest(apiURL, "POST", data, nil, false)
	if err != nil {
		return err
	}

	if deployResp.StatusCode < http.StatusOK || deployResp.StatusCode >= http.StatusMultipleChoices {
		return ErrDeploy
	}
	return nil
}

func (app *Application) DeleteApplication(ec *EaaClient) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)

	deleteResp, err := ec.SendAPIRequest(apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return err
	}

	if deleteResp.StatusCode < http.StatusOK || deleteResp.StatusCode >= http.StatusMultipleChoices {
		return ErrAppDelete
	}
	return nil
}

type ApplicationUpdateRequest struct {
	Application
	AdvancedSettings AdvancedSettings_Complete `json:"advanced_settings"`
	Domain           string                    `json:"domain"`
	SAMLSettings     []SAMLConfig              `json:"saml_settings,omitempty"`
	WSFEDSettings    []WSFEDConfig             `json:"wsfed_settings,omitempty"`
	OIDCSettings     *OIDCConfig               `json:"oidc_settings,omitempty"`
}

func (appUpdateReq *ApplicationUpdateRequest) UpdateAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	ec.Logger.Info("updating application")
	appUpdateReq.TunnelInternalHosts = []TunnelInternalHost{}
	if tunnelInternalHosts, ok := d.GetOk("tunnel_internal_hosts"); ok {
		if tunnelInternalHostsList, ok := tunnelInternalHosts.([]interface{}); ok {
			for _, th := range tunnelInternalHostsList {
				if thData, ok := th.(map[string]interface{}); ok {
					tunnelInternalHost := TunnelInternalHost{}
					if h, ok := thData["host"].(string); ok {
						tunnelInternalHost.Host = h
					}
					if pr, ok := thData["port_range"].(string); ok {
						tunnelInternalHost.PortRange = pr
					}
					if pt, ok := thData["proto_type"].(int); ok {
						tunnelInternalHost.ProtoType = pt
					}
					appUpdateReq.TunnelInternalHosts = append(appUpdateReq.TunnelInternalHosts, tunnelInternalHost)
				}
			}
		}
	}

	if ac, ok := d.GetOk("app_category"); ok {
		if acValue, ok := ac.(string); ok {

			if acValue != "" {
				uuid, err := GetAppCategoryUuid(ec, acValue)
				if err == nil {
					category := AppCategory{}
					category.Name = acValue
					category.UUID_URL = uuid
					appUpdateReq.AppCategory = category
				}
			}
		}
	}

	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		if advSettingsList, ok := advSettingsData.([]interface{}); ok {
			if advSettingsList != nil {
				if len(advSettingsList) > 0 {
					if advSettingsData, ok := advSettingsList[0].(map[string]interface{}); ok {

						advSettings := AdvancedSettings{}

						if isSSL, ok := advSettingsData["is_ssl_verification_enabled"].(string); ok {
							advSettings.IsSSLVerificationEnabled = isSSL
						}
						if internal_hostname, ok := advSettingsData["internal_hostname"].(string); ok {
							advSettings.InternalHostname = &internal_hostname
						}
						if internal_host_port, ok := advSettingsData["internal_host_port"].(string); ok {
							advSettings.InternalHostPort = internal_host_port
						}
						if wildcard_internal_hostname, ok := advSettingsData["wildcard_internal_hostname"].(string); ok {
							advSettings.WildcardInternalHostname = wildcard_internal_hostname
						}
						if ip_access_allow, ok := advSettingsData["ip_access_allow"].(string); ok {
							advSettings.IPAccessAllow = ip_access_allow
						}

						if x_wapp_read_timeout, ok := advSettingsData["x_wapp_read_timeout"].(string); ok {
							advSettings.XWappReadTimeout = x_wapp_read_timeout
						}
						if icr, ok := advSettingsData["ignore_cname_resolution"].(string); ok {
							advSettings.IgnoreCnameResolution = icr
						}
						if g2o, ok := advSettingsData["g2o_enabled"].(string); ok {
							advSettings.G2OEnabled = g2o
							if g2o == STR_TRUE {

								g2oResp, err := appUpdateReq.UpdateG2O(ec)
								if err != nil {
									ec.Logger.Error("g2o request failed. err: ", err)
									return err
								}
								advSettings.G2OEnabled = STR_TRUE
								advSettings.G2OKey = &g2oResp.G2OKey
								advSettings.G2ONonce = &g2oResp.G2ONonce

							}
						}
						if edgeAuth, ok := advSettingsData["edge_authentication_enabled"].(string); ok {
							advSettings.EdgeAuthenticationEnabled = edgeAuth
							if edgeAuth == STR_TRUE {

								edgeAuthResp, err := appUpdateReq.UpdateEdgeAuthentication(ec)
								if err != nil {
									ec.Logger.Error("edge auth cookie request failed. err: ", err)
									return err
								}
								advSettings.EdgeAuthenticationEnabled = STR_TRUE
								advSettings.EdgeCookieKey = &edgeAuthResp.EdgeCookieKey
								advSettings.SlaObjectUrl = &edgeAuthResp.SlaObjectUrl
							}
						}
						if websocket_enabled, ok := advSettingsData["websocket_enabled"].(string); ok {
							advSettings.WebSocketEnabled = websocket_enabled
						}
						if sticky_agent, ok := advSettingsData["sticky_agent"].(string); ok {
							advSettings.StickyAgent = sticky_agent
						}

						if app_cookie_domain, ok := advSettingsData["app_cookie_domain"].(string); ok {
							if app_cookie_domain != "" {
								advSettings.AppCookieDomain = &app_cookie_domain
							}
						}
						if logout_url, ok := advSettingsData["logout_url"].(string); ok {
							if logout_url != "" {
								advSettings.LogoutURL = &logout_url
							}
						}
						if sentry_redirect_401, ok := advSettingsData["sentry_redirect_401"].(string); ok {
							advSettings.SentryRedirect401 = sentry_redirect_401
						}
						var customHeaders []CustomHeader

						if headersRaw, ok := advSettingsData["custom_headers"]; ok {
							if chList, ok := headersRaw.([]interface{}); ok {
								for _, ch := range chList {
									if headerMap, ok := ch.(map[string]interface{}); ok {
										customHeader := CustomHeader{}
										// Safely extract strings if present
										if val, ok := headerMap["attribute_type"].(string); ok {
											customHeader.AttributeType = val
											if val == "custom" {
												if val, ok := headerMap["attribute"].(string); ok {
													customHeader.Attribute = val
												}
											} else {
												customHeader.Attribute = ""
											}
										}
										if val, ok := headerMap["header"].(string); ok {
											customHeader.Header = val
										}
										if customHeader.AttributeType != "" {
											customHeaders = append(customHeaders, customHeader)
										}
									}
								}
								advSettings.CustomHeaders = customHeaders
							}
						}
						if allow_cors, ok := advSettingsData["allow_cors"].(string); ok {
							advSettings.AllowCORS = allow_cors
							if allow_cors == STR_TRUE {
								if cors_origin_list, ok := advSettingsData["cors_origin_list"].(string); ok {
									advSettings.CORSOriginList = cors_origin_list
								}
								if cors_method_list, ok := advSettingsData["cors_method_list"].(string); ok {
									advSettings.CORSMethodList = cors_method_list
								}
								if cors_header_list, ok := advSettingsData["cors_header_list"].(string); ok {
									advSettings.CORSHeaderList = cors_header_list
								}
								if cors_support_credential, ok := advSettingsData["cors_support_credential"].(string); ok {
									advSettings.CORSSupportCredential = cors_support_credential
								}
								if cors_max_age, ok := advSettingsData["cors_max_age"].(int); ok {
									advSettings.CORSMaxAge = strconv.Itoa(cors_max_age)
								}
							}
						}

						// Handle app_auth field
						if app_auth, ok := advSettingsData["app_auth"].(string); ok {
							// Handle special authentication types that require setting boolean flags
							switch app_auth {
							case "SAML2.0":
								// For SAML2.0, set app_auth to "none" in payload
								advSettings.AppAuth = "none"
								appUpdateReq.SAML = true
								appUpdateReq.Oidc = false
								appUpdateReq.WSFED = false
							case "oidc", "OpenID Connect 1.0":
								// For oidc, set app_auth to "oidc" in payload and oidc = true
								advSettings.AppAuth = "oidc"
								appUpdateReq.SAML = false
								appUpdateReq.Oidc = true
								appUpdateReq.WSFED = false
							case "wsfed", "WS-Federation":
								// For wsfed, include app_auth in payload
								advSettings.AppAuth = "none"
								appUpdateReq.SAML = false
								appUpdateReq.Oidc = false
								appUpdateReq.WSFED = true
							default:
								// For "none", "kerberos", "basic", "NTLMv1", "NTLMv2", include app_auth in payload
								advSettings.AppAuth = app_auth
								appUpdateReq.SAML = false
								appUpdateReq.Oidc = false
								appUpdateReq.WSFED = false
							}
						}

						// Handle wapp_auth field
						if wapp_auth, ok := advSettingsData["wapp_auth"].(string); ok {
							advSettings.WappAuth = wapp_auth
						} else {
							// Default to "form" if not provided
							advSettings.WappAuth = "form"
						}

						// Handle JWT-specific fields
						if jwt_issuers, ok := advSettingsData["jwt_issuers"].(string); ok {
							advSettings.JWTIssuers = jwt_issuers
						}
						if jwt_audience, ok := advSettingsData["jwt_audience"].(string); ok {
							advSettings.JWTAudience = jwt_audience
						}
						if jwt_grace_period, ok := advSettingsData["jwt_grace_period"].(string); ok {
							advSettings.JWTGracePeriod = jwt_grace_period
						} else {
							// Default to "60" if not provided
							advSettings.JWTGracePeriod = "60"
						}
						if jwt_return_option, ok := advSettingsData["jwt_return_option"].(string); ok {
							advSettings.JWTReturnOption = jwt_return_option
						} else {
							// Default to "401" if not provided
							advSettings.JWTReturnOption = "401"
						}
						if jwt_username, ok := advSettingsData["jwt_username"].(string); ok {
							advSettings.JWTUsername = jwt_username
						}
						if jwt_return_url, ok := advSettingsData["jwt_return_url"].(string); ok {
							advSettings.JWTReturnURL = jwt_return_url
						}

						// Handle Kerberos-specific fields
						if app_auth_domain, ok := advSettingsData["app_auth_domain"].(string); ok {
							advSettings.AppAuthDomain = app_auth_domain
						}
						if app_client_cert_auth, ok := advSettingsData["app_client_cert_auth"].(string); ok {
							advSettings.AppClientCertAuth = app_client_cert_auth
						}
						if forward_ticket_granting_ticket, ok := advSettingsData["forward_ticket_granting_ticket"].(string); ok {
							advSettings.ForwardTicketGrantingTicket = forward_ticket_granting_ticket
						}
						if keytab, ok := advSettingsData["keytab"].(string); ok {
							advSettings.Keytab = keytab
						}
						if service_principal_name, ok := advSettingsData["service_principal_name"].(string); ok {
							advSettings.ServicePrincipalName = service_principal_name
						}

						UpdateAdvancedSettings(&appUpdateReq.AdvancedSettings, advSettings)

						// appUpdateReq.AdvancedSettings = advSettings
					}
				}
			}
		}

		// Handle SAML settings - always create structure when app_auth = "SAML2.0"
		var samlConfigs []SAMLConfig
		
		if samlSettingsData, ok := d.GetOk("saml_settings"); ok {
			// User provided saml_settings - use their values
			samlSettingsList := samlSettingsData.([]interface{})
			if len(samlSettingsList) > 0 {
				for _, samlSetting := range samlSettingsList {
					samlSettings := samlSetting.(map[string]interface{})
					
					samlConfig := SAMLConfig{}

					// Process SP (Service Provider) settings
					if spData, ok := samlSettings["sp"].([]interface{}); ok && len(spData) > 0 {
						sp := spData[0].(map[string]interface{})
						
						spConfig := SPConfig{}

						// Handle mandatory fields - always include them
						if entityID, ok := sp["entity_id"].(string); ok {
							spConfig.EntityID = entityID
						} else {
							spConfig.EntityID = "" // default value
						}
						if acsURL, ok := sp["acs_url"].(string); ok {
							spConfig.ACSURL = acsURL
						} else {
							spConfig.ACSURL = "" // default value
						}
						if sloURL, ok := sp["slo_url"].(string); ok {
							spConfig.SLOURL = sloURL
						} else {
							spConfig.SLOURL = "" // default value
						}
						if reqBind, ok := sp["req_bind"].(string); ok {
							spConfig.ReqBind = reqBind
						} else {
							spConfig.ReqBind = "redirect" // default value
						}
						if metadata, ok := sp["metadata"].(string); ok {
							spConfig.Metadata = metadata
						}
						if defaultRelayState, ok := sp["default_relay_state"].(string); ok && defaultRelayState != "" {
							spConfig.DefaultRelayState = &defaultRelayState
						}
						// default_relay_state remains nil if not provided (null in JSON)
						if forceAuth, ok := sp["force_auth"].(bool); ok {
							spConfig.ForceAuth = forceAuth
						} else {
							spConfig.ForceAuth = false // default value
						}
						if reqVerify, ok := sp["req_verify"].(bool); ok {
							spConfig.ReqVerify = reqVerify
						} else {
							spConfig.ReqVerify = false // default value
						}
						if signCert, ok := sp["sign_cert"].(string); ok {
							spConfig.SignCert = signCert
						} else {
							spConfig.SignCert = "" // default value
						}
						if respEncr, ok := sp["resp_encr"].(bool); ok {
							spConfig.RespEncr = respEncr
						} else {
							spConfig.RespEncr = false // default value
						}
						if encrCert, ok := sp["encr_cert"].(string); ok {
							spConfig.EncrCert = encrCert
						} else {
							spConfig.EncrCert = "" // default value
						}
						if encrAlgo, ok := sp["encr_algo"].(string); ok {
							spConfig.EncrAlgo = encrAlgo
						} else {
							spConfig.EncrAlgo = "aes256-cbc" // default value
						}
						if sloReqVerify, ok := sp["slo_req_verify"].(bool); ok {
							spConfig.SLOReqVerify = sloReqVerify
						} else {
							spConfig.SLOReqVerify = true // default value
						}
						if dstURL, ok := sp["dst_url"].(string); ok {
							spConfig.DSTURL = dstURL
						} else {
							spConfig.DSTURL = "" // default value
						}
						if sloBind, ok := sp["slo_bind"].(string); ok {
							spConfig.SLOBind = sloBind
						} else {
							spConfig.SLOBind = "post" // default value
						}

						samlConfig.SP = spConfig
					}

					// Process IDP (Identity Provider) settings
					if idpData, ok := samlSettings["idp"].([]interface{}); ok && len(idpData) > 0 {
						idp := idpData[0].(map[string]interface{})
						
						idpConfig := IDPConfig{}

						// Handle mandatory fields - always include them
						if entityID, ok := idp["entity_id"].(string); ok {
							idpConfig.EntityID = entityID
						} else {
							idpConfig.EntityID = "" // default value
						}
						if metadata, ok := idp["metadata"].(string); ok {
							idpConfig.Metadata = metadata
						} else {
							idpConfig.Metadata = "" // default value
						}
						if signCert, ok := idp["sign_cert"].(string); ok {
							idpConfig.SignCert = signCert
						} else {
							idpConfig.SignCert = "" // default value
						}
						if signKey, ok := idp["sign_key"].(string); ok {
							idpConfig.SignKey = signKey
						} else {
							idpConfig.SignKey = "" // default value
						}
						if selfSigned, ok := idp["self_signed"].(bool); ok {
							idpConfig.SelfSigned = selfSigned
						} else {
							idpConfig.SelfSigned = true // default value
						}
						if signAlgo, ok := idp["sign_algo"].(string); ok {
							idpConfig.SignAlgo = signAlgo
						} else {
							idpConfig.SignAlgo = "SHA256" // default value
						}
						if respBind, ok := idp["resp_bind"].(string); ok {
							idpConfig.RespBind = respBind
						} else {
							idpConfig.RespBind = "post" // default value
						}
						if sloURL, ok := idp["slo_url"].(string); ok {
							idpConfig.SLOURL = sloURL
						} else {
							idpConfig.SLOURL = "" // default value
						}
						if ecpIsEnabled, ok := idp["ecp_enable"].(bool); ok {
							idpConfig.ECPIsEnabled = ecpIsEnabled
						} else {
							idpConfig.ECPIsEnabled = false // default value
						}
						if ecpRespSignature, ok := idp["ecp_resp_signature"].(bool); ok {
							idpConfig.ECPRespSignature = ecpRespSignature
						} else {
							idpConfig.ECPRespSignature = false // default value
						}

						samlConfig.IDP = idpConfig
					}

					// Process Subject settings
					if subjectData, ok := samlSettings["subject"].([]interface{}); ok && len(subjectData) > 0 {
						subject := subjectData[0].(map[string]interface{})
						
						subjectConfig := SubjectConfig{}

						if fmt, ok := subject["fmt"].(string); ok {
							subjectConfig.Fmt = fmt
						} else {
							subjectConfig.Fmt = "email" // default value
						}
						if src, ok := subject["src"].(string); ok {
							subjectConfig.Src = src
						} else {
							subjectConfig.Src = "user.email" // default value
						}
						if val, ok := subject["val"].(string); ok {
							subjectConfig.Val = val
						}
						if rule, ok := subject["rule"].(string); ok {
							subjectConfig.Rule = rule
						}

						samlConfig.Subject = subjectConfig
					}

					// Process Attrmap settings
					if attrmapData, ok := samlSettings["attrmap"].([]interface{}); ok {
						var attrMappings []AttrMapping
						
						// Process each attrmap item
						for _, attrItem := range attrmapData {
							if attrMap, ok := attrItem.(map[string]interface{}); ok {
								attrMapping := AttrMapping{}
								
								if name, ok := attrMap["name"].(string); ok {
									attrMapping.Name = name
								}
								if fname, ok := attrMap["fname"].(string); ok {
									attrMapping.Fname = fname
								}
								if fmt, ok := attrMap["fmt"].(string); ok {
									attrMapping.Fmt = fmt
								}
								if val, ok := attrMap["val"].(string); ok {
									attrMapping.Val = val
								}
								if src, ok := attrMap["src"].(string); ok {
									attrMapping.Src = src
								}
								if rule, ok := attrMap["rule"].(string); ok {
									attrMapping.Rule = rule
								}
								
								attrMappings = append(attrMappings, attrMapping)
							}
						}

						samlConfig.Attrmap = attrMappings
					}

					samlConfigs = append(samlConfigs, samlConfig)
				}
			}
		} else if appUpdateReq.SAML { // This condition ensures it only runs if app_auth was SAML2.0
			// No saml_settings provided but app_auth = "SAML2.0" - create default structure
			// This ensures mandatory SAML fields are always in the payload
			defaultSAMLConfig := SAMLConfig{
				SP: SPConfig{
					EntityID:     "",
					ACSURL:       "",
					SLOURL:       "",
					ReqBind:      "redirect",
					ForceAuth:    false,
					ReqVerify:    false,
					SignCert:     "",
					RespEncr:     false,
					EncrCert:     "",
					EncrAlgo:     "aes256-cbc",
					SLOReqVerify: true,
					DSTURL:       "",
					SLOBind:      "post",
				},
				IDP: IDPConfig{
					EntityID:         "",
					Metadata:         "",
					SignCert:         "",
					SignKey:          "",
					SelfSigned:       true,
					SignAlgo:         "SHA256",
					RespBind:         "post",
					SLOURL:           "",
					ECPIsEnabled:     false,
					ECPRespSignature: false,
				},
				Subject: SubjectConfig{
					Fmt: "email",
					Src: "user.email",
				},
				Attrmap: []AttrMapping{},
			}

			samlConfigs = append(samlConfigs, defaultSAMLConfig)
		}

		// Set the SAML settings in the application update request if we have any
		if len(samlConfigs) > 0 {
			appUpdateReq.SAMLSettings = samlConfigs
		}
	}

	// Handle WS-Federation settings - always create structure when app_auth = "wsfed"
	var wsfedConfigs []WSFEDConfig
	
	if wsfedSettingsData, ok := d.GetOk("wsfed_settings"); ok {
		// User provided wsfed_settings - use their values
		wsfedSettingsList := wsfedSettingsData.([]interface{})
		if len(wsfedSettingsList) > 0 {
			for _, wsfedSetting := range wsfedSettingsList {
				wsfedSettings := wsfedSetting.(map[string]interface{})
				
				wsfedConfig := WSFEDConfig{}

				// Process SP (Service Provider) settings
				if spData, ok := wsfedSettings["sp"].([]interface{}); ok && len(spData) > 0 {
					sp := spData[0].(map[string]interface{})
					
					spConfig := WSFEDSPConfig{}

					// Handle mandatory fields - always include them
					if entityID, ok := sp["entity_id"].(string); ok {
						spConfig.EntityID = entityID
					} else {
						spConfig.EntityID = "" // default value
					}
					if sloURL, ok := sp["slo_url"].(string); ok {
						spConfig.SLOURL = sloURL
					} else {
						spConfig.SLOURL = "" // default value
					}
					if dstURL, ok := sp["dst_url"].(string); ok {
						spConfig.DSTURL = dstURL
					} else {
						spConfig.DSTURL = "" // default value
					}
					if respBind, ok := sp["resp_bind"].(string); ok {
						spConfig.RespBind = respBind
					} else {
						spConfig.RespBind = "post" // default value
					}
					if tokenLife, ok := sp["token_life"].(int); ok {
						spConfig.TokenLife = tokenLife
					} else {
						spConfig.TokenLife = 3600 // default value
					}
					if encrAlgo, ok := sp["encr_algo"].(string); ok {
						spConfig.EncrAlgo = encrAlgo
					} else {
						spConfig.EncrAlgo = "aes256-cbc" // default value
					}

					wsfedConfig.SP = spConfig
				}

				// Process IDP (Identity Provider) settings
				if idpData, ok := wsfedSettings["idp"].([]interface{}); ok && len(idpData) > 0 {
					idp := idpData[0].(map[string]interface{})
					
					idpConfig := WSFEDIDPConfig{}

					if entityID, ok := idp["entity_id"].(string); ok {
						idpConfig.EntityID = entityID
					} else {
						idpConfig.EntityID = "" // default value
					}
					if signAlgo, ok := idp["sign_algo"].(string); ok {
						idpConfig.SignAlgo = signAlgo
					} else {
						idpConfig.SignAlgo = "SHA256" // default value
					}
					if signCert, ok := idp["sign_cert"].(string); ok {
						idpConfig.SignCert = signCert
					} else {
						idpConfig.SignCert = "" // default value
					}
					if signKey, ok := idp["sign_key"].(string); ok {
						idpConfig.SignKey = signKey
					} else {
						idpConfig.SignKey = "" // default value
					}
					if selfSigned, ok := idp["self_signed"].(bool); ok {
						idpConfig.SelfSigned = selfSigned
					} else {
						idpConfig.SelfSigned = true // default value
					}

					wsfedConfig.IDP = idpConfig
				}

				// Process Subject settings
				if subjectData, ok := wsfedSettings["subject"].([]interface{}); ok && len(subjectData) > 0 {
					subject := subjectData[0].(map[string]interface{})
					
					subjectConfig := WSFEDSubjectConfig{}

					if fmt, ok := subject["fmt"].(string); ok {
						subjectConfig.Fmt = fmt
					} else {
						subjectConfig.Fmt = "" // default value
					}
					if customFmt, ok := subject["custom_fmt"].(string); ok {
						subjectConfig.CustomFmt = customFmt
					} else {
						subjectConfig.CustomFmt = "" // default value
					}
					if src, ok := subject["src"].(string); ok {
						subjectConfig.Src = src
					} else {
						subjectConfig.Src = "" // default value
					}
					if val, ok := subject["val"].(string); ok {
						subjectConfig.Val = val
					} else {
						subjectConfig.Val = "" // default value
					}
					if rule, ok := subject["rule"].(string); ok {
						subjectConfig.Rule = rule
					} else {
						subjectConfig.Rule = "" // default value
					}

					wsfedConfig.Subject = subjectConfig
				}

				// Process Attrmap settings
				if attrmapData, ok := wsfedSettings["attrmap"].([]interface{}); ok {
					var attrmapList []WSFEDAttrMapping
					for _, attrmapItem := range attrmapData {
						if attrmap, ok := attrmapItem.(map[string]interface{}); ok {
							attrMapping := WSFEDAttrMapping{}

							if name, ok := attrmap["name"].(string); ok {
								attrMapping.Name = name
							} else {
								attrMapping.Name = "" // default value
							}
							if fmt, ok := attrmap["fmt"].(string); ok {
								attrMapping.Fmt = fmt
							} else {
								attrMapping.Fmt = "" // default value
							}
							if customFmt, ok := attrmap["custom_fmt"].(string); ok {
								attrMapping.CustomFmt = customFmt
							} else {
								attrMapping.CustomFmt = "" // default value
							}
							if val, ok := attrmap["val"].(string); ok {
								attrMapping.Val = val
							} else {
								attrMapping.Val = "" // default value
							}
							if src, ok := attrmap["src"].(string); ok {
								attrMapping.Src = src
							} else {
								attrMapping.Src = "" // default value
							}
							if rule, ok := attrmap["rule"].(string); ok {
								attrMapping.Rule = rule
							} else {
								attrMapping.Rule = "" // default value
							}

							attrmapList = append(attrmapList, attrMapping)
						}
					}
					wsfedConfig.Attrmap = attrmapList
				} else {
					wsfedConfig.Attrmap = []WSFEDAttrMapping{} // empty array
				}

				wsfedConfigs = append(wsfedConfigs, wsfedConfig)
			}
		}
	} else if appUpdateReq.WSFED { // This condition ensures it only runs if app_auth was wsfed
		// No wsfed_settings provided but app_auth = "wsfed" - create default structure
		// This ensures mandatory WS-Federation fields are always in the payload
		defaultWSFEDConfig := WSFEDConfig{
			SP: WSFEDSPConfig{
				EntityID:  "",
				SLOURL:    "",
				DSTURL:    "",
				RespBind:  "post",
				TokenLife: 3600,
				EncrAlgo:  "aes256-cbc",
			},
			IDP: WSFEDIDPConfig{
				EntityID:  "",
				SignAlgo:  "SHA256",
				SignCert:  "",
				SignKey:   "",
				SelfSigned: true,
			},
			Subject: WSFEDSubjectConfig{
				Fmt:       "email",
				CustomFmt: "",
				Src:       "user.email",
				Val:       "",
				Rule:      "",
			},
			Attrmap: []WSFEDAttrMapping{},
		}

		wsfedConfigs = append(wsfedConfigs, defaultWSFEDConfig)
	}

	// Set the WS-Federation settings in the application update request if we have any
	if len(wsfedConfigs) > 0 {
		appUpdateReq.WSFEDSettings = wsfedConfigs
	}

	// Handle OIDC settings - always create structure when app_auth = "oidc"
	var oidcConfig *OIDCConfig

	if oidcSettingsData, ok := d.GetOk("oidc_settings"); ok {
		// User provided oidc_settings - use their values
		oidcSettingsList := oidcSettingsData.([]interface{})
		if len(oidcSettingsList) > 0 {
			oidcSettings := oidcSettingsList[0].(map[string]interface{})

			oidcConfig = &OIDCConfig{}

			// Process OIDC clients
			if oidcClientsData, ok := oidcSettings["oidc_clients"].([]interface{}); ok {
				var oidcClients []OIDCClient
				for _, clientData := range oidcClientsData {
					if client, ok := clientData.(map[string]interface{}); ok {
						oidcClient := OIDCClient{}

						if clientName, ok := client["client_name"].(string); ok {
							oidcClient.ClientName = clientName
						}
						if clientID, ok := client["client_id"].(string); ok {
							oidcClient.ClientID = clientID
						}

						// Process client_secret
						if clientSecretData, ok := client["client_secret"].([]interface{}); ok {
							var clientSecrets []OIDCClientSecret
							for _, secretData := range clientSecretData {
								if secret, ok := secretData.(map[string]interface{}); ok {
									clientSecret := OIDCClientSecret{}
									if timestamp, ok := secret["timestamp"].(string); ok {
										clientSecret.Timestamp = timestamp
									}
									if value, ok := secret["value"].(string); ok {
										clientSecret.Value = value
									}
									clientSecrets = append(clientSecrets, clientSecret)
								}
							}
							oidcClient.ClientSecret = clientSecrets
						}

						// Process response_type
						if responseTypeData, ok := client["response_type"].([]interface{}); ok {
							var responseTypes []string
							for _, rt := range responseTypeData {
								if rtStr, ok := rt.(string); ok {
									responseTypes = append(responseTypes, rtStr)
								}
							}
							oidcClient.ResponseType = responseTypes
						} else {
							oidcClient.ResponseType = []string{"code"} // default
						}

						if implicitGrant, ok := client["implicit_grant"].(bool); ok {
							oidcClient.ImplicitGrant = implicitGrant
						}

						if clientType, ok := client["type"].(string); ok {
							oidcClient.Type = clientType
						}

						// Process redirect_uris
						if redirectURIsData, ok := client["redirect_uris"].([]interface{}); ok {
							var redirectURIs []string
							for _, uri := range redirectURIsData {
								if uriStr, ok := uri.(string); ok {
									redirectURIs = append(redirectURIs, uriStr)
								}
							}
							oidcClient.RedirectURIs = redirectURIs
						}

						// Process javascript_origins
						if jsOriginsData, ok := client["javascript_origins"].([]interface{}); ok {
							var jsOrigins []string
							for _, origin := range jsOriginsData {
								if originStr, ok := origin.(string); ok {
									jsOrigins = append(jsOrigins, originStr)
								}
							}
							oidcClient.JavaScriptOrigins = jsOrigins
						}

						if logoutURL, ok := client["logout_url"].(string); ok {
							oidcClient.LogoutURL = logoutURL
						}

						if logoutSessionRequired, ok := client["logout_session_required"].(bool); ok {
							oidcClient.LogoutSessionRequired = logoutSessionRequired
						}

						// Process post_logout_redirect_uri
						if postLogoutURIsData, ok := client["post_logout_redirect_uri"].([]interface{}); ok {
							var postLogoutURIs []string
							for _, uri := range postLogoutURIsData {
								if uriStr, ok := uri.(string); ok {
									postLogoutURIs = append(postLogoutURIs, uriStr)
								}
							}
							oidcClient.PostLogoutRedirectURI = postLogoutURIs
						}

						if metadata, ok := client["metadata"].(string); ok {
							oidcClient.Metadata = metadata
						}

						// Process claims
						if claimsData, ok := client["claims"].([]interface{}); ok {
							var claims []OIDCClaim
							for _, claimData := range claimsData {
								if claim, ok := claimData.(map[string]interface{}); ok {
									oidcClaim := OIDCClaim{}
									if name, ok := claim["name"].(string); ok {
										oidcClaim.Name = name
									}
									if scope, ok := claim["scope"].(string); ok {
										oidcClaim.Scope = scope
									}
									if val, ok := claim["val"].(string); ok {
										oidcClaim.Val = val
									}
									if src, ok := claim["src"].(string); ok {
										oidcClaim.Src = src
									}
									if rule, ok := claim["rule"].(string); ok {
										oidcClaim.Rule = rule
									}
									claims = append(claims, oidcClaim)
								}
							}
							oidcClient.Claims = claims
						}

						oidcClients = append(oidcClients, oidcClient)
					}
				}
				oidcConfig.OIDCClients = oidcClients
			}
		}
	} else if appUpdateReq.Oidc { // This condition ensures it only runs if app_auth was oidc
		// No oidc_settings provided but app_auth = "oidc" - create empty OIDCConfig
		// This will result in "oidc_settings": {} in the payload
		oidcConfig = &OIDCConfig{
			OIDCClients: []OIDCClient{}, // empty slice
		}
	}

	// Set the OIDC settings in the application update request if we have any
	if oidcConfig != nil {
		appUpdateReq.OIDCSettings = oidcConfig
	}
	appUpdateReq.Servers = []Server{}
	if servers, ok := d.GetOk("servers"); ok {
		if serversList, ok := servers.([]interface{}); ok {
			for _, s := range serversList {
				if sData, ok := s.(map[string]interface{}); ok {
					server := Server{}
					if oh, ok := sData["origin_host"].(string); ok {
						server.OriginHost = oh
					}
					if ot, ok := sData["orig_tls"].(bool); ok {
						server.OrigTLS = ot
					}
					if op, ok := sData["origin_port"].(int); ok {
						server.OriginPort = op
					}
					if opr, ok := sData["origin_protocol"].(string); ok {
						server.OriginProtocol = opr
					}
					appUpdateReq.Servers = append(appUpdateReq.Servers, server)
				}
			}
		}
	}

	if bookmarkURL, ok := d.GetOk("bookmark_url"); ok {
		if bm, ok := bookmarkURL.(string); ok {
			appUpdateReq.BookmarkURL = bm
		}
	}

	if host, ok := d.GetOk("host"); ok {
		if hv, ok := host.(string); ok {
			appUpdateReq.Host = &hv
		}
	}

	if authEnabled, ok := d.GetOk("auth_enabled"); ok {
		if ae, ok := authEnabled.(string); ok {
			appUpdateReq.AuthEnabled = ae
		}
	}

	if popRegion, ok := d.GetOk("popregion"); ok {
		if popregionstr, ok := popRegion.(string); ok {
			appUpdateReq.POPRegion = popregionstr
			if popRegion != "" {
				popname, uuid, err := GetPopUuid(ec, popregionstr)
				if err == nil {
					appUpdateReq.POPName = popname
					appUpdateReq.POP = uuid
				}
			}
		}
	}

	if domain, ok := d.GetOk("domain"); ok {
		if strDomain, ok := domain.(string); ok {
			appDomain := Domain(strDomain)
			value, err := appDomain.ToInt()
			if err != nil {
				ec.Logger.Error("Update Application failed. Domain is invalid")
				return ErrInvalidValue
			}
			appUpdateReq.Domain = strconv.Itoa(value)

			if appDomain == AppDomainCustom {
				if err := processCustomDomain(ec, appUpdateReq, d, ctx); err != nil {
					ec.Logger.Error("Custom domain processing failed: ", err)
					return err
				}
			}
		}
	} else {
		appUpdateReq.Domain = strconv.Itoa(int(APP_DOMAIN_WAPP))
	}

	fmt.Printf("updating application - advanced settings")
	fmt.Printf("%+v\n", appUpdateReq)
	fmt.Printf("%+v\n", appUpdateReq.AdvancedSettings)
	return nil
}
func processCustomDomain(ec *EaaClient, appUpdateReq *ApplicationUpdateRequest, d *schema.ResourceData, ctx context.Context) error {
	ec.Logger.Info("Custom domain")

	// Default certificate type to "self-signed"
	certType := "self_signed"

	// Check if 'cert_type' is specified in the Terraform input
	if cert, ok := d.GetOk("cert_type"); ok {
		if certStr, ok := cert.(string); ok {
			certType = certStr
		} else {
			return fmt.Errorf("cert_type is not a valid string")
		}
	}

	// Convert certificate type to CertType
	appCert := CertType(certType)
	ec.Logger.Info("Certificate type: ", appCert)

	// Check if the certificate type is self-signed
	if appCert == CertSelfSigned {
		// Check if a self-signed certificate exists for the given hostname
		certObj, err := DoesSelfSignedCertExistForHost(ec, *appUpdateReq.Host)
		if err != nil {
			return fmt.Errorf("failed to check self-signed certificate existence: %w", err)
		}

		if certObj != nil {
			// Use existing self-signed certificate
			appUpdateReq.Cert = &certObj.UUIDURL
			ec.Logger.Info("Using existing self-signed certificate: ", appUpdateReq.Cert)
			return nil
		} else {
			ec.Logger.Info("Generating self-signed certificate")
			// Create a new self-signed certificate
			var certReq CreateSelfSignedCertRequest
			certReq.HostName = *appUpdateReq.Host
			certReq.CertType = CERT_TYPE_APP_SSC
			certResp, err := certReq.CreateSelfSignedCertificate(ctx, ec)
			if err != nil {
				return fmt.Errorf("failed to generate self-signed certificate: %w", err)
			}

			// Update application request with the generated certificate
			appUpdateReq.Cert = &certResp.UUIDURL
			ec.Logger.Info("Generated self-signed certificate: ", appUpdateReq.Cert)
			return nil
		}
	}
	if appCert == CertUploaded {
		cert, ok := d.GetOk("cert_name")
		if !ok {
			return fmt.Errorf("uploaded cert name is missing")
		}
		certStr, ok := cert.(string)
		if !ok || certStr == "" {
			return fmt.Errorf("cert_name is not a valid string")
		}

		// Check if the uploaded certificate exists for the given certname
		certObj, err := DoesUploadedCertExist(ec, certStr)
		if err != nil || certObj == nil {
			return fmt.Errorf("the uploaded cert does not exist: %w", err)
		}

		if certObj != nil {
			// Use existing self-signed certificate
			appUpdateReq.Cert = &certObj.UUIDURL
			ec.Logger.Info("using uploaded cert : ", appUpdateReq.Cert)
			return nil
		}
	}

	return nil
}

func (appUpdateReq *ApplicationUpdateRequest) UpdateApplication(ctx context.Context, ec *EaaClient) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, appUpdateReq.UUIDURL)
	ec.Logger.Info("API URL: ", apiURL)
	
	// Log the request payload
	b, _ := json.MarshalIndent(appUpdateReq, "", "  ")
	fmt.Println("=== REQUEST PAYLOAD ===")
	fmt.Println(string(b))
	fmt.Println("=== END REQUEST PAYLOAD ===")

	appUpdResp, err := ec.SendAPIRequest(apiURL, "PUT", appUpdateReq, nil, false)
	if err != nil {
		ec.Logger.Error("update application failed. err: ", err)
		return err
	}
	
	// Log the response
	fmt.Println("=== RESPONSE STATUS ===")
	fmt.Printf("Status Code: %d\n", appUpdResp.StatusCode)
	fmt.Println("=== END RESPONSE STATUS ===")
	
	// Log the response body
	fmt.Println("=== RESPONSE BODY ===")
	bodyBytes, _ := io.ReadAll(appUpdResp.Body)
	fmt.Println(string(bodyBytes))
	fmt.Println("=== END RESPONSE BODY ===")
	
	if appUpdResp.StatusCode < http.StatusOK || appUpdResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(appUpdResp)
		updErrMsg := fmt.Errorf("%w: %s", ErrAppUpdate, desc)

		ec.Logger.Error("update application failed. appUpdResp.StatusCode: desc ", appUpdResp.StatusCode, desc)
		return updErrMsg
	}

	return nil
}

type ApplicationDataModel struct {
	Application
	AdvancedSettings AdvancedSettings `json:"advanced_settings"`
	Domain           int              `json:"domain"`
}

type Server struct {
	OriginHost     string `json:"origin_host"`
	OrigTLS        bool   `json:"orig_tls"`
	OriginPort     int    `json:"origin_port"`
	OriginProtocol string `json:"origin_protocol"`
}

type TunnelInternalHost struct {
	Host      string `json:"host"`
	PortRange string `json:"port_range"`
	ProtoType int    `json:"proto_type"`
}

type AppCategory struct {
	Name     string `json:"name,omitempty"`
	UUID_URL string `json:"uuid_url,omitempty"`
}

type ApplicationResponse struct {
	AdvancedSettings AdvancedSettings_Complete `json:"advanced_settings"`
	AppCategory      AppCategory               `json:"app_category"`

	AppDeployed            bool                 `json:"app_deployed"`
	AppLogo                *string              `json:"app_logo"`
	AppOperational         int                  `json:"app_operational"`
	AppProfile             int                  `json:"app_profile"`
	AppProfileID           *string              `json:"app_profile_id"`
	AppStatus              int                  `json:"app_status"`
	AppType                int                  `json:"app_type"`
	AuthEnabled            string               `json:"auth_enabled"`
	AuthType               int                  `json:"auth_type"`
	BookmarkURL            string               `json:"bookmark_url"`
	Cert                   *string              `json:"cert"`
	ClientAppMode          int                  `json:"client_app_mode"`
	CName                  *string              `json:"cname"`
	CreatedAt              string               `json:"created_at"`
	Description            *string              `json:"description"`
	DomainSuffix           string               `json:"domain_suffix"`
	FailoverPopName        string               `json:"failover_popName"`
	FQDNBridgeEnabled      bool                 `json:"fqdn_bridge_enabled"`
	Host                   *string              `json:"host"`
	ModifiedAt             string               `json:"modified_at"`
	Name                   string               `json:"name"`
	Oidc                   bool                 `json:"oidc"`
	OrigTLS                string               `json:"orig_tls"`
	OriginHost             *string              `json:"origin_host"`
	OriginPort             int                  `json:"origin_port"`
	POP                    string               `json:"pop"`
	POPName                string               `json:"popName"`
	POPRegion              string               `json:"popRegion"`
	RDPVersion             string               `json:"rdp_version"`
	Resource               string               `json:"resource"`
	SAML                   bool                 `json:"saml"`
	SAMLSettings           []SAMLConfig         `json:"saml_settings,omitempty"`
	Servers                []Server             `json:"servers"`
	SSLCACert              string               `json:"ssl_ca_cert"`
	Status                 int                  `json:"status"`
	SupportedClientVersion int                  `json:"supported_client_version"`
	TLSSuiteName           *string              `json:"tls_suite_name"`
	TunnelInternalHosts    []TunnelInternalHost `json:"tunnel_internal_hosts"`
	UUIDURL                string               `json:"uuid_url"` //Id - to do
	WSFED                  bool                 `json:"wsfed"`
	WSFEDSettings          []WSFEDConfig        `json:"wsfed_settings,omitempty"`
	OIDCSettings           *OIDCSettings        `json:"oidc_settings,omitempty"`
}

type ResourceStatus struct {
	HostReachable      bool `json:"host_reachable"`
	DirectoriesStatus  int  `json:"directories_status"`
	OriginHostStatus   int  `json:"origin_host_status"`
	CnameDNSStatus     int  `json:"cname_dns_status"`
	DataAgentStatus    int  `json:"data_agent_status"`
	CertStatus         int  `json:"cert_status"`
	HostDNSStatus      int  `json:"host_dns_status"`
	InternalHostStatus int  `json:"internal_host_status"`
	DialinServerStatus int  `json:"dialin_server_status"`
	PopStatus          int  `json:"pop_status"`
}

type G2O_Response struct {
	G2OEnabled string `json:"g2o_enabled,omitempty"`
	G2ONonce   string `json:"g2o_nonce,omitempty"`
	G2OKey     string `json:"g2o_key,omitempty"`
}

type EdgeAuth_Response struct {
	EdgeCookieKey string `json:"edge_cookie_key,omitempty"`
	SlaObjectUrl  string `json:"sla_object_url,omitempty"`
}

type CustomHeader struct {
	Attribute     string `json:"attribute"`
	AttributeType string `json:"attribute_type"`
	Header        string `json:"header"`
}

type AdvancedSettings struct {
	IsSSLVerificationEnabled  string         `json:"is_ssl_verification_enabled,omitempty"`
	IgnoreCnameResolution     string         `json:"ignore_cname_resolution,omitempty"`
	EdgeAuthenticationEnabled string         `json:"edge_authentication_enabled,omitempty"`
	G2OEnabled                string         `json:"g2o_enabled,omitempty"`
	G2ONonce                  *string        `json:"g2o_nonce,omitempty"`
	G2OKey                    *string        `json:"g2o_key,omitempty"`
	XWappReadTimeout          string         `json:"x_wapp_read_timeout,omitempty"`
	InternalHostname          *string        `json:"internal_hostname,omitempty"`
	InternalHostPort          string         `json:"internal_host_port,omitempty"`
	WildcardInternalHostname  string         `json:"wildcard_internal_hostname,omitempty"`
	IPAccessAllow             string         `json:"ip_access_allow,omitempty"`
	EdgeCookieKey             *string        `json:"edge_cookie_key,omitempty"`
	SlaObjectUrl              *string        `json:"sla_object_url,omitempty"`
	AllowCORS                 string         `json:"allow_cors,omitempty"`
	CORSOriginList            string         `json:"cors_origin_list,omitempty"`
	CORSMethodList            string         `json:"cors_method_list,omitempty"`
	CORSHeaderList            string         `json:"cors_header_list,omitempty"`
	CORSSupportCredential     string         `json:"cors_support_credential,omitempty"`
	CORSMaxAge                string         `json:"cors_max_age,omitempty"`
	WebSocketEnabled          string         `json:"websocket_enabled,omitempty"`
	StickyAgent               string         `json:"sticky_agent,omitempty"`
	AppCookieDomain           *string        `json:"app_cookie_domain,omitempty"`
	LogoutURL                 *string        `json:"logout_url,omitempty"`
	SentryRedirect401         string         `json:"sentry_redirect_401,omitempty"`
	AppAuth                   string         `json:"app_auth,omitempty"`
	WappAuth                  string         `json:"wapp_auth,omitempty"`
	JWTIssuers                string         `json:"jwt_issuers,omitempty"`
	JWTAudience                string         `json:"jwt_audience,omitempty"`
	JWTGracePeriod            string         `json:"jwt_grace_period,omitempty"`
	JWTReturnOption           string         `json:"jwt_return_option,omitempty"`
	JWTUsername                string         `json:"jwt_username,omitempty"`
	JWTReturnURL               string         `json:"jwt_return_url,omitempty"`
	AppAuthDomain             string         `json:"app_auth_domain,omitempty"`
	AppClientCertAuth         string         `json:"app_client_cert_auth,omitempty"`
	ForwardTicketGrantingTicket string       `json:"forward_ticket_granting_ticket,omitempty"`
	Keytab                    string         `json:"keytab,omitempty"`
	ServicePrincipalName      string         `json:"service_principal_name,omitempty"`
	CustomHeaders             []CustomHeader `json:"custom_headers,omitempty"`
}

type AdvancedSettings_Complete struct {
	LoginURL                     *string        `json:"login_url,omitempty"`
	LogoutURL                    *string        `json:"logout_url,omitempty"`
	InternalHostname             *string        `json:"internal_hostname,omitempty"`
	InternalHostPort             string         `json:"internal_host_port,omitempty"`
	WildcardInternalHostname     string         `json:"wildcard_internal_hostname,omitempty"`
	IPAccessAllow                string         `json:"ip_access_allow,omitempty"`
	CookieDomain                 *string        `json:"cookie_domain,omitempty"`
	RequestParameters            *string        `json:"request_parameters,omitempty"`
	LoggingEnabled               string         `json:"logging_enabled,omitempty"`
	LoginTimeout                 string         `json:"login_timeout,omitempty"`
	AppAuth                      string         `json:"app_auth,omitempty"`
	WappAuth                     string         `json:"wapp_auth,omitempty"`
	JWTIssuers                   string         `json:"jwt_issuers,omitempty"`
	JWTAudience                  string         `json:"jwt_audience,omitempty"`
	JWTGracePeriod               string         `json:"jwt_grace_period,omitempty"`
	JWTReturnOption              string         `json:"jwt_return_option,omitempty"`
	JWTUsername                  string         `json:"jwt_username,omitempty"`
	JWTReturnURL                 string         `json:"jwt_return_url,omitempty"`
	SSO                          string         `json:"sso,omitempty"`
	HTTPOnlyCookie               string         `json:"http_only_cookie,omitempty"`
	RequestBodyRewrite           string         `json:"request_body_rewrite,omitempty"`
	IDPIdleExpiry                *string        `json:"idp_idle_expiry,omitempty"`
	IDPMaxExpiry                 *string        `json:"idp_max_expiry,omitempty"`
	HTTPSSSLV3                   string         `json:"https_sslv3,omitempty"`
	SPDYEnabled                  string         `json:"spdy_enabled,omitempty"`
	WebSocketEnabled             string         `json:"websocket_enabled,omitempty"`
	HiddenApp                    string         `json:"hidden_app,omitempty"`
	AppLocation                  *string        `json:"app_location,omitempty"`
	AppCookieDomain              *string        `json:"app_cookie_domain,omitempty"`
	AppAuthDomain                string         `json:"app_auth_domain,omitempty"`
	LoadBalancingMetric          string         `json:"load_balancing_metric,omitempty"`
	HealthCheckType              string         `json:"health_check_type,omitempty"`
	HealthCheckHTTPURL           string         `json:"health_check_http_url,omitempty"`
	HealthCheckHTTPVersion       string         `json:"health_check_http_version,omitempty"`
	HealthCheckHTTPHostHeader    *string        `json:"health_check_http_host_header,omitempty"`
	ProxyBufferSizeKB            string         `json:"proxy_buffer_size_kb,omitempty"`
	SessionSticky                string         `json:"session_sticky,omitempty"`
	SessionStickyCookieMaxAge    string         `json:"session_sticky_cookie_maxage,omitempty"`
	SessionStickyServerCookie    *string        `json:"session_sticky_server_cookie,omitempty"`
	PassPhrase                   *string        `json:"pass_phrase,omitempty"`
	PrivateKey                   *string        `json:"private_key,omitempty"`
	HostKey                      *string        `json:"host_key,omitempty"`
	UserName                     *string        `json:"user_name,omitempty"`
	ExternalCookieDomain         *string        `json:"external_cookie_domain,omitempty"`
	ServicePrincipleName         string         `json:"service_principle_name,omitempty"`
	ServerCertValidate           string         `json:"server_cert_validate,omitempty"`
	IgnoreCnameResolution        string         `json:"ignore_cname_resolution,omitempty"`
	SSHAuditEnabled              string         `json:"ssh_audit_enabled,omitempty"`
	MFA                          string         `json:"mfa,omitempty"`
	RefreshStickyCookie          string         `json:"refresh_sticky_cookie,omitempty"`
	AppServerReadTimeout         string         `json:"app_server_read_timeout,omitempty"`
	IdleConnFloor                string         `json:"idle_conn_floor,omitempty"`
	IdleConnCeil                 string         `json:"idle_conn_ceil,omitempty"`
	IdleConnStep                 string         `json:"idle_conn_step,omitempty"`
	IdleCloseTimeSeconds         string         `json:"idle_close_time_seconds,omitempty"`
	RateLimit                    string         `json:"rate_limit,omitempty"`
	AuthenticatedServerReqLimit  string         `json:"authenticated_server_request_limit,omitempty"`
	AnonymousServerReqLimit      string         `json:"anonymous_server_request_limit,omitempty"`
	AuthenticatedServerConnLimit string         `json:"authenticated_server_conn_limit,omitempty"`
	AnonymousServerConnLimit     string         `json:"anonymous_server_conn_limit,omitempty"`
	ServerRequestBurst           string         `json:"server_request_burst,omitempty"`
	HealthCheckRise              string         `json:"health_check_rise,omitempty"`
	HealthCheckFall              string         `json:"health_check_fall,omitempty"`
	HealthCheckTimeout           string         `json:"health_check_timeout,omitempty"`
	HealthCheckInterval          string         `json:"health_check_interval,omitempty"`
	KerberosNegotiateOnce        string         `json:"kerberos_negotiate_once,omitempty"`
	InjectAjaxJavascript         string         `json:"inject_ajax_javascript,omitempty"`
	SentryRedirect401            string         `json:"sentry_redirect_401,omitempty"`
	ProxyDisableClipboard        string         `json:"proxy_disable_clipboard,omitempty"`
	PreauthEnforceURL            string         `json:"preauth_enforce_url,omitempty"`
	ForceMFA                     string         `json:"force_mfa,omitempty"`
	IgnoreBypassMFA              string         `json:"ignore_bypass_mfa,omitempty"`
	StickyAgent                  string         `json:"sticky_agent,omitempty"`
	SaaSEnabled                  string         `json:"saas_enabled,omitempty"`
	AllowCORS                    string         `json:"allow_cors,omitempty"`
	CORSOriginList               string         `json:"cors_origin_list,omitempty"`
	CORSMethodList               string         `json:"cors_method_list,omitempty"`
	CORSHeaderList               string         `json:"cors_header_list,omitempty"`
	CORSSupportCredential        string         `json:"cors_support_credential,omitempty"`
	CORSMaxAge                   string         `json:"cors_max_age,omitempty"`
	KeepaliveEnable              string         `json:"keepalive_enable,omitempty"`
	KeepaliveConnectionPool      string         `json:"keepalive_connection_pool,omitempty"`
	KeepaliveTimeout             string         `json:"keepalive_timeout,omitempty"`
	KeyedKeepaliveEnable         string         `json:"keyed_keepalive_enable,omitempty"`
	Keytab                       string         `json:"keytab,omitempty"`
	EdgeCookieKey                string         `json:"edge_cookie_key,omitempty"`
	SLAObjectURL                 string         `json:"sla_object_url,omitempty"`
	ForwardTicketGrantingTicket  string         `json:"forward_ticket_granting_ticket,omitempty"`
	EdgeAuthenticationEnabled    string         `json:"edge_authentication_enabled,omitempty"`
	HSTSage                      string         `json:"hsts_age,omitempty"`
	RDPInitialProgram            *string        `json:"rdp_initial_program,omitempty"`
	RemoteSparkMapClipboard      string         `json:"remote_spark_mapClipboard,omitempty"`
	RDPLegacyMode                string         `json:"rdp_legacy_mode,omitempty"`
	RemoteSparkAudio             string         `json:"remote_spark_audio,omitempty"`
	RemoteSparkMapPrinter        string         `json:"remote_spark_mapPrinter,omitempty"`
	RemoteSparkPrinter           string         `json:"remote_spark_printer,omitempty"`
	RemoteSparkMapDisk           string         `json:"remote_spark_mapDisk,omitempty"`
	RemoteSparkDisk              string         `json:"remote_spark_disk,omitempty"`
	RemoteSparkRecording         string         `json:"remote_spark_recording,omitempty"`
	ClientCertAuth               string         `json:"client_cert_auth,omitempty"`
	ClientCertUserParam          string         `json:"client_cert_user_param,omitempty"`
	G2OEnabled                   string         `json:"g2o_enabled,omitempty"`
	G2ONonce                     *string        `json:"g2o_nonce,omitempty"`
	G2OKey                       *string        `json:"g2o_key,omitempty"`
	RDPTLS1                      string         `json:"rdp_tls1,omitempty"`
	DomainExceptionList          string         `json:"domain_exception_list,omitempty"`
	Acceleration                 string         `json:"acceleration,omitempty"`
	OffloadOnPremiseTraffic      string         `json:"offload_onpremise_traffic,omitempty"`
	AppClientCertAuth            string         `json:"app_client_cert_auth,omitempty"`
	PreauthConsent               string         `json:"preauth_consent,omitempty"`
	MDCEnable                    string         `json:"mdc_enable,omitempty"`
	SingleHostEnable             string         `json:"single_host_enable,omitempty"`
	SingleHostFQDN               string         `json:"single_host_fqdn,omitempty"`
	SingleHostPath               string         `json:"single_host_path,omitempty"`
	SingleHostContentRW          string         `json:"single_host_content_rw,omitempty"`
	IsSSLVerificationEnabled     string         `json:"is_ssl_verification_enabled,omitempty"`
	SingleHostCookieDomain       string         `json:"single_host_cookie_domain,omitempty"`
	XWappReadTimeout             string         `json:"x_wapp_read_timeout,omitempty"`
	ForceIPRoute                 string         `json:"force_ip_route,omitempty"`
	CustomHeaders                []CustomHeader `json:"custom_headers,omitempty"`
}

type OIDCSettings struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	CertsURI              string `json:"certs_uri"`
	CheckSessionIframe    string `json:"check_session_iframe"`
	DiscoveryURL          string `json:"discovery_url"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	OpenIDMetadata        string `json:"openid_metadata"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// Simple SAML configuration object that matches the API expectation
type SAMLConfig struct {
	SP      SPConfig      `json:"sp"`
	IDP     IDPConfig     `json:"idp"`
	Subject SubjectConfig `json:"subject"`
	Attrmap []AttrMapping `json:"attrmap"`
}

type SPConfig struct {
	EntityID          string  `json:"entity_id"`
	ACSURL            string  `json:"acs_url"`
	SLOURL            string  `json:"slo_url"`
	ReqBind           string  `json:"req_bind"`
	Metadata          string  `json:"metadata"`
	DefaultRelayState *string `json:"default_relay_state,omitempty"`
	ForceAuth         bool    `json:"force_auth"`
	ReqVerify         bool    `json:"req_verify"`
	SignCert          string  `json:"sign_cert"`
	RespEncr          bool    `json:"resp_encr"`
	EncrCert          string  `json:"encr_cert"`
	EncrAlgo          string  `json:"encr_algo"`
	SLOReqVerify      bool    `json:"slo_req_verify"`
	DSTURL            string  `json:"dst_url"`
	SLOBind           string  `json:"slo_bind"`
}

type IDPConfig struct {
	EntityID         string `json:"entity_id"`
	Metadata         string `json:"metadata"`
	SignCert         string `json:"sign_cert"`
	SignKey          string `json:"sign_key"`
	SelfSigned       bool   `json:"self_signed"`
	SignAlgo         string `json:"sign_algo"`
	RespBind         string `json:"resp_bind"`
	SLOURL           string `json:"slo_url"`
	ECPIsEnabled     bool   `json:"ecp_enable"`
	ECPRespSignature bool   `json:"ecp_resp_signature"`
}

type SubjectConfig struct {
	Fmt  string `json:"fmt"`
	Src  string `json:"src"`
	Val  string `json:"val"`
	Rule string `json:"rule"`
}

type AttrMapping struct {
	Name  string `json:"name"`
	Fname string `json:"fname"`
	Fmt   string `json:"fmt"`
	Val   string `json:"val"`
	Src   string `json:"src"`
	Rule  string `json:"rule"`
}

// WS-Federation configuration structs
type WSFEDConfig struct {
	SP      WSFEDSPConfig      `json:"sp"`
	IDP     WSFEDIDPConfig     `json:"idp"`
	Subject WSFEDSubjectConfig `json:"subject"`
	Attrmap []WSFEDAttrMapping `json:"attrmap"`
}

type WSFEDSPConfig struct {
	EntityID  string `json:"entity_id"`
	SLOURL    string `json:"slo_url"`
	DSTURL    string `json:"dst_url"`
	RespBind  string `json:"resp_bind"`
	TokenLife int    `json:"token_life"`
	EncrAlgo  string `json:"encr_algo"`
}

type WSFEDIDPConfig struct {
	EntityID  string `json:"entity_id"`
	SignAlgo  string `json:"sign_algo"`
	SignCert  string `json:"sign_cert"`
	SignKey   string `json:"sign_key"`
	SelfSigned bool  `json:"self_signed"`
}

type WSFEDSubjectConfig struct {
	Fmt       string `json:"fmt"`
	CustomFmt string `json:"custom_fmt"`
	Src       string `json:"src"`
	Val       string `json:"val"`
	Rule      string `json:"rule"`
}

type WSFEDAttrMapping struct {
	Name      string `json:"name"`
	Fmt       string `json:"fmt"`
	CustomFmt string `json:"custom_fmt"`
	Val       string `json:"val"`
	Src       string `json:"src"`
	Rule      string `json:"rule"`
}

// OIDC configuration structs
type OIDCConfig struct {
	OIDCClients []OIDCClient `json:"oidc_clients,omitempty"`
}

type OIDCClient struct {
	ClientName                string                    `json:"client_name"`
	ClientID                  string                    `json:"client_id"`
	ClientSecret              []OIDCClientSecret        `json:"client_secret"`
	ResponseType              []string                  `json:"response_type"`
	ImplicitGrant             bool                      `json:"implicit_grant"`
	Type                      string                    `json:"type"`
	RedirectURIs              []string                  `json:"redirect_uris"`
	JavaScriptOrigins         []string                  `json:"javascript_origins"`
	LogoutURL                 string                    `json:"logout_url"`
	LogoutSessionRequired     bool                      `json:"logout_session_required"`
	PostLogoutRedirectURI     []string                  `json:"post_logout_redirect_uri"`
	Metadata                  string                    `json:"metadata"`
	Claims                    []OIDCClaim               `json:"claims"`
}

type OIDCClientSecret struct {
	Timestamp string `json:"timestamp"`
	Value     string `json:"value"`
}

type OIDCClaim struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Val   string `json:"val"`
	Src   string `json:"src"`
	Rule  string `json:"rule"`
}

// Legacy structs for backward compatibility with response parsing
type SAMLSettings struct {
	Title string       `json:"title"`
	Type  string       `json:"type"`
	Items []SAMLObject `json:"items"`
}

type SAMLObject struct {
	Type       string         `json:"type"`
	Properties SAMLProperties `json:"properties"`
}

type SAMLProperties struct {
	SP      SPMetadata    `json:"sp"`
	IDP     IDPMetadata   `json:"idp"`
	Subject SubjectData   `json:"subject"`
	Attrmap AttrMapSchema `json:"attrmap"`
}

type SPMetadata struct {
	Type       string       `json:"type"`
	Properties SPProperties `json:"properties"`
	Required   []string     `json:"required"`
}

type SPProperties struct {
	EntityID          *string `json:"entity_id,omitempty"`
	ACSURL            *string `json:"acs_url,omitempty"`
	SLOURL            *string `json:"slo_url,omitempty"`
	ReqBind           string  `json:"req_bind"`
	Metadata          *string `json:"metadata,omitempty"`
	DefaultRelayState *string `json:"default_relay_state,omitempty"`
	ForceAuth         bool    `json:"force_auth"`
	ReqVerify         bool    `json:"req_verify"`
	SignCert          *string `json:"sign_cert,omitempty"`
	RespEncr          bool    `json:"resp_encr"`
	EncrCert          *string `json:"encr_cert,omitempty"`
	EncrAlgo          string  `json:"encr_algo"`
	SLOReqVerify      *bool   `json:"slo_req_verify,omitempty"`
	DSTURL            *string `json:"dst_url,omitempty"`
	SLOBind           *string `json:"slo_bind,omitempty"`
}

type IDPMetadata struct {
	Type       string        `json:"type"`
	Properties IDPProperties `json:"properties"`
}

type IDPProperties struct {
	EntityID         string `json:"entity_id"`
	Metadata         string `json:"metadata,omitempty"`
	SignCert         string `json:"sign_cert,omitempty"`
	SignKey          string `json:"sign_key,omitempty"`
	SelfSigned       bool   `json:"self_signed"`
	SignAlgo         string `json:"sign_algo"`
	RespBind         string `json:"resp_bind"`
	SLOURL           string `json:"slo_url,omitempty"`
	ECPIsEnabled     bool   `json:"ecp_enable"`
	ECPRespSignature bool   `json:"ecp_resp_signature"`
}

type SubjectData struct {
	Type       string            `json:"type"`
	Properties SubjectProperties `json:"properties"`
	Required   []string          `json:"required"`
}

type SubjectProperties struct {
	Fmt  string `json:"fmt"`
	Src  string `json:"src"`
	Val  string `json:"val,omitempty"`
	Rule string `json:"rule,omitempty"`
}

type AttrMapSchema struct {
	Type       string        `json:"type"`
	UniqueItems bool         `json:"uniqueItems"`
	Items      AttrMapItem   `json:"items"`
	AttributeMap map[string]string `json:"attribute_map"`
}

type AttrMapItem struct {
	Type       string                `json:"type"`
	Properties AttrMapItemProperties `json:"properties"`
	Required   []string              `json:"required"`
}

type AttrMapItemProperties struct {
	Name AttrMapField `json:"name"`
	Fname AttrMapField `json:"fname"`
	Fmt  AttrMapField `json:"fmt"`
	Val  AttrMapField `json:"val"`
	Src  AttrMapField `json:"src"`
	Rule AttrMapField `json:"rule"`
}

type AttrMapField struct {
	Type string `json:"type"`
}

type TLSCipherSuite struct {
	Default      bool   `json:"default"`
	Selected     bool   `json:"selected"`
	SSLCipher    string `json:"ssl_cipher"`
	SSLProtocols string `json:"ssl_protocols"`
	WeakCipher   bool   `json:"weak_cipher"`
}

type ResourceURI struct {
	Directories string `json:"directories"`
	Sites       string `json:"sites"`
	Pop         string `json:"pop"`
	Href        string `json:"href"`
	Groups      string `json:"groups"`
	Services    string `json:"services"`
}

type Service struct {
	DPAcl   bool   `json:"dp_acl"`
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

type AppDetail struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

type Directory struct {
	UserCount int    `json:"user_count"`
	Type      int    `json:"type"`
	Name      string `json:"name"`
	UUIDURL   string `json:"uuid_url"`
}

type IDP struct {
	IDPId               string `json:"idp_id"`
	ClientCertAuth      string `json:"client_cert_auth"`
	ClientCertUserParam string `json:"client_cert_user_param"`
	Name                string `json:"name"`
	Type                int    `json:"type"`
}

type AppsResponse struct {
	Meta struct {
		TotalCount int `json:"total_count"`
	} `json:"meta"`
	Applications []ApplicationDataModel `json:"objects"`
}

