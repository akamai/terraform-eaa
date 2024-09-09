package client

import (
	"context"
	"encoding/json"
	"fmt"
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

	SAML              bool `json:"saml"`
	Oidc              bool `json:"oidc"`
	FQDNBridgeEnabled bool `json:"fqdn_bridge_enabled"`
	WSFED             bool `json:"wsfed"`
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
	if !(g2ohttpResp.StatusCode >= http.StatusOK && g2ohttpResp.StatusCode < http.StatusMultipleChoices) {
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
	if !(edgeAuthhttpResp.StatusCode >= http.StatusOK && edgeAuthhttpResp.StatusCode < http.StatusMultipleChoices) {
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

	if !(deployResp.StatusCode >= http.StatusOK && deployResp.StatusCode < http.StatusMultipleChoices) {
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

	if !(deleteResp.StatusCode >= http.StatusOK && deleteResp.StatusCode < http.StatusMultipleChoices) {
		return ErrAppDelete
	}
	return nil
}

type ApplicationUpdateRequest struct {
	Application
	AdvancedSettings AdvancedSettings_Complete `json:"advanced_settings"`
	Domain           string                    `json:"domain"`
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

								g2oResp, err := appUpdateReq.Application.UpdateG2O(ec)
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

								edgeAuthResp, err := appUpdateReq.Application.UpdateEdgeAuthentication(ec)
								if err != nil {
									ec.Logger.Error("edge auth cookie request failed. err: ", err)
									return err
								}
								advSettings.EdgeAuthenticationEnabled = STR_TRUE
								advSettings.EdgeCookieKey = &edgeAuthResp.EdgeCookieKey
								advSettings.SlaObjectUrl = &edgeAuthResp.SlaObjectUrl
							}
						}
						UpdateAdvancedSettings(&appUpdateReq.AdvancedSettings, advSettings)

						// appUpdateReq.AdvancedSettings = advSettings
					}
				}
			}
		}
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
	ec.Logger.Info(apiURL)
	b, _ := json.Marshal(appUpdateReq)
	fmt.Println(string(b))

	appUpdResp, err := ec.SendAPIRequest(apiURL, "PUT", appUpdateReq, nil, false)
	if err != nil {
		ec.Logger.Error("update application failed. err: ", err)
		return err
	}
	if !(appUpdResp.StatusCode >= http.StatusOK && appUpdResp.StatusCode < http.StatusMultipleChoices) {
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
	Servers                []Server             `json:"servers"`
	SSLCACert              string               `json:"ssl_ca_cert"`
	Status                 int                  `json:"status"`
	SupportedClientVersion int                  `json:"supported_client_version"`
	TLSSuiteName           *string              `json:"tls_suite_name"`
	TunnelInternalHosts    []TunnelInternalHost `json:"tunnel_internal_hosts"`
	UUIDURL                string               `json:"uuid_url"` //Id - to do
	WSFED                  bool                 `json:"wsfed"`
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

type AdvancedSettings struct {
	IsSSLVerificationEnabled  string  `json:"is_ssl_verification_enabled,omitempty"`
	IgnoreCnameResolution     string  `json:"ignore_cname_resolution,omitempty"`
	EdgeAuthenticationEnabled string  `json:"edge_authentication_enabled,omitempty"`
	G2OEnabled                string  `json:"g2o_enabled,omitempty"`
	G2ONonce                  *string `json:"g2o_nonce,omitempty"`
	G2OKey                    *string `json:"g2o_key,omitempty"`
	XWappReadTimeout          string  `json:"x_wapp_read_timeout,omitempty"`
	InternalHostname          *string `json:"internal_hostname,omitempty"`
	InternalHostPort          string  `json:"internal_host_port,omitempty"`
	WildcardInternalHostname  string  `json:"wildcard_internal_hostname,omitempty"`
	IPAccessAllow             string  `json:"ip_access_allow,omitempty"`
	EdgeCookieKey             *string `json:"edge_cookie_key,omitempty"`
	SlaObjectUrl              *string `json:"sla_object_url,omitempty"`
}

type AdvancedSettings_Complete struct {
	LoginURL                     *string `json:"login_url,omitempty"`
	LogoutURL                    *string `json:"logout_url,omitempty"`
	InternalHostname             *string `json:"internal_hostname,omitempty"`
	InternalHostPort             string  `json:"internal_host_port,omitempty"`
	WildcardInternalHostname     string  `json:"wildcard_internal_hostname,omitempty"`
	IPAccessAllow                string  `json:"ip_access_allow,omitempty"`
	CookieDomain                 *string `json:"cookie_domain,omitempty"`
	RequestParameters            *string `json:"request_parameters,omitempty"`
	LoggingEnabled               string  `json:"logging_enabled,omitempty"`
	LoginTimeout                 string  `json:"login_timeout,omitempty"`
	AppAuth                      string  `json:"app_auth,omitempty"`
	WappAuth                     string  `json:"wapp_auth,omitempty"`
	SSO                          string  `json:"sso,omitempty"`
	HTTPOnlyCookie               string  `json:"http_only_cookie,omitempty"`
	RequestBodyRewrite           string  `json:"request_body_rewrite,omitempty"`
	IDPIdleExpiry                *string `json:"idp_idle_expiry,omitempty"`
	IDPMaxExpiry                 *string `json:"idp_max_expiry,omitempty"`
	HTTPSSSLV3                   string  `json:"https_sslv3,omitempty"`
	SPDYEnabled                  string  `json:"spdy_enabled,omitempty"`
	WebSocketEnabled             string  `json:"websocket_enabled,omitempty"`
	HiddenApp                    string  `json:"hidden_app,omitempty"`
	AppLocation                  *string `json:"app_location,omitempty"`
	AppCookieDomain              *string `json:"app_cookie_domain,omitempty"`
	AppAuthDomain                *string `json:"app_auth_domain,omitempty"`
	LoadBalancingMetric          string  `json:"load_balancing_metric,omitempty"`
	HealthCheckType              string  `json:"health_check_type,omitempty"`
	HealthCheckHTTPURL           string  `json:"health_check_http_url,omitempty"`
	HealthCheckHTTPVersion       string  `json:"health_check_http_version,omitempty"`
	HealthCheckHTTPHostHeader    *string `json:"health_check_http_host_header,omitempty"`
	ProxyBufferSizeKB            string  `json:"proxy_buffer_size_kb,omitempty"`
	SessionSticky                string  `json:"session_sticky,omitempty"`
	SessionStickyCookieMaxAge    string  `json:"session_sticky_cookie_maxage,omitempty"`
	SessionStickyServerCookie    *string `json:"session_sticky_server_cookie,omitempty"`
	PassPhrase                   *string `json:"pass_phrase,omitempty"`
	PrivateKey                   *string `json:"private_key,omitempty"`
	HostKey                      *string `json:"host_key,omitempty"`
	UserName                     *string `json:"user_name,omitempty"`
	ExternalCookieDomain         *string `json:"external_cookie_domain,omitempty"`
	ServicePrincipleName         *string `json:"service_principle_name,omitempty"`
	ServerCertValidate           string  `json:"server_cert_validate,omitempty"`
	IgnoreCnameResolution        string  `json:"ignore_cname_resolution,omitempty"`
	SSHAuditEnabled              string  `json:"ssh_audit_enabled,omitempty"`
	MFA                          string  `json:"mfa,omitempty"`
	RefreshStickyCookie          string  `json:"refresh_sticky_cookie,omitempty"`
	AppServerReadTimeout         string  `json:"app_server_read_timeout,omitempty"`
	IdleConnFloor                string  `json:"idle_conn_floor,omitempty"`
	IdleConnCeil                 string  `json:"idle_conn_ceil,omitempty"`
	IdleConnStep                 string  `json:"idle_conn_step,omitempty"`
	IdleCloseTimeSeconds         string  `json:"idle_close_time_seconds,omitempty"`
	RateLimit                    string  `json:"rate_limit,omitempty"`
	AuthenticatedServerReqLimit  string  `json:"authenticated_server_request_limit,omitempty"`
	AnonymousServerReqLimit      string  `json:"anonymous_server_request_limit,omitempty"`
	AuthenticatedServerConnLimit string  `json:"authenticated_server_conn_limit,omitempty"`
	AnonymousServerConnLimit     string  `json:"anonymous_server_conn_limit,omitempty"`
	ServerRequestBurst           string  `json:"server_request_burst,omitempty"`
	HealthCheckRise              string  `json:"health_check_rise,omitempty"`
	HealthCheckFall              string  `json:"health_check_fall,omitempty"`
	HealthCheckTimeout           string  `json:"health_check_timeout,omitempty"`
	HealthCheckInterval          string  `json:"health_check_interval,omitempty"`
	KerberosNegotiateOnce        string  `json:"kerberos_negotiate_once,omitempty"`
	InjectAjaxJavascript         string  `json:"inject_ajax_javascript,omitempty"`
	SentryRedirect401            string  `json:"sentry_redirect_401,omitempty"`
	ProxyDisableClipboard        string  `json:"proxy_disable_clipboard,omitempty"`
	PreauthEnforceURL            string  `json:"preauth_enforce_url,omitempty"`
	ForceMFA                     string  `json:"force_mfa,omitempty"`
	IgnoreBypassMFA              string  `json:"ignore_bypass_mfa,omitempty"`
	StickyAgent                  string  `json:"sticky_agent,omitempty"`
	SaaSEnabled                  string  `json:"saas_enabled,omitempty"`
	AllowCORS                    string  `json:"allow_cors,omitempty"`
	CORSOriginList               string  `json:"cors_origin_list,omitempty"`
	CORSMethodList               string  `json:"cors_method_list,omitempty"`
	CORSHeaderList               string  `json:"cors_header_list,omitempty"`
	CORSSupportCredential        string  `json:"cors_support_credential,omitempty"`
	CORSMaxAge                   string  `json:"cors_max_age,omitempty"`
	KeepaliveEnable              string  `json:"keepalive_enable,omitempty"`
	KeepaliveConnectionPool      string  `json:"keepalive_connection_pool,omitempty"`
	KeepaliveTimeout             string  `json:"keepalive_timeout,omitempty"`
	KeyedKeepaliveEnable         string  `json:"keyed_keepalive_enable,omitempty"`
	Keytab                       string  `json:"keytab,omitempty"`
	EdgeCookieKey                string  `json:"edge_cookie_key,omitempty"`
	SLAObjectURL                 string  `json:"sla_object_url,omitempty"`
	ForwardTicketGrantingTicket  string  `json:"forward_ticket_granting_ticket,omitempty"`
	EdgeAuthenticationEnabled    string  `json:"edge_authentication_enabled,omitempty"`
	HSTSage                      string  `json:"hsts_age,omitempty"`
	RDPInitialProgram            *string `json:"rdp_initial_program,omitempty"`
	RemoteSparkMapClipboard      string  `json:"remote_spark_mapClipboard,omitempty"`
	RDPLegacyMode                string  `json:"rdp_legacy_mode,omitempty"`
	RemoteSparkAudio             string  `json:"remote_spark_audio,omitempty"`
	RemoteSparkMapPrinter        string  `json:"remote_spark_mapPrinter,omitempty"`
	RemoteSparkPrinter           string  `json:"remote_spark_printer,omitempty"`
	RemoteSparkMapDisk           string  `json:"remote_spark_mapDisk,omitempty"`
	RemoteSparkDisk              string  `json:"remote_spark_disk,omitempty"`
	RemoteSparkRecording         string  `json:"remote_spark_recording,omitempty"`
	ClientCertAuth               string  `json:"client_cert_auth,omitempty"`
	ClientCertUserParam          string  `json:"client_cert_user_param,omitempty"`
	G2OEnabled                   string  `json:"g2o_enabled,omitempty"`
	G2ONonce                     *string `json:"g2o_nonce,omitempty"`
	G2OKey                       *string `json:"g2o_key,omitempty"`
	RDPTLS1                      string  `json:"rdp_tls1,omitempty"`
	DomainExceptionList          string  `json:"domain_exception_list,omitempty"`
	Acceleration                 string  `json:"acceleration,omitempty"`
	OffloadOnPremiseTraffic      string  `json:"offload_onpremise_traffic,omitempty"`
	AppClientCertAuth            string  `json:"app_client_cert_auth,omitempty"`
	PreauthConsent               string  `json:"preauth_consent,omitempty"`
	MDCEnable                    string  `json:"mdc_enable,omitempty"`
	SingleHostEnable             string  `json:"single_host_enable,omitempty"`
	SingleHostFQDN               string  `json:"single_host_fqdn,omitempty"`
	SingleHostPath               string  `json:"single_host_path,omitempty"`
	SingleHostContentRW          string  `json:"single_host_content_rw,omitempty"`
	IsSSLVerificationEnabled     string  `json:"is_ssl_verification_enabled,omitempty"`
	SingleHostCookieDomain       string  `json:"single_host_cookie_domain,omitempty"`
	XWappReadTimeout             string  `json:"x_wapp_read_timeout,omitempty"`
	ForceIPRoute                 string  `json:"force_ip_route,omitempty"`
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

type SAMLSettings struct {
	Title string     `json:"title"`
	Type  string     `json:"type"`
	Items SAMLObject `json:"items"`
}

type SAMLObject struct {
	Type       string         `json:"type"`
	Properties SAMLProperties `json:"properties"`
}

type SAMLProperties struct {
	SP      SPMetadata    `json:"sp"`
	IDP     IDPMetadata   `json:"idp"`
	Subject SubjectData   `json:"subject"`
	Attrmap []AttrMapping `json:"attrmap"`
}

type SPMetadata struct {
	Type       string       `json:"type"`
	Properties SPProperties `json:"properties"`
	Required   []string     `json:"required"`
}

type SPProperties struct {
	EntityID          string  `json:"entity_id"`
	ACSURL            string  `json:"acs_url"`
	SLOURL            string  `json:"slo_url,omitempty"`
	ReqBind           string  `json:"req_bind"`
	Metadata          string  `json:"metadata,omitempty"`
	DefaultRelayState *string `json:"default_relay_state"`
	ForceAuth         bool    `json:"force_auth"`
	ReqVerify         bool    `json:"req_verify"`
	SignCert          string  `json:"sign_cert,omitempty"`
	RespEncr          bool    `json:"resp_encr"`
	EncrCert          string  `json:"encr_cert,omitempty"`
	EncrAlgo          string  `json:"encr_algo"`
	SLOReqVerify      bool    `json:"slo_req_verify,omitempty"`
	DSTURL            string  `json:"dst_url,omitempty"`
	SLOBind           string  `json:"slo_bind,omitempty"`
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

type AttrMapping struct {
	Name  string `json:"name"`
	Fname string `json:"fname,omitempty"`
	Fmt   string `json:"fmt"`
	Val   string `json:"val,omitempty"`
	Src   string `json:"src"`
	Rule  string `json:"rule,omitempty"`
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
