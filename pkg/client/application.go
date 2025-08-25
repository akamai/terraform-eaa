package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type CreateAppRequest struct {
	Name             string           `json:"name"`
	Description      *string          `json:"description"`
	AppProfile       int              `json:"app_profile"`
	AppType          int              `json:"app_type"`
	ClientAppMode    int              `json:"client_app_mode"`
	AdvancedSettings AdvancedSettings `json:"advanced_settings,omitempty"`
	SAML             bool             `json:"saml"`
	Oidc             bool             `json:"oidc"`
	WSFED            bool             `json:"wsfed"`
	SAMLSettings     []SAMLConfig     `json:"saml_settings"`
	OIDCSettings     *OIDCConfig      `json:"oidc_settings"`
	WSFEDSettings    []WSFEDConfig    `json:"wsfed_settings"`
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

	// Handle advanced settings for CREATE flow - ALWAYS set defaults
	// SUPER VISIBLE LOGGING

	// Get advanced settings JSON or use empty JSON to force defaults
	var advSettingsJSON string
	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		if jsonStr, ok := advSettingsData.(string); ok {
			advSettingsJSON = jsonStr
		}
	}
	if advSettingsJSON == "" {
		advSettingsJSON = "{}" // Force parsing with empty JSON to apply defaults
	}

	logger.Info("CREATE FLOW: Using JSON:", advSettingsJSON)

	// ALWAYS parse and apply malformed defaults
	advSettings, err := ParseAdvancedSettingsWithDefaults(advSettingsJSON)
	if err != nil {
		return fmt.Errorf("failed to parse advanced settings JSON: %w", err)
	}

	// Parse the JSON again to handle app_auth special cases for CREATE flow
	var advSettingsDataMap map[string]interface{}
	if err := json.Unmarshal([]byte(advSettingsJSON), &advSettingsDataMap); err == nil {
		if app_auth, ok := advSettingsDataMap["app_auth"].(string); ok {
			logger.Info("CREATE FLOW: Found app_auth in advanced settings:", app_auth)
			// Handle special authentication types that require setting boolean flags
			switch app_auth {
			case "SAML2.0":
				// For SAML2.0, set app_auth to "none" in payload
				advSettings.AppAuth = "none"
				car.SAML = true
				car.Oidc = false
				car.WSFED = false
			case "oidc", "OpenID Connect 1.0":
				// For oidc, set app_auth to "oidc" in payload and oidc = true
				advSettings.AppAuth = "oidc"
				car.SAML = false
				car.Oidc = true
				car.WSFED = false
			case "wsfed", "WS-Federation":
				// For wsfed, include app_auth in payload
				advSettings.AppAuth = "none"
				car.SAML = false
				car.Oidc = false
				car.WSFED = true
			default:
				// For "none", "kerberos", "basic", "NTLMv1", "NTLMv2", include app_auth in payload
				advSettings.AppAuth = app_auth
				car.SAML = false
				car.Oidc = false
				car.WSFED = false
			}
		} else {
			logger.Info("CREATE FLOW: No app_auth found in advanced settings, explicitly setting to 'none'")
			advSettings.AppAuth = "none"
		}
	}
	logger.Info("CREATE FLOW: Final app_auth value in payload:", advSettings.AppAuth)
	
	logger.Info("CREATE FLOW: After setting flags - SAML:", car.SAML)
	logger.Info("CREATE FLOW: After setting flags - Oidc:", car.Oidc)
	logger.Info("CREATE FLOW: After setting flags - WSFED:", car.WSFED)

	// Handle SAML settings for CREATE flow
	if car.SAML {
		if samlSettingsData, ok := d.GetOk("saml_settings"); ok {
			// User provided saml_settings as JSON string - parse it
			logger.Info("CREATE FLOW: Found saml_settings as JSON string")
			if samlSettingsJSON, ok := samlSettingsData.(string); ok && samlSettingsJSON != "" {
				// Parse the JSON string into SAMLConfig slice
				if err := json.Unmarshal([]byte(samlSettingsJSON), &car.SAMLSettings); err != nil {
					logger.Error("CREATE FLOW: Failed to parse saml_settings JSON:", err)
					return fmt.Errorf("failed to parse saml_settings JSON: %w", err)
				}
				logger.Info("CREATE FLOW: Successfully parsed", len(car.SAMLSettings), "SAML configs from JSON")
			}
		} else {
			// No saml_settings provided but SAML is enabled - create default structure
			logger.Info("CREATE FLOW: No saml_settings found, creating defaults")
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
					SignCert:         nil,
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
			car.SAMLSettings = []SAMLConfig{defaultSAMLConfig}
		}
	} else {
		car.SAMLSettings = []SAMLConfig{}
	}

	// Always set the settings fields to ensure they appear in payload
	if !car.Oidc {
		car.OIDCSettings = nil
	} else {
		// Handle OIDC settings for CREATE flow
		if oidcSettingsData, ok := d.GetOk("oidc_settings"); ok {
			logger.Info("CREATE FLOW: Found oidc_settings as JSON string")
			if oidcSettingsJSON, ok := oidcSettingsData.(string); ok && oidcSettingsJSON != "" {
				if err := json.Unmarshal([]byte(oidcSettingsJSON), &car.OIDCSettings); err != nil {
					logger.Error("CREATE FLOW: Failed to parse oidc_settings JSON:", err)
					return fmt.Errorf("failed to parse oidc_settings JSON: %w", err)
				}
				logger.Info("CREATE FLOW: Successfully parsed OIDC settings from JSON")
			}
		} else {
			logger.Info("CREATE FLOW: No oidc_settings found, creating defaults")
			car.OIDCSettings = &OIDCConfig{
				OIDCClients: []OIDCClient{
					{
						ClientName:            "default_client",
						ClientID:              "default_client_id",
						ResponseType:          []string{"code"},
						ImplicitGrant:         false,
						Type:                  "standard",
						RedirectURIs:          []string{},
						JavaScriptOrigins:     []string{},
						Claims:                []OIDCClaim{},
					},
				},
			}
		}
	}
	if !car.WSFED {
		car.WSFEDSettings = []WSFEDConfig{}
	} else {
		// Handle WS-Federation settings for CREATE flow
		if wsfedSettingsData, ok := d.GetOk("wsfed_settings"); ok {
			logger.Info("CREATE FLOW: Found wsfed_settings as JSON string")
			if wsfedSettingsJSON, ok := wsfedSettingsData.(string); ok && wsfedSettingsJSON != "" {
				if err := json.Unmarshal([]byte(wsfedSettingsJSON), &car.WSFEDSettings); err != nil {
					logger.Error("CREATE FLOW: Failed to parse wsfed_settings JSON:", err)
					return fmt.Errorf("failed to parse wsfed_settings JSON: %w", err)
				}
				logger.Info("CREATE FLOW: Successfully parsed", len(car.WSFEDSettings), "WS-Federation configs from JSON")
			}
		} else {
			logger.Info("CREATE FLOW: No wsfed_settings found, creating defaults")
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
					EntityID:   "",
					SignAlgo:   "SHA256",
					SignCert:   "",
					SignKey:    "",
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
			car.WSFEDSettings = []WSFEDConfig{defaultWSFEDConfig}
		}
	}

	logger.Info("CREATE FLOW: Setting car.AdvancedSettings with malformed defaults")
	car.AdvancedSettings = *advSettings

	return nil
}

func (car *CreateAppRequest) CreateApplication(ctx context.Context, ec *EaaClient) (*ApplicationResponse, error) {
	ec.Logger.Info("create application")

	// Log the complete payload being sent to API
	payloadBytes, _ := json.MarshalIndent(car, "", "  ")
	ec.Logger.Info("=== COMPLETE API PAYLOAD BEING SENT ===")
	ec.Logger.Info(string(payloadBytes))
	ec.Logger.Info("=== END API PAYLOAD ===")

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

	SAML              bool          `json:"saml"`
	SAMLSettings      []SAMLConfig  `json:"saml_settings,omitempty"`
	Oidc              bool          `json:"oidc"`
	OIDCSettings      *OIDCConfig   `json:"oidc_settings,omitempty"`
	FQDNBridgeEnabled bool          `json:"fqdn_bridge_enabled"`
	WSFED             bool          `json:"wsfed"`
	WSFEDSettings     []WSFEDConfig `json:"wsfed_settings"`
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
	SAMLSettings     []SAMLConfig              `json:"saml_settings"`
	WSFEDSettings    []WSFEDConfig             `json:"wsfed_settings"`
	OIDCSettings     *OIDCConfig               `json:"oidc_settings"`
}

func (appUpdateReq *ApplicationUpdateRequest) UpdateAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	ec.Logger.Info("updating application")
	
	// Handle basic application fields
	if description, ok := d.GetOk("description"); ok {
		if descriptionStr, ok := description.(string); ok && descriptionStr != "" {
			appUpdateReq.Description = &descriptionStr
		}
	}
	
	if name, ok := d.GetOk("name"); ok {
		if nameStr, ok := name.(string); ok && nameStr != "" {
			appUpdateReq.Name = nameStr
		}
	}
	
	if host, ok := d.GetOk("host"); ok {
		if hostStr, ok := host.(string); ok && hostStr != "" {
			appUpdateReq.Host = &hostStr
		}
	}
	
	if domain, ok := d.GetOk("domain"); ok {
		if domainStr, ok := domain.(string); ok && domainStr != "" {
			appUpdateReq.Domain = domainStr
		}
	}
	
	if popregion, ok := d.GetOk("popregion"); ok {
		if popregionStr, ok := popregion.(string); ok && popregionStr != "" {
			appUpdateReq.POPRegion = popregionStr
		}
	}
	

	
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
		if advSettingsJSON, ok := advSettingsData.(string); ok && advSettingsJSON != "" {
			// Parse JSON and apply defaults
			advSettings, err := ParseAdvancedSettingsWithDefaults(advSettingsJSON)
			if err != nil {
				return fmt.Errorf("failed to parse advanced settings JSON: %w", err)
			}

			// Parse the JSON again to handle app_auth special cases
			var advSettingsData map[string]interface{}
			if err := json.Unmarshal([]byte(advSettingsJSON), &advSettingsData); err == nil {
				if app_auth, ok := advSettingsData["app_auth"].(string); ok {
					ec.Logger.Info("UPDATE FLOW: Found app_auth in advanced settings:", app_auth)
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
				} else {
					ec.Logger.Info("UPDATE FLOW: No app_auth found in advanced settings, explicitly setting to 'none'")
					advSettings.AppAuth = "none"
				}
			}
			ec.Logger.Info("UPDATE FLOW: Final app_auth value in payload:", advSettings.AppAuth)
			ec.Logger.Info("UPDATE FLOW: SAML flag:", appUpdateReq.SAML)
			ec.Logger.Info("UPDATE FLOW: Oidc flag:", appUpdateReq.Oidc)
			ec.Logger.Info("UPDATE FLOW: WSFED flag:", appUpdateReq.WSFED)

			// Always set the settings fields to ensure they appear in payload
			if !appUpdateReq.SAML {
				appUpdateReq.SAMLSettings = []SAMLConfig{}
			}
			if !appUpdateReq.Oidc {
				appUpdateReq.OIDCSettings = nil
			}
			if !appUpdateReq.WSFED {
				appUpdateReq.WSFEDSettings = []WSFEDConfig{}
			}

			// Handle special cases that require API calls
			if advSettings.G2OEnabled == STR_TRUE {
				g2oResp, err := appUpdateReq.UpdateG2O(ec)
				if err != nil {
					ec.Logger.Error("g2o request failed. err: ", err)
					return err
				}
				advSettings.G2OKey = &g2oResp.G2OKey
				advSettings.G2ONonce = &g2oResp.G2ONonce
			}

			if advSettings.EdgeAuthenticationEnabled == STR_TRUE {
				edgeAuthResp, err := appUpdateReq.UpdateEdgeAuthentication(ec)
				if err != nil {
					ec.Logger.Error("edge auth cookie request failed. err: ", err)
					return err
				}
				advSettings.EdgeCookieKey = &edgeAuthResp.EdgeCookieKey
				advSettings.SlaObjectUrl = &edgeAuthResp.SlaObjectUrl
			}

			// Use the UpdateAdvancedSettings function to properly update the struct
			UpdateAdvancedSettings(&appUpdateReq.AdvancedSettings, *advSettings)
			
			// Explicitly set the AppAuth field to ensure it's preserved
			appUpdateReq.AdvancedSettings.AppAuth = advSettings.AppAuth
			
			// Log the final advanced settings to see what's being sent
			ec.Logger.Info("UPDATE FLOW: Final advanced settings AppAuth:", appUpdateReq.AdvancedSettings.AppAuth)
		}

		// Handle SAML settings - always create structure when app_auth = "SAML2.0"
		var samlConfigs []SAMLConfig

		if samlSettingsData, ok := d.GetOk("saml_settings"); ok {
			// User provided saml_settings as JSON string - parse it
			ec.Logger.Info("UPDATE FLOW: Found saml_settings as JSON string")
			if samlSettingsJSON, ok := samlSettingsData.(string); ok && samlSettingsJSON != "" {
				// Parse the JSON string into SAMLConfig slice
				if err := json.Unmarshal([]byte(samlSettingsJSON), &samlConfigs); err != nil {
					ec.Logger.Error("UPDATE FLOW: Failed to parse saml_settings JSON:", err)
					return fmt.Errorf("failed to parse saml_settings JSON: %w", err)
				}
				ec.Logger.Info("UPDATE FLOW: Successfully parsed", len(samlConfigs), "SAML configs from JSON")
			}
		} else if appUpdateReq.SAML { // This condition ensures it only runs if app_auth was SAML2.0
			// No saml_settings provided but app_auth = "SAML2.0" - create default structure
			// This ensures mandatory SAML fields are always in the payload
			ec.Logger.Info("UPDATE FLOW: No saml_settings found, creating defaults")
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
					SignCert:         nil,
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

	// Handle WS-Federation settings for UPDATE flow
	var wsfedConfigs []WSFEDConfig

	if appUpdateReq.WSFED {
		if wsfedSettingsData, ok := d.GetOk("wsfed_settings"); ok {
			ec.Logger.Info("UPDATE FLOW: Found wsfed_settings as JSON string")
			if wsfedSettingsJSON, ok := wsfedSettingsData.(string); ok && wsfedSettingsJSON != "" {
				if err := json.Unmarshal([]byte(wsfedSettingsJSON), &wsfedConfigs); err != nil {
					ec.Logger.Error("UPDATE FLOW: Failed to parse wsfed_settings JSON:", err)
					return fmt.Errorf("failed to parse wsfed_settings JSON: %w", err)
				}
				ec.Logger.Info("UPDATE FLOW: Successfully parsed", len(wsfedConfigs), "WS-Federation configs from JSON")
			}
		} else {
			ec.Logger.Info("UPDATE FLOW: No wsfed_settings found, creating defaults")
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
					EntityID:   "",
					SignAlgo:   "SHA256",
					SignCert:   "",
					SignKey:    "",
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
	} else {
		wsfedConfigs = []WSFEDConfig{}
	}

	// Set the WS-Federation settings in the application update request if we have any
	if len(wsfedConfigs) > 0 {
		appUpdateReq.WSFEDSettings = wsfedConfigs
	}

	// Handle OIDC settings for UPDATE flow
	var oidcConfig *OIDCConfig

	if appUpdateReq.Oidc {
		if oidcSettingsData, ok := d.GetOk("oidc_settings"); ok {
			ec.Logger.Info("UPDATE FLOW: Found oidc_settings as JSON string")
			if oidcSettingsJSON, ok := oidcSettingsData.(string); ok && oidcSettingsJSON != "" {
				if err := json.Unmarshal([]byte(oidcSettingsJSON), &oidcConfig); err != nil {
					ec.Logger.Error("UPDATE FLOW: Failed to parse oidc_settings JSON:", err)
					return fmt.Errorf("failed to parse oidc_settings JSON: %w", err)
				}
				ec.Logger.Info("UPDATE FLOW: Successfully parsed OIDC settings from JSON")
			}
		} else {
			ec.Logger.Info("UPDATE FLOW: No oidc_settings found, creating defaults")
			oidcConfig = &OIDCConfig{
				OIDCClients: []OIDCClient{
					{
						ClientName:            "default_client",
						ClientID:              "default_client_id",
						ResponseType:          []string{"code"},
						ImplicitGrant:         false,
						Type:                  "standard",
						RedirectURIs:          []string{},
						JavaScriptOrigins:     []string{},
						Claims:                []OIDCClaim{},
					},
				},
			}
		}
	} else {
		oidcConfig = nil
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

	// Parse the response to show the returned values
	responseBody, _ := io.ReadAll(appUpdResp.Body)
	var responseData map[string]interface{}
	if err := json.Unmarshal(responseBody, &responseData); err == nil {
		ec.Logger.Info("API RESPONSE:")
		responseJSON, _ := json.MarshalIndent(responseData, "", "  ")
		ec.Logger.Info(string(responseJSON))

		// Show specific advanced settings from response
		if advancedSettings, ok := responseData["advanced_settings"].(map[string]interface{}); ok {
			ec.Logger.Info("ADVANCED SETTINGS FROM RESPONSE:")
			if appAuthDomain, exists := advancedSettings["app_auth_domain"]; exists {
				ec.Logger.Info(fmt.Sprintf("app_auth_domain: %v (type: %T)", appAuthDomain, appAuthDomain))
			} else {
				ec.Logger.Info("app_auth_domain: not present in response")
			}
			if appClientCertAuth, exists := advancedSettings["app_client_cert_auth"]; exists {
				ec.Logger.Info(fmt.Sprintf("app_client_cert_auth: %v (type: %T)", appClientCertAuth, appClientCertAuth))
			} else {
				ec.Logger.Info("app_client_cert_auth: not present in response")
			}
			if acceleration, exists := advancedSettings["acceleration"]; exists {
				ec.Logger.Info(fmt.Sprintf("acceleration: %v (type: %T)", acceleration, acceleration))
			} else {
				ec.Logger.Info("acceleration: not present in response")
			}
		}
		ec.Logger.Info("")
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
	OIDCClients            []OIDCClient         `json:"oidcclients,omitempty"`
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

// CustomHeader represents a custom header configuration
type CustomHeader struct {
	AttributeType string `json:"attribute_type,omitempty"`
	Header        string `json:"header,omitempty"`
	Attribute     string `json:"attribute,omitempty"`
}

type AdvancedSettings struct {
	IsSSLVerificationEnabled     string                 `json:"is_ssl_verification_enabled,omitempty"`
	IgnoreCnameResolution        string                 `json:"ignore_cname_resolution,omitempty"`
	EdgeAuthenticationEnabled    string                 `json:"edge_authentication_enabled,omitempty"`
	G2OEnabled                   string                 `json:"g2o_enabled,omitempty"`
	G2ONonce                     *string                `json:"g2o_nonce,omitempty"`
	G2OKey                       *string                `json:"g2o_key,omitempty"`
	XWappReadTimeout             string                 `json:"x_wapp_read_timeout,omitempty"`
	InternalHostname             *string                `json:"internal_hostname,omitempty"`
	InternalHostPort             string                 `json:"internal_host_port,omitempty"`
	WildcardInternalHostname     string                 `json:"wildcard_internal_hostname,omitempty"`
	IPAccessAllow                string                 `json:"ip_access_allow,omitempty"`
	EdgeCookieKey                *string                `json:"edge_cookie_key,omitempty"`
	SlaObjectUrl                 *string                `json:"sla_object_url,omitempty"`
	AllowCORS                    string                 `json:"allow_cors,omitempty"`
	CORSOriginList               string                 `json:"cors_origin_list,omitempty"`
	CORSMethodList               string                 `json:"cors_method_list,omitempty"`
	CORSHeaderList               string                 `json:"cors_header_list,omitempty"`
	CORSSupportCredential        string                 `json:"cors_support_credential,omitempty"`
	CORSMaxAge                   string                 `json:"cors_max_age,omitempty"`
	WebSocketEnabled             string                 `json:"websocket_enabled,omitempty"`
	StickyAgent                  string                 `json:"sticky_agent,omitempty"`
	AppCookieDomain              *string                `json:"app_cookie_domain,omitempty"`
	LogoutURL                    *string                `json:"logout_url,omitempty"`
	SentryRedirect401            string                 `json:"sentry_redirect_401,omitempty"`
	AppAuth                      string                 `json:"app_auth"`
	WappAuth                     string                 `json:"wapp_auth,omitempty"`
	JWTIssuers                   string                 `json:"jwt_issuers,omitempty"`
	JWTAudience                  string                 `json:"jwt_audience,omitempty"`
	JWTGracePeriod               string                 `json:"jwt_grace_period,omitempty"`
	JWTReturnOption              string                 `json:"jwt_return_option,omitempty"`
	JWTUsername                  string                 `json:"jwt_username,omitempty"`
	JWTReturnURL                 string                 `json:"jwt_return_url,omitempty"`
	AppAuthDomain                *string                `json:"app_auth_domain,omitempty"`
	AppClientCertAuth            string                 `json:"app_client_cert_auth,omitempty"`
	ForwardTicketGrantingTicket  string                 `json:"forward_ticket_granting_ticket,omitempty"`
	Keytab                       string                 `json:"keytab,omitempty"`
	ServicePrincipalName         *string                `json:"service_principle_name,omitempty"`
	CustomHeaders                []CustomHeader         `json:"custom_headers,omitempty"`
	Acceleration                 string                 `json:"acceleration,omitempty"`
	AnonymousServerConnLimit     string                 `json:"anonymous_server_conn_limit,omitempty"`
	AnonymousServerReqLimit      string                 `json:"anonymous_server_request_limit,omitempty"`
	AppLocation                  *string                `json:"app_location"`
	AppServerReadTimeout         string                 `json:"app_server_read_timeout,omitempty"`
	AuthenticatedServerConnLimit string                 `json:"authenticated_server_conn_limit,omitempty"`
	AuthenticatedServerReqLimit  string                 `json:"authenticated_server_request_limit,omitempty"`
	ClientCertAuth               string                 `json:"client_cert_auth,omitempty"`
	ClientCertUserParam          string                 `json:"client_cert_user_param,omitempty"`
	CookieDomain                 *string                `json:"cookie_domain"`
	DisableUserAgentCheck        string                 `json:"disable_user_agent_check,omitempty"`
	DomainExceptionList          string                 `json:"domain_exception_list,omitempty"`
	EdgeTransportManualMode      string                 `json:"edge_transport_manual_mode,omitempty"`
	EdgeTransportPropertyID      *string                `json:"edge_transport_property_id"`
	EnableClientSideXHRRewrite   string                 `json:"enable_client_side_xhr_rewrite,omitempty"`
	ExternalCookieDomain         *string                `json:"external_cookie_domain"`
	ForceIPRoute                 string                 `json:"force_ip_route,omitempty"`
	ForceMFA                     string                 `json:"force_mfa,omitempty"`
	FormPostAttributes           []string               `json:"form_post_attributes,omitempty"`
	FormPostURL                  string                 `json:"form_post_url,omitempty"`
	HealthCheckFall              string                 `json:"health_check_fall,omitempty"`
	HealthCheckHTTPHostHeader    *string                `json:"health_check_http_host_header"`
	HealthCheckHTTPURL           string                 `json:"health_check_http_url,omitempty"`
	HealthCheckHTTPVersion       string                 `json:"health_check_http_version,omitempty"`
	HealthCheckInterval          string                 `json:"health_check_interval,omitempty"`
	HealthCheckRise              string                 `json:"health_check_rise,omitempty"`
	HealthCheckTimeout           string                 `json:"health_check_timeout,omitempty"`
	HealthCheckType              string                 `json:"health_check_type,omitempty"`
	HiddenApp                    string                 `json:"hidden_app,omitempty"`
	HostKey                      *string                `json:"host_key"`
	HSTSage                      string                 `json:"hsts_age,omitempty"`
	HTTPOnlyCookie               string                 `json:"http_only_cookie,omitempty"`
	HTTPSSSLV3                   string                 `json:"https_sslv3,omitempty"`
	IdleCloseTimeSeconds         string                 `json:"idle_close_time_seconds,omitempty"`
	IdleConnCeil                 string                 `json:"idle_conn_ceil,omitempty"`
	IdleConnFloor                string                 `json:"idle_conn_floor,omitempty"`
	IdleConnStep                 string                 `json:"idle_conn_step,omitempty"`
	IDPIdleExpiry                *string                `json:"idp_idle_expiry"`
	IDPMaxExpiry                 *string                `json:"idp_max_expiry"`
	IgnoreBypassMFA              string                 `json:"ignore_bypass_mfa,omitempty"`
	InjectAjaxJavascript         string                 `json:"inject_ajax_javascript,omitempty"`
	InterceptURL                 string                 `json:"intercept_url,omitempty"`
	IsBrotliEnabled              string                 `json:"is_brotli_enabled,omitempty"`
	KeepaliveConnectionPool      string                 `json:"keepalive_connection_pool,omitempty"`
	KeepaliveEnable              string                 `json:"keepalive_enable,omitempty"`
	KeepaliveTimeout             string                 `json:"keepalive_timeout,omitempty"`
	LoadBalancingMetric          string                 `json:"load_balancing_metric,omitempty"`
	LoggingEnabled               string                 `json:"logging_enabled,omitempty"`
	LoginTimeout                 string                 `json:"login_timeout,omitempty"`
	LoginURL                     *string                `json:"login_url"`
	MDCEnable                    string                 `json:"mdc_enable,omitempty"`
	MFA                          string                 `json:"mfa,omitempty"`
	OffloadOnpremiseTraffic      string                 `json:"offload_onpremise_traffic,omitempty"`
	Onramp                       string                 `json:"onramp,omitempty"`
	PassPhrase                   *string                `json:"pass_phrase"`
	PreauthConsent               string                 `json:"preauth_consent,omitempty"`
	PreauthEnforceURL            string                 `json:"preauth_enforce_url,omitempty"`
	PrivateKey                   *string                `json:"private_key"`
	RemoteSparkAudio             string                 `json:"remote_spark_audio,omitempty"`
	RemoteSparkDisk              string                 `json:"remote_spark_disk,omitempty"`
	RemoteSparkMapClipboard      string                 `json:"remote_spark_mapClipboard,omitempty"`
	RemoteSparkMapDisk           string                 `json:"remote_spark_mapDisk,omitempty"`
	RemoteSparkMapPrinter        string                 `json:"remote_spark_mapPrinter,omitempty"`
	RemoteSparkPrinter           string                 `json:"remote_spark_printer,omitempty"`
	RemoteSparkRecording         string                 `json:"remote_spark_recording,omitempty"`
	RequestBodyRewrite           string                 `json:"request_body_rewrite,omitempty"`
	RequestParameters            map[string]interface{} `json:"request_parameters"`
	SaaSEnabled                  string                 `json:"saas_enabled,omitempty"`
	SegmentationPolicyEnable     string                 `json:"segmentation_policy_enable,omitempty"`
	SentryRestoreFormPost        string                 `json:"sentry_restore_form_post,omitempty"`
	ServerCertValidate           string                 `json:"server_cert_validate,omitempty"`
	ServerRequestBurst           string                 `json:"server_request_burst,omitempty"`
	ServicePrincipleName         *string                `json:"service_principle_name"`
	SessionSticky                string                 `json:"session_sticky,omitempty"`
	SessionStickyCookieMaxAge    string                 `json:"session_sticky_cookie_maxage,omitempty"`
	SessionStickyServerCookie    *string                `json:"session_sticky_server_cookie"`
	SingleHostContentRW          string                 `json:"single_host_content_rw,omitempty"`
	SingleHostCookieDomain       string                 `json:"single_host_cookie_domain,omitempty"`
	SingleHostEnable             string                 `json:"single_host_enable,omitempty"`
	SingleHostFQDN               string                 `json:"single_host_fqdn,omitempty"`
	SingleHostPath               string                 `json:"single_host_path,omitempty"`
	SPDYEnabled                  string                 `json:"spdy_enabled,omitempty"`
	SSHAuditEnabled              string                 `json:"ssh_audit_enabled,omitempty"`
	SSO                          string                 `json:"sso,omitempty"`
	UserName                     *string                `json:"user_name"`
	XWappPoolEnabled             string                 `json:"x_wapp_pool_enabled,omitempty"`
	XWappPoolSize                string                 `json:"x_wapp_pool_size,omitempty"`
	XWappPoolTimeout             string                 `json:"x_wapp_pool_timeout,omitempty"`
	RDPKeyboardLang              string                 `json:"rdp_keyboard_lang,omitempty"`
	RDPRemoteApps                []string               `json:"rdp_remote_apps,omitempty"`
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`

	// JWT fields
	JwtAudience     string `json:"jwt_audience,omitempty"`
	JwtGracePeriod  string `json:"jwt_grace_period,omitempty"`
	JwtIssuers      string `json:"jwt_issuers,omitempty"`
	JwtReturnOption string `json:"jwt_return_option,omitempty"`
	JwtReturnUrl    string `json:"jwt_return_url,omitempty"`
	JwtUsername     string `json:"jwt_username,omitempty"`
}

type AdvancedSettings_Complete struct {
	LoginURL                     *string                `json:"login_url,omitempty"`
	LogoutURL                    *string                `json:"logout_url,omitempty"`
	InternalHostname             *string                `json:"internal_hostname,omitempty"`
	InternalHostPort             string                 `json:"internal_host_port,omitempty"`
	WildcardInternalHostname     string                 `json:"wildcard_internal_hostname,omitempty"`
	IPAccessAllow                string                 `json:"ip_access_allow,omitempty"`
	CookieDomain                 *string                `json:"cookie_domain"`
	RequestParameters            map[string]interface{} `json:"request_parameters"`
	LoggingEnabled               string                 `json:"logging_enabled,omitempty"`
	LoginTimeout                 string                 `json:"login_timeout,omitempty"`
	AppAuth                      string                 `json:"app_auth"`
	WappAuth                     string                 `json:"wapp_auth,omitempty"`
	JWTIssuers                   string                 `json:"jwt_issuers,omitempty"`
	JWTAudience                  string                 `json:"jwt_audience,omitempty"`
	JWTGracePeriod               string                 `json:"jwt_grace_period,omitempty"`
	JWTReturnOption              string                 `json:"jwt_return_option,omitempty"`
	JWTUsername                  string                 `json:"jwt_username,omitempty"`
	JWTReturnURL                 string                 `json:"jwt_return_url,omitempty"`
	SSO                          string                 `json:"sso,omitempty"`
	HTTPOnlyCookie               string                 `json:"http_only_cookie,omitempty"`
	RequestBodyRewrite           string                 `json:"request_body_rewrite,omitempty"`
	IDPIdleExpiry                *string                `json:"idp_idle_expiry,omitempty"`
	IDPMaxExpiry                 *string                `json:"idp_max_expiry,omitempty"`
	HTTPSSSLV3                   string                 `json:"https_sslv3,omitempty"`
	SPDYEnabled                  string                 `json:"spdy_enabled,omitempty"`
	WebSocketEnabled             string                 `json:"websocket_enabled,omitempty"`
	HiddenApp                    string                 `json:"hidden_app,omitempty"`
	AppLocation                  *string                `json:"app_location"`
	AppCookieDomain              *string                `json:"app_cookie_domain,omitempty"`
	AppAuthDomain                string                 `json:"app_auth_domain,omitempty"`
	LoadBalancingMetric          string                 `json:"load_balancing_metric,omitempty"`
	HealthCheckType              string                 `json:"health_check_type,omitempty"`
	HealthCheckHTTPURL           string                 `json:"health_check_http_url,omitempty"`
	HealthCheckHTTPVersion       string                 `json:"health_check_http_version,omitempty"`
	HealthCheckHTTPHostHeader    *string                `json:"health_check_http_host_header,omitempty"`
	ProxyBufferSizeKB            string                 `json:"proxy_buffer_size_kb,omitempty"`
	SessionSticky                string                 `json:"session_sticky,omitempty"`
	SessionStickyCookieMaxAge    string                 `json:"session_sticky_cookie_maxage,omitempty"`
	SessionStickyServerCookie    *string                `json:"session_sticky_server_cookie,omitempty"`
	PassPhrase                   *string                `json:"pass_phrase,omitempty"`
	PrivateKey                   *string                `json:"private_key,omitempty"`
	HostKey                      *string                `json:"host_key,omitempty"`
	UserName                     *string                `json:"user_name,omitempty"`
	ExternalCookieDomain         *string                `json:"external_cookie_domain,omitempty"`
	ServicePrincipalName         *string                `json:"service_principle_name,omitempty"`
	ServerCertValidate           string                 `json:"server_cert_validate,omitempty"`
	IgnoreCnameResolution        string                 `json:"ignore_cname_resolution,omitempty"`
	SSHAuditEnabled              string                 `json:"ssh_audit_enabled,omitempty"`
	MFA                          string                 `json:"mfa,omitempty"`
	RefreshStickyCookie          string                 `json:"refresh_sticky_cookie,omitempty"`
	AppServerReadTimeout         string                 `json:"app_server_read_timeout,omitempty"`
	IdleConnFloor                string                 `json:"idle_conn_floor,omitempty"`
	IdleConnCeil                 string                 `json:"idle_conn_ceil,omitempty"`
	IdleConnStep                 string                 `json:"idle_conn_step,omitempty"`
	IdleCloseTimeSeconds         string                 `json:"idle_close_time_seconds,omitempty"`
	RateLimit                    string                 `json:"rate_limit,omitempty"`
	AuthenticatedServerReqLimit  string                 `json:"authenticated_server_request_limit,omitempty"`
	AnonymousServerReqLimit      string                 `json:"anonymous_server_request_limit,omitempty"`
	AuthenticatedServerConnLimit string                 `json:"authenticated_server_conn_limit,omitempty"`
	AnonymousServerConnLimit     string                 `json:"anonymous_server_conn_limit,omitempty"`
	ServerRequestBurst           string                 `json:"server_request_burst,omitempty"`
	HealthCheckRise              string                 `json:"health_check_rise,omitempty"`
	HealthCheckFall              string                 `json:"health_check_fall,omitempty"`
	HealthCheckTimeout           string                 `json:"health_check_timeout,omitempty"`
	HealthCheckInterval          string                 `json:"health_check_interval,omitempty"`
	KerberosNegotiateOnce        string                 `json:"kerberos_negotiate_once,omitempty"`
	InjectAjaxJavascript         string                 `json:"inject_ajax_javascript,omitempty"`
	SentryRedirect401            string                 `json:"sentry_redirect_401,omitempty"`
	ProxyDisableClipboard        string                 `json:"proxy_disable_clipboard,omitempty"`
	PreauthEnforceURL            string                 `json:"preauth_enforce_url,omitempty"`
	ForceMFA                     string                 `json:"force_mfa,omitempty"`
	IgnoreBypassMFA              string                 `json:"ignore_bypass_mfa,omitempty"`
	StickyAgent                  string                 `json:"sticky_agent,omitempty"`
	SaaSEnabled                  string                 `json:"saas_enabled,omitempty"`
	AllowCORS                    string                 `json:"allow_cors,omitempty"`
	CORSOriginList               string                 `json:"cors_origin_list,omitempty"`
	CORSMethodList               string                 `json:"cors_method_list,omitempty"`
	CORSHeaderList               string                 `json:"cors_header_list,omitempty"`
	CORSSupportCredential        string                 `json:"cors_support_credential,omitempty"`
	CORSMaxAge                   string                 `json:"cors_max_age,omitempty"`
	KeepaliveEnable              string                 `json:"keepalive_enable,omitempty"`
	KeepaliveConnectionPool      string                 `json:"keepalive_connection_pool,omitempty"`
	KeepaliveTimeout             string                 `json:"keepalive_timeout,omitempty"`
	KeyedKeepaliveEnable         string                 `json:"keyed_keepalive_enable,omitempty"`
	Keytab                       string                 `json:"keytab,omitempty"`
	EdgeCookieKey                string                 `json:"edge_cookie_key,omitempty"`
	SLAObjectURL                 string                 `json:"sla_object_url,omitempty"`
	ForwardTicketGrantingTicket  string                 `json:"forward_ticket_granting_ticket,omitempty"`
	InterceptURL                 string                 `json:"intercept_url,omitempty"`
	IsBrotliEnabled              string                 `json:"is_brotli_enabled,omitempty"`
	Onramp                       string                 `json:"onramp,omitempty"`
	SegmentationPolicyEnable     string                 `json:"segmentation_policy_enable,omitempty"`
	SentryRestoreFormPost        string                 `json:"sentry_restore_form_post,omitempty"`
	ServicePrincipleName         *string                `json:"service_principle_name,omitempty"`
	FormPostAttributes           []string               `json:"form_post_attributes,omitempty"`
	FormPostURL                  string                 `json:"form_post_url,omitempty"`
	EdgeAuthenticationEnabled    string                 `json:"edge_authentication_enabled,omitempty"`
	HSTSage                      string                 `json:"hsts_age,omitempty"`
	RDPInitialProgram            *string                `json:"rdp_initial_program,omitempty"`
	RemoteSparkMapClipboard      string                 `json:"remote_spark_mapClipboard,omitempty"`
	RDPLegacyMode                string                 `json:"rdp_legacy_mode,omitempty"`
	RemoteSparkAudio             string                 `json:"remote_spark_audio,omitempty"`
	RemoteSparkMapPrinter        string                 `json:"remote_spark_mapPrinter,omitempty"`
	RemoteSparkPrinter           string                 `json:"remote_spark_printer,omitempty"`
	RemoteSparkMapDisk           string                 `json:"remote_spark_mapDisk,omitempty"`
	RemoteSparkDisk              string                 `json:"remote_spark_disk,omitempty"`
	RemoteSparkRecording         string                 `json:"remote_spark_recording,omitempty"`
	ClientCertAuth               string                 `json:"client_cert_auth,omitempty"`
	ClientCertUserParam          string                 `json:"client_cert_user_param,omitempty"`
	G2OEnabled                   string                 `json:"g2o_enabled,omitempty"`
	G2ONonce                     *string                `json:"g2o_nonce,omitempty"`
	G2OKey                       *string                `json:"g2o_key,omitempty"`
	RDPTLS1                      string                 `json:"rdp_tls1,omitempty"`
	DomainExceptionList          string                 `json:"domain_exception_list,omitempty"`
	DisableUserAgentCheck        string                 `json:"disable_user_agent_check,omitempty"`
	EdgeTransportManualMode      string                 `json:"edge_transport_manual_mode,omitempty"`
	EdgeTransportPropertyID      *string                `json:"edge_transport_property_id,omitempty"`
	EnableClientSideXHRRewrite   string                 `json:"enable_client_side_xhr_rewrite,omitempty"`
	Acceleration                 string                 `json:"acceleration,omitempty"`
	OffloadOnPremiseTraffic      string                 `json:"offload_onpremise_traffic,omitempty"`
	AppClientCertAuth            string                 `json:"app_client_cert_auth,omitempty"`
	PreauthConsent               string                 `json:"preauth_consent,omitempty"`
	MDCEnable                    string                 `json:"mdc_enable,omitempty"`
	SingleHostEnable             string                 `json:"single_host_enable,omitempty"`
	SingleHostFQDN               string                 `json:"single_host_fqdn,omitempty"`
	SingleHostPath               string                 `json:"single_host_path,omitempty"`
	SingleHostContentRW          string                 `json:"single_host_content_rw,omitempty"`
	IsSSLVerificationEnabled     string                 `json:"is_ssl_verification_enabled,omitempty"`
	SingleHostCookieDomain       string                 `json:"single_host_cookie_domain,omitempty"`
	XWappReadTimeout             string                 `json:"x_wapp_read_timeout,omitempty"`
	XWappPoolEnabled             string                 `json:"x_wapp_pool_enabled,omitempty"`
	XWappPoolSize                string                 `json:"x_wapp_pool_size,omitempty"`
	XWappPoolTimeout             string                 `json:"x_wapp_pool_timeout,omitempty"`
	RDPKeyboardLang              string                 `json:"rdp_keyboard_lang,omitempty"`
	RDPRemoteApps                []string               `json:"rdp_remote_apps,omitempty"`
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`
	ForceIPRoute                 string                 `json:"force_ip_route,omitempty"`
	CustomHeaders                []CustomHeader         `json:"custom_headers,omitempty"`
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
	EntityID         string  `json:"entity_id"`
	Metadata         string  `json:"metadata"`
	SignCert         *string `json:"sign_cert,omitempty"`
	SignKey          string  `json:"sign_key"`
	SelfSigned       bool    `json:"self_signed"`
	SignAlgo         string  `json:"sign_algo"`
	RespBind         string  `json:"resp_bind"`
	SLOURL           string  `json:"slo_url"`
	ECPIsEnabled     bool    `json:"ecp_enable"`
	ECPRespSignature bool    `json:"ecp_resp_signature"`
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
	EntityID   string `json:"entity_id"`
	SignAlgo   string `json:"sign_algo"`
	SignCert   string `json:"sign_cert"`
	SignKey    string `json:"sign_key"`
	SelfSigned bool   `json:"self_signed"`
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
	ClientName            string             `json:"client_name"`
	ClientID              string             `json:"client_id"`
	ClientSecret          []OIDCClientSecret `json:"client_secret"`
	ResponseType          []string           `json:"response_type"`
	ImplicitGrant         bool               `json:"implicit_grant"`
	Type                  string             `json:"type"`
	RedirectURIs          []string           `json:"redirect_uris"`
	JavaScriptOrigins     []string           `json:"javascript_origins"`
	LogoutURL             string             `json:"logout_url"`
	LogoutSessionRequired bool               `json:"logout_session_required"`
	PostLogoutRedirectURI []string           `json:"post_logout_redirect_uri"`
	Metadata              string             `json:"metadata"`
	Claims                []OIDCClaim        `json:"claims"`
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
	Type         string            `json:"type"`
	UniqueItems  bool              `json:"uniqueItems"`
	Items        AttrMapItem       `json:"items"`
	AttributeMap map[string]string `json:"attribute_map"`
}

type AttrMapItem struct {
	Type       string                `json:"type"`
	Properties AttrMapItemProperties `json:"properties"`
	Required   []string              `json:"required"`
}

type AttrMapItemProperties struct {
	Name  AttrMapField `json:"name"`
	Fname AttrMapField `json:"fname"`
	Fmt   AttrMapField `json:"fmt"`
	Val   AttrMapField `json:"val"`
	Src   AttrMapField `json:"src"`
	Rule  AttrMapField `json:"rule"`
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
		EdgeTransportManualMode:      "true",
		EdgeTransportPropertyID:      nil,
		EnableClientSideXHRRewrite:   "false",
		ExternalCookieDomain:         nil,
		ForceIPRoute:                 "false",
		ForceMFA:                     "off",
		FormPostAttributes:           []string{},
		FormPostURL:                  "",
		ForwardTicketGrantingTicket:  "false",
		G2OEnabled:                   "true",
		G2OKey:                       nil,
		G2ONonce:                     nil,
		HealthCheckFall:              "3",
		HealthCheckHTTPURL:           "/",
		HealthCheckHTTPVersion:       "1.1",
		HealthCheckInterval:          "30000",
		HealthCheckRise:              "2",
		HealthCheckTimeout:           "50000",
		HealthCheckType:              "Default",
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
		IgnoreCnameResolution:        "true",
		InjectAjaxJavascript:         "off",
		InterceptURL:                 "",
		InternalHostPort:             "0",

		// JWT defaults
		JwtAudience:              "",
		JwtGracePeriod:           "60",
		JwtIssuers:               "",
		JwtReturnOption:          "401",
		JwtReturnUrl:             "",
		JwtUsername:              "",
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

		RDPRemoteApps:       []string{},
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
		"rate_limit":                          "RateLimit",
		"refresh_sticky_cookie":               "RefreshStickyCookie",
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
		"keyed_keepalive_enable":        "KeyedKeepaliveEnable",
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
		"session_sticky":                  "SessionSticky",
		"session_sticky_cookie_maxage":   "SessionStickyCookieMaxAge",
		"session_sticky_server_cookie":   "SessionStickyServerCookie",
		"single_host_fqdn":               "SingleHostFQDN",
		"single_host_path":               "SingleHostPath",
		"user_name":                      "UserName",
		"wildcard_internal_hostname":     "WildcardInternalHostname",

		// JWT fields
		"jwt_audience":      "JwtAudience",
		"jwt_grace_period":  "JwtGracePeriod",
		"jwt_issuers":       "JwtIssuers",
		"jwt_return_option": "JwtReturnOption",
		"jwt_return_url":    "JwtReturnUrl",
		"jwt_username":      "JwtUsername",
		"wapp_auth":         "WappAuth",
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
						// Map descriptive values to numeric values for health_check_type
						switch strVal {
						case "Default":
							value = "0"
						case "HTTP":
							value = "1"
						case "HTTPS":
							value = "2"
						case "SSL":
							value = "3"
						case "TCP":
							value = "4"
						case "None":
							value = "5"
						default:
							// Keep original value if it's already numeric
							value = strVal
						}
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
							fmt.Fprintf(os.Stderr, "ERROR: app_auth must be a string, got %T (value: %v). No automatic conversion allowed.\n", value, value)
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
							fmt.Fprintf(os.Stderr, "WARNING: Cannot convert string %s to integer for field %s, skipping\n", v, jsonKey)
							continue
						}
					default:
						fmt.Fprintf(os.Stderr, "WARNING: Cannot convert value type %T to integer for field %s, skipping\n", value, jsonKey)
						continue
					}
					field.SetInt(intVal)
				case reflect.Slice:
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
								fmt.Fprintf(os.Stderr, "WARNING: Cannot convert value type %T to string slice for field %s, skipping\n", value, jsonKey)
							}
							continue
						}
					} else {
						// For non-string slices, handle type conversion properly
						if reflect.TypeOf(value).AssignableTo(field.Type()) {
							field.Set(reflect.ValueOf(value))
						} else {
							fmt.Fprintf(os.Stderr, "WARNING: Cannot assign value type %T to field type %v for %s, skipping\n", value, field.Type(), jsonKey)
							continue
						}
					}
				}
			}
		}
	}
}


