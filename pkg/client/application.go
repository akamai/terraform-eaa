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

// MinimalCreateAppRequest represents the minimal fields required for basic app creation
// This follows the two-phase approach: create app first, then configure additional settings
type MinimalCreateAppRequest struct {
	Name          string `json:"name"`
	AppProfile    int    `json:"app_profile"`
	AppType       int    `json:"app_type"`
	ClientAppMode int    `json:"client_app_mode"`
}

type CreateAppRequest struct {
	Description      *string          `json:"description"`
	TLSSuiteName     *string          `json:"tls_suite_name,omitempty"`
	TLSSuiteType     *int             `json:"tlsSuiteType,omitempty"`
	OIDCSettings     *OIDCConfig      `json:"oidc_settings"`
	AdvancedSettings AdvancedSettings `json:"advanced_settings,omitempty"`
	Name             string           `json:"name"`
	AppBundle        string           `json:"app_bundle,omitempty"`
	SAMLSettings     []SAMLConfig     `json:"saml_settings"`
	WSFEDSettings    []WSFEDConfig    `json:"wsfed_settings"`
	AppType          int              `json:"app_type"`
	ClientAppMode    int              `json:"client_app_mode"`
	AppProfile       int              `json:"app_profile"`
	WSFED            bool             `json:"wsfed"`
	Oidc             bool             `json:"oidc"`
	SAML             bool             `json:"saml"`
}

// CreateMinimalAppRequestFromSchema creates a minimal app creation request with only essential fields
func (mcar *MinimalCreateAppRequest) CreateMinimalAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	logger := ec.Logger

	// Validate and set the name field (required)
	if name, ok := d.GetOk("name"); ok {
		nameStr, ok := name.(string)
		if ok && nameStr != "" {
			mcar.Name = nameStr
		} else {
			logger.Error("create Application failed. name is invalid")
			return ErrInvalidValue
		}
	} else {
		logger.Error("create Application failed. name is required")
		return ErrInvalidValue
	}

	// Set app_type with default
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
		mcar.AppType = value
		logger.Debug("appType", appType)
		logger.Debug("mcar.AppType", mcar.AppType)
	} else {
		logger.Debug("appType is not present, defaulting to enterprise")
		mcar.AppType = int(APP_TYPE_ENTERPRISE_HOSTED)
	}

	// Set app_profile with default
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
		mcar.AppProfile = value
		logger.Debug("appProfile", appProfile)
		logger.Debug("mcar.AppProfile", mcar.AppProfile)
	} else {
		logger.Debug("appProfile is not present, defaulting to http")
		mcar.AppProfile = int(APP_PROFILE_HTTP)
	}

	// Set client_app_mode with default
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
		mcar.ClientAppMode = value
		logger.Debug("appMode", clientAppMode)
		logger.Debug("mcar.ClientAppMode", mcar.ClientAppMode)
	} else {
		logger.Debug("appMode is not present, defaulting to tcp")
		mcar.ClientAppMode = int(CLIENT_APP_MODE_TCP)
	}

	logger.Debug("Minimal app creation request prepared successfully")
	return nil
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
		logger.Debug("appType is not present, defaulting to enterprise")
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
		logger.Debug("appProfile is not present, defaulting to http")
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
		logger.Debug("appMode is not present, defaulting to tcp")
		car.ClientAppMode = int(CLIENT_APP_MODE_TCP)
	}

	// Handle app_bundle field - validate name and get UUID
	var validatedAppBundleUUID string
	if appBundle, ok := d.GetOk("app_bundle"); ok {
		if appBundleStr, ok := appBundle.(string); ok && appBundleStr != "" {
			logger.Debug("CREATE FLOW: Found app_bundle:", appBundleStr)

			// Validate app bundle name and get UUID
			appBundleUUID, err := ec.GetAppBundleByName(appBundleStr)
			if err != nil {
				logger.Error("CREATE FLOW: Failed to validate app_bundle name '%s': %v", appBundleStr, err)
				return fmt.Errorf("invalid app_bundle name '%s': %w", appBundleStr, err)
			}

			validatedAppBundleUUID = appBundleUUID
			logger.Debug("CREATE FLOW: App bundle '%s' validated, UUID: %s", appBundleStr, appBundleUUID)
		}
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

	logger.Debug("CREATE FLOW: Using JSON:", advSettingsJSON)

	// ALWAYS parse and apply malformed defaults
	advSettings, err := ParseAdvancedSettingsWithDefaults(advSettingsJSON)
	if err != nil {
		return fmt.Errorf("failed to parse advanced settings JSON: %w", err)
	}

	// Extract TLS Suite fields from advanced_settings and set them at the top level
	// Parse the advanced_settings JSON to extract TLS Suite fields
	logger.Debug("CREATE FLOW: TLS Suite extraction - advSettingsJSON:", advSettingsJSON)
	var userSettings map[string]interface{}
	if err := json.Unmarshal([]byte(advSettingsJSON), &userSettings); err == nil {
		logger.Debug("CREATE FLOW: TLS Suite extraction - parsed userSettings:", userSettings)

		// Extract tlsSuiteType
		if tlsSuiteTypeVal, exists := userSettings["tlsSuiteType"]; exists {
			logger.Debug("CREATE FLOW: TLS Suite extraction - found tlsSuiteType:", tlsSuiteTypeVal)

			var tlsSuiteTypeInt int
			switch v := tlsSuiteTypeVal.(type) {
			case string:
				// Handle string values: "default" -> 1, "custom" -> 2
				switch v {
				case "default":
					tlsSuiteTypeInt = 1
				case "custom":
					tlsSuiteTypeInt = 2
				default:
					logger.Error("CREATE FLOW: Invalid tlsSuiteType string value:", v)
				}
			case float64:
				// Handle numeric values (for backward compatibility)
				tlsSuiteTypeInt = int(v)
			default:
				logger.Error("CREATE FLOW: Invalid tlsSuiteType type:", v)
				return fmt.Errorf("invalid tlsSuiteType type: %T", v)
			}

			car.TLSSuiteType = &tlsSuiteTypeInt
			logger.Debug("CREATE FLOW: Set tlsSuiteType from advanced_settings:", tlsSuiteTypeInt)
		} else {
			logger.Debug("CREATE FLOW: TLS Suite extraction - tlsSuiteType not found in userSettings")
		}

		// Extract tls_suite_name
		if tlsSuiteNameVal, exists := userSettings["tls_suite_name"]; exists {
			logger.Debug("CREATE FLOW: TLS Suite extraction - found tls_suite_name:", tlsSuiteNameVal)
			if tlsSuiteNameStr, ok := tlsSuiteNameVal.(string); ok {
				car.TLSSuiteName = &tlsSuiteNameStr
				logger.Debug("CREATE FLOW: Set tls_suite_name from advanced_settings:", tlsSuiteNameStr)
			}
		} else {
			logger.Debug("CREATE FLOW: TLS Suite extraction - tls_suite_name not found in userSettings")
		}
	} else {
		logger.Error("CREATE FLOW: TLS Suite extraction - failed to parse advSettingsJSON:", err)
	}

	// Set authentication flags based on Terraform boolean flags for CREATE flow
	// Preserve user-provided app_auth value from advanced_settings
	logger.Debug("CREATE FLOW: Using app_auth from advanced_settings:", advSettings.AppAuth)

	// Set authentication flags based on Terraform boolean flags
	// Reset all auth types to false first
	car.SAML = false
	car.Oidc = false
	car.WSFED = false

	// Initialize default settings for all auth types
	car.SAMLSettings = []SAMLConfig{}
	car.OIDCSettings = nil
	car.WSFEDSettings = []WSFEDConfig{}

	// Determine authentication method using shared helper (single-source of truth)
	enableSAML, enableOIDC, enableWSFED, normalizedAppAuth := decideAuthFromConfig(d, advSettings.AppAuth)
	if enableSAML || enableOIDC || enableWSFED {
		car.SAML = enableSAML
		car.Oidc = enableOIDC
		car.WSFED = enableWSFED
		// Use normalized app_auth: "none" for SAML/WSFED, "oidc" for OIDC
		advSettings.AppAuth = normalizedAppAuth
	}

	// Handle SAML settings for CREATE flow
	if car.SAML {
		// Use schema approach (nested blocks)
		if samlSettings, ok := d.GetOk("saml_settings"); ok {
			if samlSettingsList, ok := samlSettings.([]interface{}); ok && len(samlSettingsList) > 0 {
				// Convert nested blocks to SAMLConfig
				samlConfig, err := convertNestedBlocksToSAMLConfig(samlSettingsList[0].(map[string]interface{}))
				if err != nil {
					logger.Error("Failed to convert nested blocks to SAML config:", err)
					return fmt.Errorf("failed to convert nested blocks to SAML config: %w", err)
				}
				car.SAMLSettings = []SAMLConfig{samlConfig}
			}
		} else {
			// No saml_settings provided but SAML is enabled - create default structure
			car.SAMLSettings = []SAMLConfig{DefaultSAMLConfig}
		}
	} else {
		car.SAMLSettings = []SAMLConfig{}
	}

	// Always set the settings fields to ensure they appear in payload
	if !car.Oidc {
		car.OIDCSettings = nil
	} else {
		// Handle OIDC settings for CREATE flow
		if oidcSettings, ok := d.GetOk("oidc_settings"); ok {
			logger.Debug("CREATE FLOW: Found oidc_settings blocks")
			if oidcSettingsList, ok := oidcSettings.([]interface{}); ok && len(oidcSettingsList) > 0 {
				// Convert nested blocks to OIDCConfig
				oidcConfig, err := convertNestedBlocksToOIDCConfig(oidcSettingsList[0].(map[string]interface{}))
				if err != nil {
					logger.Error("CREATE FLOW: Failed to convert nested blocks to OIDC config:", err)
					return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
				}
				car.OIDCSettings = oidcConfig
				logger.Debug("CREATE FLOW: Successfully converted nested blocks to OIDC config")
			}
		} else {
			logger.Debug("CREATE FLOW: No oidc_settings found, creating defaults")
			car.OIDCSettings = &OIDCConfig{
				OIDCClients: []OIDCClient{
					{
						ClientName:        "default_client",
						ClientID:          "default_client_id",
						ResponseType:      []string{"code"},
						ImplicitGrant:     false,
						Type:              "standard",
						RedirectURIs:      []string{},
						JavaScriptOrigins: []string{},
						Claims:            []OIDCClaim{},
					},
				},
			}
		}
	}
	// Handle WS-Federation settings for CREATE flow
	if car.WSFED {
		if wsfedSettingsData, ok := d.GetOk("wsfed_settings"); ok {
			// User provided wsfed_settings as nested blocks - parse them
			logger.Debug("CREATE FLOW: Found wsfed_settings as nested blocks")
			if wsfedSettingsList, ok := wsfedSettingsData.([]interface{}); ok && len(wsfedSettingsList) > 0 {
				// Get the first (and only) wsfed_settings block
				wsfedBlock := wsfedSettingsList[0].(map[string]interface{})

				// Start with DefaultWSFEDConfig as base
				wsfedConfig := DefaultWSFEDConfig

				// Merge SP settings
				if spBlocks, ok := wsfedBlock["sp"].([]interface{}); ok && len(spBlocks) > 0 {
					spBlock := spBlocks[0].(map[string]interface{})

					if entityID, ok := spBlock["entity_id"].(string); ok && entityID != "" {
						wsfedConfig.SP.EntityID = entityID
					}
					if sloURL, ok := spBlock["slo_url"].(string); ok && sloURL != "" {
						wsfedConfig.SP.SLOURL = sloURL
					}
					if dstURL, ok := spBlock["dst_url"].(string); ok && dstURL != "" {
						wsfedConfig.SP.DSTURL = dstURL
					}
					if respBind, ok := spBlock["resp_bind"].(string); ok && respBind != "" {
						wsfedConfig.SP.RespBind = respBind
					}
					if tokenLife, ok := spBlock["token_life"].(int); ok {
						wsfedConfig.SP.TokenLife = tokenLife
					}
					if encrAlgo, ok := spBlock["encr_algo"].(string); ok && encrAlgo != "" {
						wsfedConfig.SP.EncrAlgo = encrAlgo
					}
				}

				// Merge IDP settings
				if idpBlocks, ok := wsfedBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
					idpBlock := idpBlocks[0].(map[string]interface{})

					if entityID, ok := idpBlock["entity_id"].(string); ok && entityID != "" {
						wsfedConfig.IDP.EntityID = entityID
					}
					if signAlgo, ok := idpBlock["sign_algo"].(string); ok && signAlgo != "" {
						wsfedConfig.IDP.SignAlgo = signAlgo
					}
					if signCert, ok := idpBlock["sign_cert"].(string); ok && signCert != "" {
						wsfedConfig.IDP.SignCert = signCert
					}
					if signKey, ok := idpBlock["sign_key"].(string); ok && signKey != "" {
						wsfedConfig.IDP.SignKey = signKey
					}
					if selfSigned, ok := idpBlock["self_signed"].(bool); ok {
						wsfedConfig.IDP.SelfSigned = selfSigned
					}
				}

				// Merge Subject settings
				if subjectBlocks, ok := wsfedBlock["subject"].([]interface{}); ok && len(subjectBlocks) > 0 {
					subjectBlock := subjectBlocks[0].(map[string]interface{})

					if fmtVal, ok := subjectBlock["fmt"].(string); ok && fmtVal != "" {
						wsfedConfig.Subject.Fmt = fmtVal
					}
					if customFmt, ok := subjectBlock["custom_fmt"].(string); ok && customFmt != "" {
						wsfedConfig.Subject.CustomFmt = customFmt
					}
					if src, ok := subjectBlock["src"].(string); ok && src != "" {
						wsfedConfig.Subject.Src = src
					}
					if val, ok := subjectBlock["val"].(string); ok && val != "" {
						wsfedConfig.Subject.Val = val
					}
					if rule, ok := subjectBlock["rule"].(string); ok && rule != "" {
						wsfedConfig.Subject.Rule = rule
					}
				}

				// Merge Attrmap settings
				if attrmapBlocks, ok := wsfedBlock["attrmap"].([]interface{}); ok && len(attrmapBlocks) > 0 {
					var attrmap []WSFEDAttrMapping
					for _, attrBlock := range attrmapBlocks {
						if attrMap, ok := attrBlock.(map[string]interface{}); ok {
							attr := WSFEDAttrMapping{}
							if name, ok := attrMap["name"].(string); ok {
								attr.Name = name
							}
							if fmtVal, ok := attrMap["fmt"].(string); ok {
								attr.Fmt = fmtVal
							}
							if customFmt, ok := attrMap["custom_fmt"].(string); ok {
								attr.CustomFmt = customFmt
							}
							if val, ok := attrMap["val"].(string); ok {
								attr.Val = val
							}
							if src, ok := attrMap["src"].(string); ok {
								attr.Src = src
							}
							if rule, ok := attrMap["rule"].(string); ok {
								attr.Rule = rule
							}
							attrmap = append(attrmap, attr)
						}
					}
					wsfedConfig.Attrmap = attrmap
				}

				// Use the merged configuration
				car.WSFEDSettings = []WSFEDConfig{wsfedConfig}
				logger.Debug("CREATE FLOW: Successfully merged WSFED config from nested blocks")
			}
		} else {
			// No wsfed_settings provided but WSFED is enabled - use default structure
			logger.Debug("CREATE FLOW: No wsfed_settings found, using DefaultWSFEDConfig")
			car.WSFEDSettings = []WSFEDConfig{DefaultWSFEDConfig}
		}
	} else {
		car.WSFEDSettings = []WSFEDConfig{}
	}

	// Handle app_bundle field from top-level resource - use validated UUID
	if validatedAppBundleUUID != "" {
		car.AppBundle = validatedAppBundleUUID
		logger.Debug("CREATE FLOW: Set app_bundle UUID on CreateAppRequest struct:", validatedAppBundleUUID)
	}

	car.AdvancedSettings = *advSettings

	return nil
}

// CreateMinimalApplication creates an application with minimal required fields only
func (mcar *MinimalCreateAppRequest) CreateMinimalApplication(ctx context.Context, ec *EaaClient) (*ApplicationResponse, error) {
	ec.Logger.Debug("create minimal application")

	// Log the minimal payload being sent to API
	payloadBytes, _ := json.MarshalIndent(mcar, "", "  ")
	ec.Logger.Debug("=== MINIMAL API PAYLOAD BEING SENT ===")
	ec.Logger.Debug(string(payloadBytes))
	ec.Logger.Debug("=== END MINIMAL API PAYLOAD ===")

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, APPS_URL)
	var appResp ApplicationResponse
	createAppResp, err := ec.SendAPIRequest(apiURL, "POST", mcar, &appResp, false)

	if err != nil {
		ec.Logger.Error("create minimal Application failed. err", err)
		return nil, err
	}

	if createAppResp.StatusCode != http.StatusOK {
		desc, _ := FormatErrorResponse(createAppResp)
		createErrMsg := fmt.Errorf("%w: %s", ErrAppCreate, desc)

		ec.Logger.Error("create minimal Application failed. StatusCode %d %s", createAppResp.StatusCode, desc)
		return nil, createErrMsg
	}
	ec.Logger.Debug("create minimal Application succeeded.", "name", mcar.Name)
	return &appResp, nil
}

func (car *CreateAppRequest) CreateApplication(ctx context.Context, ec *EaaClient) (*ApplicationResponse, error) {
	ec.Logger.Debug("create application")

	// Log the complete payload being sent to API
	payloadBytes, _ := json.MarshalIndent(car, "", "  ")
	ec.Logger.Debug("=== COMPLETE API PAYLOAD BEING SENT ===")
	ec.Logger.Debug(string(payloadBytes))
	ec.Logger.Debug("=== END API PAYLOAD ===")

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
	ec.Logger.Debug("create Application succeeded.", "name", car.Name)
	return &appResp, nil
}

// Configuration functions for Phase 2 of the two-phase approach

// ConfigureAgents assigns agents to an existing application
func ConfigureAgents(ctx context.Context, appID string, d *schema.ResourceData, ec *EaaClient) error {
	logger := ec.Logger

	if agentsRaw, ok := d.GetOk("agents"); ok {
		agentsList := agentsRaw.([]interface{})
		var agents AssignAgents
		agents.AppId = appID
		for _, v := range agentsList {
			if name, ok := v.(string); ok {
				agents.AgentNames = append(agents.AgentNames, name)
			}
		}
		err := agents.AssignAgents(ctx, ec)
		if err != nil {
			logger.Error("configure agents failed. err", err)
			return err
		}
		logger.Debug("configure agents succeeded.")
	}
	return nil
}

// ConfigureAuthentication configures authentication settings for an existing application
func ConfigureAuthentication(ctx context.Context, appID string, d *schema.ResourceData, ec *EaaClient) error {
	logger := ec.Logger

	auth_enabled := "false"
	if aE, ok := d.GetOk("auth_enabled"); ok {
		auth_enabled = aE.(string)
	}

	if auth_enabled == "true" {
		if appAuth, ok := d.GetOk("app_authentication"); ok {
			appAuthList := appAuth.([]interface{})
			if appAuthList == nil {
				return ErrInvalidValue
			}
			if len(appAuthList) > 0 {
				appAuthenticationMap := appAuthList[0].(map[string]interface{})
				if appAuthenticationMap == nil {
					logger.Error("invalid authentication data")
					return ErrInvalidValue
				}

				// Check if app_idp key is present
				if app_idp_name, ok := appAuthenticationMap["app_idp"].(string); ok {
					idpData, err := GetIdpWithName(ctx, ec, app_idp_name)
					if err != nil || idpData == nil {
						logger.Error("get idp with name error, err ", err)
						return err
					}
					logger.Debug("appID: ", appID, "app_idp_name: ", app_idp_name, "idpData.UUIDURL: ", idpData.UUIDURL)

					logger.Debug("Assigning IDP to application")

					appIdp := AppIdp{
						App: appID,
						IDP: idpData.UUIDURL,
					}
					err = appIdp.AssignIDP(ec)
					if err != nil {
						logger.Error("IDP assign error: ", err)
						return fmt.Errorf("assigning IDP to the app failed: %v", err)
					}
					logger.Debug("IDP assigned successfully, appID = ", appID, "idp = ", app_idp_name)

					// check if app_directories are present
					if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
						logger.Debug("Starting directory assignment...")
						err := idpData.AssignIdpDirectories(ctx, appDirs, appID, ec)
						if err != nil {
							logger.Error("directory assignment error: ", err)
							return fmt.Errorf("assigning directories to the app failed: %v", err)
						}
						logger.Debug("Directory assignment succeeded.")
					}
				}
			}
		}
	}
	return nil
}

// ConfigureAdvancedSettings configures advanced settings for an existing application
func ConfigureAdvancedSettings(ctx context.Context, appID string, d *schema.ResourceData, ec *EaaClient) error {
	logger := ec.Logger

	// Create update request with advanced settings
	updateRequest := ApplicationUpdateRequest{}

	// Get the current app data
	var appResp ApplicationResponse
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, appID)
	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		logger.Error("failed to get app for advanced settings configuration: ", err)
		return err
	}
	if getResp.StatusCode != http.StatusOK {
		desc, _ := FormatErrorResponse(getResp)
		logger.Error("failed to get app for advanced settings configuration. StatusCode %d %s", getResp.StatusCode, desc)
		return fmt.Errorf("failed to get app: %s", desc)
	}

	// Convert response to Application struct
	app := Application{}
	app.FromResponse(&appResp)
	updateRequest.Application = app

	// Update the request with advanced settings from schema
	err = updateRequest.UpdateAppRequestFromSchema(ctx, d, ec)
	if err != nil {
		logger.Error("failed to prepare advanced settings update request: ", err)
		return err
	}

	// Apply authentication transformation logic using centralized helper
	authResult := applyAuthTransformation(d)
	if authResult.EnableSAML || authResult.EnableOIDC || authResult.EnableWSFED {
		updateRequest.SAML = authResult.EnableSAML
		updateRequest.Oidc = authResult.EnableOIDC
		updateRequest.WSFED = authResult.EnableWSFED
		// Set app_auth: "none" for SAML/WSFED, "oidc" for OIDC
		updateRequest.AdvancedSettings.AppAuth = authResult.AppAuth
		if authResult.EnableOIDC {
			updateRequest.SAMLSettings = []SAMLConfig{}
		}
	}

	// Debug: Log the complete payload being sent

	// Apply the update
	err = updateRequest.UpdateApplication(ctx, ec)
	if err != nil {
		logger.Error("failed to apply advanced settings: ", err)
		return err
	}

	logger.Debug("configure advanced settings succeeded.")
	return nil
}

// DeployExistingApplication deploys an existing application
func DeployExistingApplication(ctx context.Context, appID string, ec *EaaClient) error {
	logger := ec.Logger

	// Get the current app data
	var appResp ApplicationResponse
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, appID)
	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		logger.Error("failed to get app for deployment: ", err)
		return err
	}
	if getResp.StatusCode != http.StatusOK {
		desc, _ := FormatErrorResponse(getResp)
		logger.Error("failed to get app for deployment. StatusCode %d %s", getResp.StatusCode, desc)
		return fmt.Errorf("failed to get app: %s", desc)
	}

	// Convert response to Application struct
	app := Application{}
	app.FromResponse(&appResp)

	// Deploy the application
	err = app.DeployApplication(ec)
	if err != nil {
		logger.Error("deploy application failed: ", err)
		return err
	}

	logger.Debug("deploy application succeeded.")
	return nil
}

type Application struct {
	Cert                   *string              `json:"cert"`
	Description            *string              `json:"description"`
	OIDCSettings           *OIDCConfig          `json:"oidc_settings,omitempty"`
	CName                  *string              `json:"cname"`
	Host                   *string              `json:"host"`
	TLSSuiteType           *int                 `json:"tlsSuiteType,omitempty"`
	AppLogo                *string              `json:"app_logo"`
	TLSSuiteName           *string              `json:"tls_suite_name"`
	OriginHost             *string              `json:"origin_host"`
	AppProfileID           *string              `json:"app_profile_id"`
	AppCategory            AppCategory          `json:"app_category"`
	AuthEnabled            string               `json:"auth_enabled"`
	AppBundle              string               `json:"app_bundle,omitempty"`
	POP                    string               `json:"pop"`
	POPName                string               `json:"popName"`
	POPRegion              string               `json:"popRegion"`
	RDPVersion             string               `json:"rdp_version"`
	UUIDURL                string               `json:"uuid_url"`
	BookmarkURL            string               `json:"bookmark_url"`
	SSLCACert              string               `json:"ssl_ca_cert"`
	Name                   string               `json:"name"`
	OrigTLS                string               `json:"orig_tls"`
	Servers                []Server             `json:"servers"`
	SAMLSettings           []SAMLConfig         `json:"saml_settings,omitempty"`
	TunnelInternalHosts    []TunnelInternalHost `json:"tunnel_internal_hosts"`
	WSFEDSettings          []WSFEDConfig        `json:"wsfed_settings"`
	OriginPort             int                  `json:"origin_port"`
	AppType                int                  `json:"app_type"`
	AppStatus              int                  `json:"app_status"`
	AppOperational         int                  `json:"app_operational"`
	Status                 int                  `json:"status"`
	AuthType               int                  `json:"auth_type"`
	SupportedClientVersion int                  `json:"supported_client_version"`
	AppProfile             int                  `json:"app_profile"`
	ClientAppMode          int                  `json:"client_app_mode"`
	AppDeployed            bool                 `json:"app_deployed"`
	Oidc                   bool                 `json:"oidc"`
	FQDNBridgeEnabled      bool                 `json:"fqdn_bridge_enabled"`
	WSFED                  bool                 `json:"wsfed"`
	SAML                   bool                 `json:"saml"`
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
	app.AppBundle = ar.AppBundle

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
	ec.Logger.Debug("updateG2O")
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
	ec.Logger.Debug("UpdateEdgeAuthentication")
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
	OIDCSettings     *OIDCConfig               `json:"oidc_settings"`
	Domain           string                    `json:"domain"`
	AdvancedSettings AdvancedSettings_Complete `json:"advanced_settings"`
	SAMLSettings     []SAMLConfig              `json:"saml_settings"`
	WSFEDSettings    []WSFEDConfig             `json:"wsfed_settings"`
	Application
}

func (appUpdateReq *ApplicationUpdateRequest) UpdateAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	ec.Logger.Debug("updating application")

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

	// Store app bundle UUID for later use after UpdateAdvancedSettings
	var validatedAppBundleUUID string
	if appBundle, ok := d.GetOk("app_bundle"); ok {
		if appBundleStr, ok := appBundle.(string); ok && appBundleStr != "" {
			// Validate app bundle name and get UUID
			appBundleUUID, err := ec.GetAppBundleByName(appBundleStr)
			if err != nil {
				ec.Logger.Error("UPDATE FLOW: Failed to validate app_bundle name '%s': %v", appBundleStr, err)
				return fmt.Errorf("invalid app_bundle name '%s': %w", appBundleStr, err)
			}

			validatedAppBundleUUID = appBundleUUID
			ec.Logger.Debug("UPDATE FLOW: App bundle '%s' validated, UUID: %s", appBundleStr, appBundleUUID)
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

			// Preserve user-provided app_auth value from advanced_settings
			ec.Logger.Debug("UPDATE FLOW: Using app_auth from advanced_settings:", advSettings.AppAuth)

			// Extract TLS Suite fields from advanced_settings and set them at the top level
			// Parse the advanced_settings JSON to extract TLS Suite fields
			ec.Logger.Debug("UPDATE FLOW: TLS Suite extraction - advSettingsJSON:", advSettingsJSON)
			var userSettings map[string]interface{}
			if err := json.Unmarshal([]byte(advSettingsJSON), &userSettings); err == nil {
				ec.Logger.Debug("UPDATE FLOW: TLS Suite extraction - parsed userSettings:", userSettings)

				// Extract tlsSuiteType
				if tlsSuiteTypeVal, exists := userSettings["tlsSuiteType"]; exists {
					ec.Logger.Debug("UPDATE FLOW: TLS Suite extraction - found tlsSuiteType:", tlsSuiteTypeVal)

					var tlsSuiteTypeInt int
					switch v := tlsSuiteTypeVal.(type) {
					case string:
						// Handle string values: "default" -> 1, "custom" -> 2
						switch v {
						case "default":
							tlsSuiteTypeInt = 1
						case "custom":
							tlsSuiteTypeInt = 2
						default:
							ec.Logger.Error("UPDATE FLOW: Invalid tlsSuiteType string value:", v)
							return fmt.Errorf("invalid tlsSuiteType string value: %s", v)
						}
					case float64:
						// Handle numeric values (for backward compatibility)
						tlsSuiteTypeInt = int(v)
					default:
						ec.Logger.Error("UPDATE FLOW: Invalid tlsSuiteType type:", v)
						return fmt.Errorf("invalid tlsSuiteType type: %T", v)
					}

					appUpdateReq.TLSSuiteType = &tlsSuiteTypeInt
					ec.Logger.Debug("UPDATE FLOW: Set tlsSuiteType from advanced_settings:", tlsSuiteTypeInt)
				} else {
					ec.Logger.Debug("UPDATE FLOW: TLS Suite extraction - tlsSuiteType not found in userSettings")
				}

				// Extract tls_suite_name
				if tlsSuiteNameVal, exists := userSettings["tls_suite_name"]; exists {
					ec.Logger.Debug("UPDATE FLOW: TLS Suite extraction - found tls_suite_name:", tlsSuiteNameVal)
					if tlsSuiteNameStr, ok := tlsSuiteNameVal.(string); ok {
						appUpdateReq.TLSSuiteName = &tlsSuiteNameStr
						ec.Logger.Debug("UPDATE FLOW: Set tls_suite_name from advanced_settings:", tlsSuiteNameStr)
					}
				} else {
					ec.Logger.Debug("UPDATE FLOW: TLS Suite extraction - tls_suite_name not found in userSettings")
				}
			} else {
				ec.Logger.Error("UPDATE FLOW: TLS Suite extraction - failed to parse advSettingsJSON:", err)
			}

			// Note: SAML/OIDC/WS-FED settings are now handled outside this block
			// to ensure they run regardless of whether advanced_settings is provided

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

			// Set the app bundle UUID on the Application struct (top-level field)
			if validatedAppBundleUUID != "" {
				appUpdateReq.AppBundle = validatedAppBundleUUID
				ec.Logger.Debug("UPDATE FLOW: Set app_bundle UUID on Application struct:", validatedAppBundleUUID)
			}

			// Log the final advanced settings to see what's being sent
			ec.Logger.Debug("UPDATE FLOW: Final advanced settings AppAuth:", appUpdateReq.AdvancedSettings.AppAuth)

			// Debug output for RDP fields

		}
	}

	// Set authentication flags based on Terraform boolean flags for UPDATE flow
	// This logic runs regardless of whether advanced_settings is provided

	// Determine SAML automatically based on business logic for UPDATE flow
	// Get app_auth from advanced_settings for business logic
	var appAuth string
	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		if advSettingsJSON, ok := advSettingsData.(string); ok && advSettingsJSON != "" {
			advSettings, err := ParseAdvancedSettingsWithDefaults(advSettingsJSON)
			if err == nil && advSettings != nil {
				appAuth = advSettings.AppAuth
			}
		}
	}

	// Check if SAML should be enabled based on app configuration
	samlResult := shouldEnableAuthForCreate(d, appAuth, getAuthProtocolConfig(AuthProtocolTypeSAML))

	if samlResult {
		ec.Logger.Debug("SAML automatically enabled based on app configuration")
		appUpdateReq.SAML = true
		appUpdateReq.Oidc = false
		appUpdateReq.WSFED = false
		// Override app_auth to "none" when SAML is enabled
		appUpdateReq.AdvancedSettings.AppAuth = "none"
		ec.Logger.Debug("SAML enabled, app_auth set to 'none'")

		// Use schema approach (nested blocks)
		if samlSettings, ok := d.GetOk("saml_settings"); ok {
			ec.Logger.Debug("UPDATE FLOW: Found saml_settings blocks")
			if samlSettingsList, ok := samlSettings.([]interface{}); ok && len(samlSettingsList) > 0 {
				// Defensively check type of first element before asserting
				if samlBlock, ok := samlSettingsList[0].(map[string]interface{}); ok {
					// Convert nested blocks to SAMLConfig
					samlConfig, err := convertNestedBlocksToSAMLConfig(samlBlock)
					if err != nil {
						ec.Logger.Error("UPDATE FLOW: Failed to convert nested blocks to SAML config:", err)
						return fmt.Errorf("failed to convert nested blocks to SAML config: %w", err)
					}
					appUpdateReq.SAMLSettings = []SAMLConfig{samlConfig}
					ec.Logger.Debug("UPDATE FLOW: Successfully converted nested blocks to SAML config")
				} else {
					ec.Logger.Error("UPDATE FLOW: saml_settings[0] is not a map[string]interface{}")
					return fmt.Errorf("invalid saml_settings format: expected map[string]interface{}")
				}
			} else {
				// No saml_settings provided but SAML is enabled - use DefaultSAMLConfig
				ec.Logger.Debug("UPDATE FLOW: No saml_settings found, using DefaultSAMLConfig")
				appUpdateReq.SAMLSettings = []SAMLConfig{DefaultSAMLConfig}
				ec.Logger.Debug("UPDATE FLOW: Set SAMLSettings with DefaultSAMLConfig")
			}
		}
	} else {
		oidcResult := shouldEnableAuthForCreate(d, appAuth, getAuthProtocolConfig(AuthProtocolTypeOIDC))

		if oidcResult {
			ec.Logger.Debug("OIDC automatically enabled based on app configuration")
			appUpdateReq.SAML = false
			appUpdateReq.Oidc = true
			appUpdateReq.WSFED = false
			// Override app_auth only when oidc=true
			appUpdateReq.AdvancedSettings.AppAuth = "oidc"
			appUpdateReq.SAMLSettings = []SAMLConfig{} // Clear SAML settings when OIDC is enabled

			// Handle OIDC settings for UPDATE flow
			if oidcSettings, ok := d.GetOk("oidc_settings"); ok {
				ec.Logger.Debug("UPDATE FLOW: Found oidc_settings blocks")
				if oidcSettingsList, ok := oidcSettings.([]interface{}); ok && len(oidcSettingsList) > 0 {
					// Defensively check type of first element before asserting
					if oidcBlock, ok := oidcSettingsList[0].(map[string]interface{}); ok {
						// Convert nested blocks to OIDCConfig
						oidcConfig, err := convertNestedBlocksToOIDCConfig(oidcBlock)
						if err != nil {
							ec.Logger.Error("UPDATE FLOW: Failed to convert nested blocks to OIDC config:", err)
							return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
						}
						appUpdateReq.OIDCSettings = oidcConfig
						ec.Logger.Debug("UPDATE FLOW: Successfully converted nested blocks to OIDC config")
					} else {
						ec.Logger.Error("UPDATE FLOW: oidc_settings[0] is not a map[string]interface{}")
						return fmt.Errorf("invalid oidc_settings format: expected map[string]interface{}")
					}
				} else {
					ec.Logger.Debug("UPDATE FLOW: No oidc_settings found, creating defaults")
					appUpdateReq.OIDCSettings = &OIDCConfig{
						OIDCClients: []OIDCClient{
							{
								ClientName:        "default_client",
								ClientID:          "default_client_id",
								ResponseType:      []string{"code"},
								ImplicitGrant:     false,
								Type:              "standard",
								RedirectURIs:      []string{},
								JavaScriptOrigins: []string{},
								Claims:            []OIDCClaim{},
							},
						},
					}
				}
			} else {
				ec.Logger.Debug("UPDATE FLOW: No oidc_settings found, creating defaults")
				appUpdateReq.OIDCSettings = &OIDCConfig{
					OIDCClients: []OIDCClient{
						{
							ClientName:        "default_client",
							ClientID:          "default_client_id",
							ResponseType:      []string{"code"},
							ImplicitGrant:     false,
							Type:              "standard",
							RedirectURIs:      []string{},
							JavaScriptOrigins: []string{},
							Claims:            []OIDCClaim{},
						},
					},
				}
			}
		} else if shouldEnableAuthForCreate(d, appAuth, getAuthProtocolConfig(AuthProtocolTypeWSFED)) {
			ec.Logger.Debug("WSFED automatically enabled based on app configuration")
			appUpdateReq.SAML = false
			appUpdateReq.Oidc = false
			appUpdateReq.WSFED = true
			// Override app_auth to "none" when WSFED is enabled
			appUpdateReq.AdvancedSettings.AppAuth = "none"
			ec.Logger.Debug("WSFED enabled, app_auth set to 'none'")
			appUpdateReq.SAMLSettings = []SAMLConfig{} // Clear SAML settings when WS-FED is enabled
		}
	}

	// Handle WS-Federation settings for UPDATE flow
	if appUpdateReq.WSFED {
		if wsfedSettingsData, ok := d.GetOk("wsfed_settings"); ok {
			// User provided wsfed_settings as nested blocks - parse them
			ec.Logger.Debug("UPDATE FLOW: Found wsfed_settings as nested blocks")
			if wsfedSettingsList, ok := wsfedSettingsData.([]interface{}); ok && len(wsfedSettingsList) > 0 {
				// Defensively check type of first element before asserting
				wsfedBlock, ok := wsfedSettingsList[0].(map[string]interface{})
				if !ok {
					ec.Logger.Error("UPDATE FLOW: wsfed_settings[0] is not a map[string]interface{}")
					return fmt.Errorf("invalid wsfed_settings format: expected map[string]interface{}")
				}

				// Start with DefaultWSFEDConfig as base
				wsfedConfig := DefaultWSFEDConfig

				// Merge SP settings
				if spBlocks, ok := wsfedBlock["sp"].([]interface{}); ok && len(spBlocks) > 0 {
					spBlock := spBlocks[0].(map[string]interface{})

					if entityID, ok := spBlock["entity_id"].(string); ok && entityID != "" {
						wsfedConfig.SP.EntityID = entityID
					}
					if sloURL, ok := spBlock["slo_url"].(string); ok && sloURL != "" {
						wsfedConfig.SP.SLOURL = sloURL
					}
					if dstURL, ok := spBlock["dst_url"].(string); ok && dstURL != "" {
						wsfedConfig.SP.DSTURL = dstURL
					}
					if respBind, ok := spBlock["resp_bind"].(string); ok && respBind != "" {
						wsfedConfig.SP.RespBind = respBind
					}
					if tokenLife, ok := spBlock["token_life"].(int); ok {
						wsfedConfig.SP.TokenLife = tokenLife
					}
					if encrAlgo, ok := spBlock["encr_algo"].(string); ok && encrAlgo != "" {
						wsfedConfig.SP.EncrAlgo = encrAlgo
					}
				}

				// Merge IDP settings
				if idpBlocks, ok := wsfedBlock["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
					idpBlock := idpBlocks[0].(map[string]interface{})

					if entityID, ok := idpBlock["entity_id"].(string); ok && entityID != "" {
						wsfedConfig.IDP.EntityID = entityID
					}
					if signAlgo, ok := idpBlock["sign_algo"].(string); ok && signAlgo != "" {
						wsfedConfig.IDP.SignAlgo = signAlgo
					}
					if signCert, ok := idpBlock["sign_cert"].(string); ok && signCert != "" {
						wsfedConfig.IDP.SignCert = signCert
					}
					if signKey, ok := idpBlock["sign_key"].(string); ok && signKey != "" {
						wsfedConfig.IDP.SignKey = signKey
					}
					if selfSigned, ok := idpBlock["self_signed"].(bool); ok {
						wsfedConfig.IDP.SelfSigned = selfSigned
					}
				}

				// Merge Subject settings
				if subjectBlocks, ok := wsfedBlock["subject"].([]interface{}); ok && len(subjectBlocks) > 0 {
					subjectBlock := subjectBlocks[0].(map[string]interface{})

					if fmtVal, ok := subjectBlock["fmt"].(string); ok && fmtVal != "" {
						wsfedConfig.Subject.Fmt = fmtVal
					}
					if customFmt, ok := subjectBlock["custom_fmt"].(string); ok && customFmt != "" {
						wsfedConfig.Subject.CustomFmt = customFmt
					}
					if src, ok := subjectBlock["src"].(string); ok && src != "" {
						wsfedConfig.Subject.Src = src
					}
					if val, ok := subjectBlock["val"].(string); ok && val != "" {
						wsfedConfig.Subject.Val = val
					}
					if rule, ok := subjectBlock["rule"].(string); ok && rule != "" {
						wsfedConfig.Subject.Rule = rule
					}
				}

				// Merge Attrmap settings
				if attrmapBlocks, ok := wsfedBlock["attrmap"].([]interface{}); ok && len(attrmapBlocks) > 0 {
					var attrmap []WSFEDAttrMapping
					for _, attrBlock := range attrmapBlocks {
						if attrMap, ok := attrBlock.(map[string]interface{}); ok {
							attr := WSFEDAttrMapping{}
							if name, ok := attrMap["name"].(string); ok {
								attr.Name = name
							}
							if fmtVal, ok := attrMap["fmt"].(string); ok {
								attr.Fmt = fmtVal
							}
							if customFmt, ok := attrMap["custom_fmt"].(string); ok {
								attr.CustomFmt = customFmt
							}
							if val, ok := attrMap["val"].(string); ok {
								attr.Val = val
							}
							if src, ok := attrMap["src"].(string); ok {
								attr.Src = src
							}
							if rule, ok := attrMap["rule"].(string); ok {
								attr.Rule = rule
							}
							attrmap = append(attrmap, attr)
						}
					}
					wsfedConfig.Attrmap = attrmap
				}

				// Use the merged configuration
				appUpdateReq.WSFEDSettings = []WSFEDConfig{wsfedConfig}
				ec.Logger.Debug("UPDATE FLOW: Successfully merged WSFED config from nested blocks")
			}
		} else {
			// No wsfed_settings provided but WSFED is enabled - use default structure
			ec.Logger.Debug("UPDATE FLOW: No wsfed_settings found, using DefaultWSFEDConfig")
			appUpdateReq.WSFEDSettings = []WSFEDConfig{DefaultWSFEDConfig}
		}
	} else {
		appUpdateReq.WSFEDSettings = []WSFEDConfig{}
	}

	// Handle OIDC settings for UPDATE flow
	var oidcConfig *OIDCConfig

	if appUpdateReq.Oidc {
		if oidcSettingsData, ok := d.GetOk("oidc_settings"); ok {
			ec.Logger.Debug("UPDATE FLOW: Found oidc_settings blocks")
			if oidcSettingsList, ok := oidcSettingsData.([]interface{}); ok && len(oidcSettingsList) > 0 {
				// Convert nested blocks to OIDCConfig (consistent with CREATE flow)
				convertedConfig, err := convertNestedBlocksToOIDCConfig(oidcSettingsList[0].(map[string]interface{}))
				if err != nil {
					ec.Logger.Error("UPDATE FLOW: Failed to convert nested blocks to OIDC config:", err)
					return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
				}
				oidcConfig = convertedConfig
				ec.Logger.Debug("UPDATE FLOW: Successfully converted nested blocks to OIDC config")
			}
		} else {
			ec.Logger.Debug("UPDATE FLOW: No oidc_settings found, creating defaults")
			oidcConfig = &OIDCConfig{
				OIDCClients: []OIDCClient{
					{
						ClientName:        "default_client",
						ClientID:          "default_client_id",
						ResponseType:      []string{"code"},
						ImplicitGrant:     false,
						Type:              "standard",
						RedirectURIs:      []string{},
						JavaScriptOrigins: []string{},
						Claims:            []OIDCClaim{},
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
	ec.Logger.Debug("Custom domain")

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
	ec.Logger.Debug("Certificate type: ", appCert)

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
			ec.Logger.Debug("Using existing self-signed certificate: ", appUpdateReq.Cert)
			return nil
		} else {
			ec.Logger.Debug("Generating self-signed certificate")
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
			ec.Logger.Debug("Generated self-signed certificate: ", appUpdateReq.Cert)
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
			ec.Logger.Debug("using uploaded cert : ", appUpdateReq.Cert)
			return nil
		}
	}

	return nil
}

func (appUpdateReq *ApplicationUpdateRequest) UpdateApplication(ctx context.Context, ec *EaaClient) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, appUpdateReq.UUIDURL)
	ec.Logger.Debug("API URL: ", apiURL)

	// Debug: Log the final app bundle before sending to API
	ec.Logger.Debug("FINAL PAYLOAD: AppBundle = '%s'", appUpdateReq.AppBundle)

	// Debug: Log the complete request payload
	payloadJSON, _ := json.MarshalIndent(appUpdateReq, "", "  ")
	ec.Logger.Debug("COMPLETE REQUEST PAYLOAD:\n%s", string(payloadJSON))

	appUpdResp, err := ec.SendAPIRequest(apiURL, "PUT", appUpdateReq, nil, false)
	if err != nil {
		ec.Logger.Error("update application failed. err: ", err)
		return err
	}

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
		ec.Logger.Debug("API RESPONSE:")
		responseJSON, _ := json.MarshalIndent(responseData, "", "  ")
		ec.Logger.Debug(string(responseJSON))

		// Show specific advanced settings from response
		if advancedSettings, ok := responseData["advanced_settings"].(map[string]interface{}); ok {
			ec.Logger.Debug("ADVANCED SETTINGS FROM RESPONSE:")
			if appAuthDomain, exists := advancedSettings["app_auth_domain"]; exists {
				ec.Logger.Debug(fmt.Sprintf("app_auth_domain: %v (type: %T)", appAuthDomain, appAuthDomain))
			} else {
				ec.Logger.Debug("app_auth_domain: not present in response")
			}
			if appClientCertAuth, exists := advancedSettings["app_client_cert_auth"]; exists {
				ec.Logger.Debug(fmt.Sprintf("app_client_cert_auth: %v (type: %T)", appClientCertAuth, appClientCertAuth))
			} else {
				ec.Logger.Debug("app_client_cert_auth: not present in response")
			}
			if acceleration, exists := advancedSettings["acceleration"]; exists {
				ec.Logger.Debug(fmt.Sprintf("acceleration: %v (type: %T)", acceleration, acceleration))
			} else {
				ec.Logger.Debug("acceleration: not present in response")
			}
		}
		ec.Logger.Debug("")
	}

	return nil
}

type ApplicationDataModel struct {
	AdvancedSettings AdvancedSettings `json:"advanced_settings"`
	Application
	Domain int `json:"domain"`
}

type Server struct {
	OriginHost     string `json:"origin_host"`
	OriginProtocol string `json:"origin_protocol"`
	OriginPort     int    `json:"origin_port"`
	OrigTLS        bool   `json:"orig_tls"`
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
	AdvancedSettings       AdvancedSettings_Complete `json:"advanced_settings"`
	OriginHost             *string                   `json:"origin_host"`
	Host                   *string                   `json:"host"`
	AppLogo                *string                   `json:"app_logo"`
	OIDCSettings           *OIDCSettings             `json:"oidc_settings,omitempty"`
	Description            *string                   `json:"description"`
	AppProfileID           *string                   `json:"app_profile_id"`
	CName                  *string                   `json:"cname"`
	TLSSuiteName           *string                   `json:"tls_suite_name"`
	Cert                   *string                   `json:"cert"`
	AppCategory            AppCategory               `json:"app_category"`
	CreatedAt              string                    `json:"created_at"`
	DomainSuffix           string                    `json:"domain_suffix"`
	AuthEnabled            string                    `json:"auth_enabled"`
	RDPVersion             string                    `json:"rdp_version"`
	UUIDURL                string                    `json:"uuid_url"`
	Resource               string                    `json:"resource"`
	BookmarkURL            string                    `json:"bookmark_url"`
	POP                    string                    `json:"pop"`
	FailoverPopName        string                    `json:"failover_popName"`
	SSLCACert              string                    `json:"ssl_ca_cert"`
	POPRegion              string                    `json:"popRegion"`
	ModifiedAt             string                    `json:"modified_at"`
	Name                   string                    `json:"name"`
	POPName                string                    `json:"popName"`
	OrigTLS                string                    `json:"orig_tls"`
	AppBundle              string                    `json:"app_bundle,omitempty"`
	WSFEDSettings          []WSFEDConfig             `json:"wsfed_settings,omitempty"`
	SAMLSettings           []SAMLConfig              `json:"saml_settings,omitempty"`
	Servers                []Server                  `json:"servers"`
	OIDCClients            []OIDCClient              `json:"oidcclients,omitempty"`
	TunnelInternalHosts    []TunnelInternalHost      `json:"tunnel_internal_hosts"`
	AuthType               int                       `json:"auth_type"`
	AppStatus              int                       `json:"app_status"`
	OriginPort             int                       `json:"origin_port"`
	AppOperational         int                       `json:"app_operational"`
	AppProfile             int                       `json:"app_profile"`
	Status                 int                       `json:"status"`
	SupportedClientVersion int                       `json:"supported_client_version"`
	ClientAppMode          int                       `json:"client_app_mode"`
	AppType                int                       `json:"app_type"`
	FQDNBridgeEnabled      bool                      `json:"fqdn_bridge_enabled"`
	WSFED                  bool                      `json:"wsfed"`
	SAML                   bool                      `json:"saml"`
	Oidc                   bool                      `json:"oidc"`
	AppDeployed            bool                      `json:"app_deployed"`
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
	Attribute     string `json:"attribute"`
}

type RemoteApp struct {
	RemoteApp     string `json:"remote_app"`
	RemoteAppArgs string `json:"remote_app_args"`
	RemoteAppDir  string `json:"remote_app_dir"`
}

type AdvancedSettings struct {
	AppAuthDomain                *string                `json:"app_auth_domain,omitempty"`
	G2OKey                       *string                `json:"g2o_key,omitempty"`
	InternalHostname             *string                `json:"internal_hostname,omitempty"`
	EdgeCookieKey                *string                `json:"edge_cookie_key,omitempty"`
	SlaObjectUrl                 *string                `json:"sla_object_url,omitempty"`
	UserName                     *string                `json:"user_name"`
	SessionStickyServerCookie    *string                `json:"session_sticky_server_cookie"`
	RequestParameters            map[string]interface{} `json:"request_parameters"`
	PrivateKey                   *string                `json:"private_key"`
	PassPhrase                   *string                `json:"pass_phrase"`
	LoginURL                     *string                `json:"login_url"`
	IDPMaxExpiry                 *string                `json:"idp_max_expiry"`
	IDPIdleExpiry                *string                `json:"idp_idle_expiry"`
	G2ONonce                     *string                `json:"g2o_nonce,omitempty"`
	HostKey                      *string                `json:"host_key"`
	HealthCheckHTTPHostHeader    *string                `json:"health_check_http_host_header"`
	ExternalCookieDomain         *string                `json:"external_cookie_domain"`
	EdgeTransportPropertyID      *string                `json:"edge_transport_property_id"`
	CookieDomain                 *string                `json:"cookie_domain"`
	AppLocation                  *string                `json:"app_location"`
	ServicePrincipalName         *string                `json:"service_principle_name,omitempty"`
	AppCookieDomain              *string                `json:"app_cookie_domain,omitempty"`
	LogoutURL                    *string                `json:"logout_url,omitempty"`
	HSTSage                      string                 `json:"hsts_age,omitempty"`
	IsBrotliEnabled              string                 `json:"is_brotli_enabled,omitempty"`
	WappAuth                     string                 `json:"wapp_auth,omitempty"`
	JWTIssuers                   string                 `json:"jwt_issuers,omitempty"`
	JWTAudience                  string                 `json:"jwt_audience,omitempty"`
	JWTGracePeriod               string                 `json:"jwt_grace_period,omitempty"`
	JWTReturnOption              string                 `json:"jwt_return_option,omitempty"`
	JWTUsername                  string                 `json:"jwt_username,omitempty"`
	JWTReturnURL                 string                 `json:"jwt_return_url,omitempty"`
	SentryRedirect401            string                 `json:"sentry_redirect_401,omitempty"`
	AppClientCertAuth            string                 `json:"app_client_cert_auth,omitempty"`
	ForwardTicketGrantingTicket  string                 `json:"forward_ticket_granting_ticket,omitempty"`
	Keytab                       string                 `json:"keytab,omitempty"`
	StickyAgent                  string                 `json:"sticky_agent,omitempty"`
	RDPTLS1                      string                 `json:"rdp_tls1,omitempty"`
	Acceleration                 string                 `json:"acceleration,omitempty"`
	AnonymousServerConnLimit     string                 `json:"anonymous_server_conn_limit,omitempty"`
	AnonymousServerReqLimit      string                 `json:"anonymous_server_request_limit,omitempty"`
	WebSocketEnabled             string                 `json:"websocket_enabled,omitempty"`
	AppServerReadTimeout         string                 `json:"app_server_read_timeout,omitempty"`
	AuthenticatedServerConnLimit string                 `json:"authenticated_server_conn_limit,omitempty"`
	AuthenticatedServerReqLimit  string                 `json:"authenticated_server_request_limit,omitempty"`
	ClientCertAuth               string                 `json:"client_cert_auth,omitempty"`
	ClientCertUserParam          string                 `json:"client_cert_user_param,omitempty"`
	CORSMaxAge                   string                 `json:"cors_max_age,omitempty"`
	DisableUserAgentCheck        string                 `json:"disable_user_agent_check,omitempty"`
	DomainExceptionList          string                 `json:"domain_exception_list,omitempty"`
	EdgeTransportManualMode      string                 `json:"edge_transport_manual_mode,omitempty"`
	CORSSupportCredential        string                 `json:"cors_support_credential,omitempty"`
	EnableClientSideXHRRewrite   string                 `json:"enable_client_side_xhr_rewrite,omitempty"`
	CORSHeaderList               string                 `json:"cors_header_list,omitempty"`
	ForceIPRoute                 string                 `json:"force_ip_route,omitempty"`
	ForceMFA                     string                 `json:"force_mfa,omitempty"`
	RDPLegacyMode                string                 `json:"rdp_legacy_mode,omitempty"`
	FormPostURL                  string                 `json:"form_post_url,omitempty"`
	HealthCheckFall              string                 `json:"health_check_fall,omitempty"`
	CORSMethodList               string                 `json:"cors_method_list,omitempty"`
	HealthCheckHTTPURL           string                 `json:"health_check_http_url,omitempty"`
	HealthCheckHTTPVersion       string                 `json:"health_check_http_version,omitempty"`
	HealthCheckInterval          string                 `json:"health_check_interval,omitempty"`
	HealthCheckRise              string                 `json:"health_check_rise,omitempty"`
	HealthCheckTimeout           string                 `json:"health_check_timeout,omitempty"`
	HealthCheckType              string                 `json:"health_check_type,omitempty"`
	HiddenApp                    string                 `json:"hidden_app,omitempty"`
	CORSOriginList               string                 `json:"cors_origin_list,omitempty"`
	AllowCORS                    string                 `json:"allow_cors,omitempty"`
	HTTPOnlyCookie               string                 `json:"http_only_cookie,omitempty"`
	HTTPSSSLV3                   string                 `json:"https_sslv3,omitempty"`
	IdleCloseTimeSeconds         string                 `json:"idle_close_time_seconds,omitempty"`
	IdleConnCeil                 string                 `json:"idle_conn_ceil,omitempty"`
	IdleConnFloor                string                 `json:"idle_conn_floor,omitempty"`
	IdleConnStep                 string                 `json:"idle_conn_step,omitempty"`
	IPAccessAllow                string                 `json:"ip_access_allow,omitempty"`
	WildcardInternalHostname     string                 `json:"wildcard_internal_hostname,omitempty"`
	IgnoreBypassMFA              string                 `json:"ignore_bypass_mfa,omitempty"`
	InjectAjaxJavascript         string                 `json:"inject_ajax_javascript,omitempty"`
	InterceptURL                 string                 `json:"intercept_url,omitempty"`
	AppAuth                      string                 `json:"app_auth"`
	KeepaliveConnectionPool      string                 `json:"keepalive_connection_pool,omitempty"`
	KeepaliveEnable              string                 `json:"keepalive_enable,omitempty"`
	KeepaliveTimeout             string                 `json:"keepalive_timeout,omitempty"`
	LoadBalancingMetric          string                 `json:"load_balancing_metric,omitempty"`
	LoggingEnabled               string                 `json:"logging_enabled,omitempty"`
	LoginTimeout                 string                 `json:"login_timeout,omitempty"`
	InternalHostPort             string                 `json:"internal_host_port,omitempty"`
	MDCEnable                    string                 `json:"mdc_enable,omitempty"`
	MFA                          string                 `json:"mfa,omitempty"`
	OffloadOnpremiseTraffic      string                 `json:"offload_onpremise_traffic,omitempty"`
	Onramp                       string                 `json:"onramp,omitempty"`
	XWappReadTimeout             string                 `json:"x_wapp_read_timeout,omitempty"`
	PreauthConsent               string                 `json:"preauth_consent,omitempty"`
	PreauthEnforceURL            string                 `json:"preauth_enforce_url,omitempty"`
	G2OEnabled                   string                 `json:"g2o_enabled,omitempty"`
	RemoteSparkAudio             string                 `json:"remote_spark_audio,omitempty"`
	RemoteSparkDisk              string                 `json:"remote_spark_disk,omitempty"`
	RemoteSparkMapClipboard      string                 `json:"remote_spark_mapClipboard,omitempty"`
	RemoteSparkMapDisk           string                 `json:"remote_spark_mapDisk,omitempty"`
	RemoteSparkMapPrinter        string                 `json:"remote_spark_mapPrinter,omitempty"`
	RemoteSparkPrinter           string                 `json:"remote_spark_printer,omitempty"`
	RemoteSparkRecording         string                 `json:"remote_spark_recording,omitempty"`
	RequestBodyRewrite           string                 `json:"request_body_rewrite,omitempty"`
	EdgeAuthenticationEnabled    string                 `json:"edge_authentication_enabled,omitempty"`
	SaaSEnabled                  string                 `json:"saas_enabled,omitempty"`
	SegmentationPolicyEnable     string                 `json:"segmentation_policy_enable,omitempty"`
	SentryRestoreFormPost        string                 `json:"sentry_restore_form_post,omitempty"`
	ServerCertValidate           string                 `json:"server_cert_validate,omitempty"`
	ServerRequestBurst           string                 `json:"server_request_burst,omitempty"`
	SessionSticky                string                 `json:"session_sticky,omitempty"`
	SessionStickyCookieMaxAge    string                 `json:"session_sticky_cookie_maxage,omitempty"`
	IgnoreCnameResolution        string                 `json:"ignore_cname_resolution,omitempty"`
	SingleHostContentRW          string                 `json:"single_host_content_rw,omitempty"`
	SingleHostCookieDomain       string                 `json:"single_host_cookie_domain,omitempty"`
	SingleHostEnable             string                 `json:"single_host_enable,omitempty"`
	SingleHostFQDN               string                 `json:"single_host_fqdn,omitempty"`
	SingleHostPath               string                 `json:"single_host_path,omitempty"`
	SPDYEnabled                  string                 `json:"spdy_enabled,omitempty"`
	SSHAuditEnabled              string                 `json:"ssh_audit_enabled,omitempty"`
	SSO                          string                 `json:"sso,omitempty"`
	IsSSLVerificationEnabled     string                 `json:"is_ssl_verification_enabled,omitempty"`
	XWappPoolEnabled             string                 `json:"x_wapp_pool_enabled,omitempty"`
	XWappPoolSize                string                 `json:"x_wapp_pool_size,omitempty"`
	XWappPoolTimeout             string                 `json:"x_wapp_pool_timeout,omitempty"`
	RDPKeyboardLang              string                 `json:"rdp_keyboard_lang,omitempty"`
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`
	RefreshStickyCookie          string                 `json:"refresh_sticky_cookie,omitempty"`
	DynamicIP                    string                 `json:"dynamic_ip,omitempty"`
	StickyCookies                string                 `json:"sticky_cookies,omitempty"`
	RDPInitialProgram            string                 `json:"rdp_initial_program,omitempty"`
	RDPRemoteApps                []RemoteApp            `json:"rdp_remote_apps,omitempty"`
	FormPostAttributes           []string               `json:"form_post_attributes,omitempty"`
	CustomHeaders                []CustomHeader         `json:"custom_headers,omitempty"`
}

type AdvancedSettings_Complete struct {
	AppCookieDomain              *string                `json:"app_cookie_domain,omitempty"`
	LogoutURL                    *string                `json:"logout_url,omitempty"`
	InternalHostname             *string                `json:"internal_hostname,omitempty"`
	CookieDomain                 *string                `json:"cookie_domain"`
	RequestParameters            map[string]interface{} `json:"request_parameters"`
	IDPIdleExpiry                *string                `json:"idp_idle_expiry,omitempty"`
	IDPMaxExpiry                 *string                `json:"idp_max_expiry,omitempty"`
	AppLocation                  *string                `json:"app_location"`
	TLSSuiteName                 *string                `json:"tls_suite_name,omitempty"`
	TLSSuiteType                 *int                   `json:"tlsSuiteType,omitempty"`
	EdgeTransportPropertyID      *string                `json:"edge_transport_property_id,omitempty"`
	G2OKey                       *string                `json:"g2o_key,omitempty"`
	G2ONonce                     *string                `json:"g2o_nonce,omitempty"`
	RDPInitialProgram            *string                `json:"rdp_initial_program,omitempty"`
	LoginURL                     *string                `json:"login_url,omitempty"`
	ServicePrincipalName         *string                `json:"service_principle_name,omitempty"`
	ExternalCookieDomain         *string                `json:"external_cookie_domain,omitempty"`
	UserName                     *string                `json:"user_name,omitempty"`
	HostKey                      *string                `json:"host_key,omitempty"`
	PrivateKey                   *string                `json:"private_key,omitempty"`
	PassPhrase                   *string                `json:"pass_phrase,omitempty"`
	SessionStickyServerCookie    *string                `json:"session_sticky_server_cookie,omitempty"`
	HealthCheckHTTPHostHeader    *string                `json:"health_check_http_host_header,omitempty"`
	ForceMFA                     string                 `json:"force_mfa,omitempty"`
	KeepaliveTimeout             string                 `json:"keepalive_timeout,omitempty"`
	SPDYEnabled                  string                 `json:"spdy_enabled,omitempty"`
	WebSocketEnabled             string                 `json:"websocket_enabled,omitempty"`
	RequestBodyRewrite           string                 `json:"request_body_rewrite,omitempty"`
	HiddenApp                    string                 `json:"hidden_app,omitempty"`
	AppAuthDomain                string                 `json:"app_auth_domain,omitempty"`
	LoadBalancingMetric          string                 `json:"load_balancing_metric,omitempty"`
	HealthCheckType              string                 `json:"health_check_type,omitempty"`
	HealthCheckHTTPURL           string                 `json:"health_check_http_url,omitempty"`
	HealthCheckHTTPVersion       string                 `json:"health_check_http_version,omitempty"`
	HTTPOnlyCookie               string                 `json:"http_only_cookie,omitempty"`
	ProxyBufferSizeKB            string                 `json:"proxy_buffer_size_kb,omitempty"`
	SessionSticky                string                 `json:"session_sticky,omitempty"`
	SessionStickyCookieMaxAge    string                 `json:"session_sticky_cookie_maxage,omitempty"`
	SSO                          string                 `json:"sso,omitempty"`
	JWTReturnURL                 string                 `json:"jwt_return_url,omitempty"`
	JWTUsername                  string                 `json:"jwt_username,omitempty"`
	JWTReturnOption              string                 `json:"jwt_return_option,omitempty"`
	JWTGracePeriod               string                 `json:"jwt_grace_period,omitempty"`
	JWTAudience                  string                 `json:"jwt_audience,omitempty"`
	JWTIssuers                   string                 `json:"jwt_issuers,omitempty"`
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
	WappAuth                     string                 `json:"wapp_auth,omitempty"`
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
	HTTPSSSLV3                   string                 `json:"https_sslv3,omitempty"`
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
	InternalHostPort             string                 `json:"internal_host_port,omitempty"`
	FormPostURL                  string                 `json:"form_post_url,omitempty"`
	EdgeAuthenticationEnabled    string                 `json:"edge_authentication_enabled,omitempty"`
	HSTSage                      string                 `json:"hsts_age,omitempty"`
	AppAuth                      string                 `json:"app_auth"`
	WildcardInternalHostname     string                 `json:"wildcard_internal_hostname,omitempty"`
	RemoteSparkMapClipboard      string                 `json:"remote_spark_mapClipboard,omitempty"`
	RDPLegacyMode                string                 `json:"rdp_legacy_mode,omitempty"`
	RDPTLS1                      string                 `json:"rdp_tls1,omitempty"`
	RemoteSparkAudio             string                 `json:"remote_spark_audio,omitempty"`
	RemoteSparkMapPrinter        string                 `json:"remote_spark_mapPrinter,omitempty"`
	RemoteSparkPrinter           string                 `json:"remote_spark_printer,omitempty"`
	RemoteSparkMapDisk           string                 `json:"remote_spark_mapDisk,omitempty"`
	RemoteSparkDisk              string                 `json:"remote_spark_disk,omitempty"`
	RemoteSparkRecording         string                 `json:"remote_spark_recording,omitempty"`
	ClientCertAuth               string                 `json:"client_cert_auth,omitempty"`
	ClientCertUserParam          string                 `json:"client_cert_user_param,omitempty"`
	G2OEnabled                   string                 `json:"g2o_enabled,omitempty"`
	LoginTimeout                 string                 `json:"login_timeout,omitempty"`
	LoggingEnabled               string                 `json:"logging_enabled,omitempty"`
	DomainExceptionList          string                 `json:"domain_exception_list,omitempty"`
	DisableUserAgentCheck        string                 `json:"disable_user_agent_check,omitempty"`
	EdgeTransportManualMode      string                 `json:"edge_transport_manual_mode,omitempty"`
	IPAccessAllow                string                 `json:"ip_access_allow,omitempty"`
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
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`
	ForceIPRoute                 string                 `json:"force_ip_route,omitempty"`
	CustomHeaders                []CustomHeader         `json:"custom_headers,omitempty"`
	RDPRemoteApps                []RemoteApp            `json:"rdp_remote_apps,omitempty"`
	FormPostAttributes           []string               `json:"form_post_attributes,omitempty"`
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
	DefaultRelayState *string `json:"default_relay_state,omitempty"`
	EncrAlgo          string  `json:"encr_algo"`
	ACSURL            string  `json:"acs_url"`
	SLOURL            string  `json:"slo_url"`
	ReqBind           string  `json:"req_bind"`
	Metadata          string  `json:"metadata"`
	EntityID          string  `json:"entity_id"`
	SLOBind           string  `json:"slo_bind"`
	SignCert          string  `json:"sign_cert"`
	DSTURL            string  `json:"dst_url"`
	EncrCert          string  `json:"encr_cert"`
	ForceAuth         bool    `json:"force_auth"`
	SLOReqVerify      bool    `json:"slo_req_verify"`
	RespEncr          bool    `json:"resp_encr"`
	ReqVerify         bool    `json:"req_verify"`
}

type IDPConfig struct {
	SignCert         *string `json:"sign_cert,omitempty"`
	EntityID         string  `json:"entity_id"`
	Metadata         string  `json:"metadata"`
	SignKey          string  `json:"sign_key"`
	SignAlgo         string  `json:"sign_algo"`
	RespBind         string  `json:"resp_bind"`
	SLOURL           string  `json:"slo_url"`
	SelfSigned       bool    `json:"self_signed"`
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
	EncrAlgo  string `json:"encr_algo"`
	TokenLife int    `json:"token_life"`
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
	Type                  string             `json:"type"`
	ClientID              string             `json:"client_id"`
	Metadata              string             `json:"metadata"`
	LogoutURL             string             `json:"logout_url"`
	ClientName            string             `json:"client_name"`
	RedirectURIs          []string           `json:"redirect_uris"`
	JavaScriptOrigins     []string           `json:"javascript_origins"`
	ResponseType          []string           `json:"response_type"`
	PostLogoutRedirectURI []string           `json:"post_logout_redirect_uri"`
	ClientSecret          []OIDCClientSecret `json:"client_secret"`
	Claims                []OIDCClaim        `json:"claims"`
	ImplicitGrant         bool               `json:"implicit_grant"`
	LogoutSessionRequired bool               `json:"logout_session_required"`
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
	SLOReqVerify      *bool   `json:"slo_req_verify,omitempty"`
	ACSURL            *string `json:"acs_url,omitempty"`
	SLOURL            *string `json:"slo_url,omitempty"`
	Metadata          *string `json:"metadata,omitempty"`
	DefaultRelayState *string `json:"default_relay_state,omitempty"`
	EntityID          *string `json:"entity_id,omitempty"`
	SLOBind           *string `json:"slo_bind,omitempty"`
	SignCert          *string `json:"sign_cert,omitempty"`
	DSTURL            *string `json:"dst_url,omitempty"`
	EncrCert          *string `json:"encr_cert,omitempty"`
	ReqBind           string  `json:"req_bind"`
	EncrAlgo          string  `json:"encr_algo"`
	ForceAuth         bool    `json:"force_auth"`
	RespEncr          bool    `json:"resp_encr"`
	ReqVerify         bool    `json:"req_verify"`
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
	SignAlgo         string `json:"sign_algo"`
	RespBind         string `json:"resp_bind"`
	SLOURL           string `json:"slo_url,omitempty"`
	SelfSigned       bool   `json:"self_signed"`
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
	AttributeMap map[string]string `json:"attribute_map"`
	Type         string            `json:"type"`
	Items        AttrMapItem       `json:"items"`
	UniqueItems  bool              `json:"uniqueItems"`
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
	SSLCipher    string `json:"ssl_cipher"`
	SSLProtocols string `json:"ssl_protocols"`
	Default      bool   `json:"default"`
	Selected     bool   `json:"selected"`
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
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
	DPAcl   bool   `json:"dp_acl"`
}

type AppDetail struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

type Directory struct {
	Name      string `json:"name"`
	UUIDURL   string `json:"uuid_url"`
	UserCount int    `json:"user_count"`
	Type      int    `json:"type"`
}

type IDP struct {
	IDPId               string `json:"idp_id"`
	ClientCertAuth      string `json:"client_cert_auth"`
	ClientCertUserParam string `json:"client_cert_user_param"`
	Name                string `json:"name"`
	Type                int    `json:"type"`
}

// convertNestedBlocksToSAMLConfig converts Terraform nested blocks to SAMLConfig
func convertNestedBlocksToSAMLConfig(nestedData map[string]interface{}) (SAMLConfig, error) {
	config := DefaultSAMLConfig

	// Convert SP block
	if spBlocks, ok := nestedData["sp"].([]interface{}); ok && len(spBlocks) > 0 {
		spData := spBlocks[0].(map[string]interface{})

		if entityID, ok := spData["entity_id"].(string); ok {
			config.SP.EntityID = entityID
		}
		if acsURL, ok := spData["acs_url"].(string); ok {
			config.SP.ACSURL = acsURL
		}
		if sloURL, ok := spData["slo_url"].(string); ok {
			config.SP.SLOURL = sloURL
		}
		if dstURL, ok := spData["dst_url"].(string); ok {
			config.SP.DSTURL = dstURL
		}
		if respBind, ok := spData["resp_bind"].(string); ok {
			config.SP.ReqBind = respBind
		}
		// Note: SPConfig doesn't have TokenLife field
		if encrAlgo, ok := spData["encr_algo"].(string); ok {
			config.SP.EncrAlgo = encrAlgo
		}
	}

	// Convert IDP block
	if idpBlocks, ok := nestedData["idp"].([]interface{}); ok && len(idpBlocks) > 0 {
		idpData := idpBlocks[0].(map[string]interface{})

		if entityID, ok := idpData["entity_id"].(string); ok {
			config.IDP.EntityID = entityID
		}
		if signAlgo, ok := idpData["sign_algo"].(string); ok {
			config.IDP.SignAlgo = signAlgo
		}
		if signCert, ok := idpData["sign_cert"].(string); ok {
			config.IDP.SignCert = &signCert
		}
		if signKey, ok := idpData["sign_key"].(string); ok {
			config.IDP.SignKey = signKey
		}
		if selfSigned, ok := idpData["self_signed"].(bool); ok {
			config.IDP.SelfSigned = selfSigned
		}
	}

	// Convert Subject block
	if subjectBlocks, ok := nestedData["subject"].([]interface{}); ok && len(subjectBlocks) > 0 {
		subjectData := subjectBlocks[0].(map[string]interface{})

		if fmt, ok := subjectData["fmt"].(string); ok {
			config.Subject.Fmt = fmt
		}
		if src, ok := subjectData["src"].(string); ok {
			config.Subject.Src = src
		}
		if val, ok := subjectData["val"].(string); ok {
			config.Subject.Val = val
		}
		if rule, ok := subjectData["rule"].(string); ok {
			config.Subject.Rule = rule
		}
	}

	// Convert Attrmap block
	if attrmapBlocks, ok := nestedData["attrmap"].([]interface{}); ok {
		config.Attrmap = make([]AttrMapping, 0, len(attrmapBlocks))
		for _, attrmapData := range attrmapBlocks {
			if attrmapMap, ok := attrmapData.(map[string]interface{}); ok {
				attrMapping := AttrMapping{}
				if name, ok := attrmapMap["name"].(string); ok {
					attrMapping.Name = name
				}
				if fname, ok := attrmapMap["fname"].(string); ok {
					attrMapping.Fname = fname
				}
				if fmt, ok := attrmapMap["fmt"].(string); ok {
					attrMapping.Fmt = fmt
				}
				if val, ok := attrmapMap["val"].(string); ok {
					attrMapping.Val = val
				}
				if src, ok := attrmapMap["src"].(string); ok {
					attrMapping.Src = src
				}
				if rule, ok := attrmapMap["rule"].(string); ok {
					attrMapping.Rule = rule
				}
				config.Attrmap = append(config.Attrmap, attrMapping)
			}
		}
	}

	return config, nil
}

// convertNestedBlocksToOIDCConfig converts Terraform nested blocks to OIDCConfig
func convertNestedBlocksToOIDCConfig(nestedData map[string]interface{}) (*OIDCConfig, error) {
	config := &OIDCConfig{}

	// Note: OIDC endpoints are handled elsewhere (probably in advanced_settings)
	// This function only handles OIDC clients

	// Convert OIDC clients
	if oidcClients, ok := nestedData["oidc_clients"].([]interface{}); ok {
		config.OIDCClients = make([]OIDCClient, 0, len(oidcClients))
		for _, clientData := range oidcClients {
			if clientMap, ok := clientData.(map[string]interface{}); ok {
				client := OIDCClient{}
				if clientName, ok := clientMap["client_name"].(string); ok {
					client.ClientName = clientName
				}
				if clientID, ok := clientMap["client_id"].(string); ok {
					client.ClientID = clientID
				}
				if responseType, ok := clientMap["response_type"].([]interface{}); ok {
					client.ResponseType = make([]string, 0, len(responseType))
					for _, rt := range responseType {
						if rtStr, ok := rt.(string); ok {
							client.ResponseType = append(client.ResponseType, rtStr)
						}
					}
				}
				if implicitGrant, ok := clientMap["implicit_grant"].(bool); ok {
					client.ImplicitGrant = implicitGrant
				}
				if clientType, ok := clientMap["type"].(string); ok {
					client.Type = clientType
				}
				if redirectURIs, ok := clientMap["redirect_uris"].([]interface{}); ok {
					client.RedirectURIs = make([]string, 0, len(redirectURIs))
					for _, uri := range redirectURIs {
						if uriStr, ok := uri.(string); ok {
							client.RedirectURIs = append(client.RedirectURIs, uriStr)
						}
					}
				}
				if jsOrigins, ok := clientMap["javascript_origins"].([]interface{}); ok {
					client.JavaScriptOrigins = make([]string, 0, len(jsOrigins))
					for _, origin := range jsOrigins {
						if originStr, ok := origin.(string); ok {
							client.JavaScriptOrigins = append(client.JavaScriptOrigins, originStr)
						}
					}
				}
				if claims, ok := clientMap["claims"].([]interface{}); ok {
					client.Claims = make([]OIDCClaim, 0, len(claims))
					for _, claimData := range claims {
						if claimMap, ok := claimData.(map[string]interface{}); ok {
							claim := OIDCClaim{}
							if name, ok := claimMap["name"].(string); ok {
								claim.Name = name
							}
							if scope, ok := claimMap["scope"].(string); ok {
								claim.Scope = scope
							}
							if val, ok := claimMap["val"].(string); ok {
								claim.Val = val
							}
							if src, ok := claimMap["src"].(string); ok {
								claim.Src = src
							}
							if rule, ok := claimMap["rule"].(string); ok {
								claim.Rule = rule
							}
							client.Claims = append(client.Claims, claim)
						}
					}
				}
				config.OIDCClients = append(config.OIDCClients, client)
			}
		}
	}

	return config, nil
}

type AppsResponse struct {
	Applications []ApplicationDataModel `json:"objects"`
	Meta         struct {
		TotalCount int `json:"total_count"`
	} `json:"meta"`
}

// ParseAdvancedSettingsWithDefaults parses JSON advanced settings and applies sensible defaults
// Moved to app_advanced_settings.go for better maintainability

// DefaultSAMLConfig provides a default SAML configuration with sensible defaults
var DefaultSAMLConfig = SAMLConfig{
	SP: SPConfig{
		EntityID:     "",
		ACSURL:       "",
		SLOURL:       "",
		ReqBind:      string(SAMLResponseBindingRedirect),
		ForceAuth:    false,
		ReqVerify:    false,
		SignCert:     "",
		RespEncr:     false,
		EncrCert:     "",
		EncrAlgo:     string(DefaultSAMLEncryptionAlgorithm),
		SLOReqVerify: true,
		DSTURL:       "",
		SLOBind:      string(DefaultSAMLResponseBinding),
	},
	IDP: IDPConfig{
		EntityID:         "",
		Metadata:         "",
		SignCert:         nil,
		SignKey:          "",
		SelfSigned:       true,
		SignAlgo:         string(DefaultSAMLSigningAlgorithm),
		RespBind:         string(DefaultSAMLResponseBinding),
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

// DefaultWSFEDConfig provides a default WS-Federation configuration with sensible defaults
var DefaultWSFEDConfig = WSFEDConfig{
	SP: WSFEDSPConfig{
		EntityID:  "",
		SLOURL:    "",
		DSTURL:    "",
		RespBind:  string(DefaultSAMLResponseBinding),
		TokenLife: DefaultSAMLTokenLife,
		EncrAlgo:  string(DefaultSAMLEncryptionAlgorithm),
	},
	IDP: WSFEDIDPConfig{
		EntityID:   "",
		SignAlgo:   string(DefaultSAMLSigningAlgorithm),
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

// DefaultOIDCConfig provides a default OIDC configuration with sensible defaults
var DefaultOIDCConfig = OIDCConfig{
	OIDCClients: []OIDCClient{
		{
			ClientName:   "",
			ClientID:     "",
			ResponseType: []string{"code"},
		},
	},
}

// shouldEnableAuthForCreate is used to determine if SAML should be automatically enabled during creation
// (moved helpers to app_facing_auth.go)
