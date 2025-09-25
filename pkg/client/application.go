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
	Name             string           `json:"name"`
	Description      *string          `json:"description"`
	AppProfile       int              `json:"app_profile"`
	AppType          int              `json:"app_type"`
	ClientAppMode    int              `json:"client_app_mode"`
	AppBundle        string           `json:"app_bundle,omitempty"`
	AdvancedSettings AdvancedSettings `json:"advanced_settings,omitempty"`
	SAML             bool             `json:"saml"`
	Oidc             bool             `json:"oidc"`
	WSFED            bool             `json:"wsfed"`
	SAMLSettings     []SAMLConfig     `json:"saml_settings"`
	OIDCSettings     *OIDCConfig      `json:"oidc_settings"`
	WSFEDSettings    []WSFEDConfig    `json:"wsfed_settings"`
	TLSSuiteType     *int             `json:"tlsSuiteType,omitempty"`
	TLSSuiteName     *string          `json:"tls_suite_name,omitempty"`
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
		logger.Info("appType", appType)
		logger.Info("mcar.AppType", mcar.AppType)
	} else {
		logger.Info("appType is not present, defaulting to enterprise")
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
		logger.Info("appProfile", appProfile)
		logger.Info("mcar.AppProfile", mcar.AppProfile)
	} else {
		logger.Info("appProfile is not present, defaulting to http")
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
		logger.Info("appMode", clientAppMode)
		logger.Info("mcar.ClientAppMode", mcar.ClientAppMode)
	} else {
		logger.Info("appMode is not present, defaulting to tcp")
		mcar.ClientAppMode = int(CLIENT_APP_MODE_TCP)
	}

	logger.Info("Minimal app creation request prepared successfully")
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

	// Handle app_bundle field - validate name and get UUID
	var validatedAppBundleUUID string
	if appBundle, ok := d.GetOk("app_bundle"); ok {
		if appBundleStr, ok := appBundle.(string); ok && appBundleStr != "" {
			logger.Info("CREATE FLOW: Found app_bundle:", appBundleStr)
			
			// Validate app bundle name and get UUID
			appBundleUUID, err := ec.GetAppBundleByName(appBundleStr)
			if err != nil {
				logger.Error("CREATE FLOW: Failed to validate app_bundle name '%s': %v", appBundleStr, err)
				return fmt.Errorf("invalid app_bundle name '%s': %w", appBundleStr, err)
			}
			
			validatedAppBundleUUID = appBundleUUID
			logger.Info("CREATE FLOW: App bundle '%s' validated, UUID: %s", appBundleStr, appBundleUUID)
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

	logger.Info("CREATE FLOW: Using JSON:", advSettingsJSON)

	// ALWAYS parse and apply malformed defaults
	advSettings, err := ParseAdvancedSettingsWithDefaults(advSettingsJSON)
	if err != nil {
		return fmt.Errorf("failed to parse advanced settings JSON: %w", err)
	}

	// Extract TLS Suite fields from advanced_settings and set them at the top level
	// Parse the advanced_settings JSON to extract TLS Suite fields
	logger.Info("CREATE FLOW: TLS Suite extraction - advSettingsJSON:", advSettingsJSON)
	var userSettings map[string]interface{}
	if err := json.Unmarshal([]byte(advSettingsJSON), &userSettings); err == nil {
		logger.Info("CREATE FLOW: TLS Suite extraction - parsed userSettings:", userSettings)

		// Extract tlsSuiteType
		if tlsSuiteTypeVal, exists := userSettings["tlsSuiteType"]; exists {
			logger.Info("CREATE FLOW: TLS Suite extraction - found tlsSuiteType:", tlsSuiteTypeVal)

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
			logger.Info("CREATE FLOW: Set tlsSuiteType from advanced_settings:", tlsSuiteTypeInt)
		} else {
			logger.Info("CREATE FLOW: TLS Suite extraction - tlsSuiteType not found in userSettings")
		}

		// Extract tls_suite_name
		if tlsSuiteNameVal, exists := userSettings["tls_suite_name"]; exists {
			logger.Info("CREATE FLOW: TLS Suite extraction - found tls_suite_name:", tlsSuiteNameVal)
			if tlsSuiteNameStr, ok := tlsSuiteNameVal.(string); ok {
				car.TLSSuiteName = &tlsSuiteNameStr
				logger.Info("CREATE FLOW: Set tls_suite_name from advanced_settings:", tlsSuiteNameStr)
			}
		} else {
			logger.Info("CREATE FLOW: TLS Suite extraction - tls_suite_name not found in userSettings")
		}
	} else {
		logger.Error("CREATE FLOW: TLS Suite extraction - failed to parse advSettingsJSON:", err)
	}

	// Set authentication flags based on Terraform boolean flags for CREATE flow
	// Preserve user-provided app_auth value from advanced_settings
	logger.Info("CREATE FLOW: Using app_auth from advanced_settings:", advSettings.AppAuth)

	// Set authentication flags based on Terraform boolean flags
	// Reset all auth types to false first
	car.SAML = false
	car.Oidc = false
	car.WSFED = false

	// Then set the specific one based on flags
	if samlFlag, ok := d.GetOk("saml"); ok {
		if samlBool, ok := samlFlag.(bool); ok && samlBool {
			logger.Info("CREATE FLOW: Found saml=true in Terraform config")
			car.SAML = true
		}
	}

	if oidcFlag, ok := d.GetOk("oidc"); ok {
		if oidcBool, ok := oidcFlag.(bool); ok && oidcBool {
			logger.Info("CREATE FLOW: Found oidc=true in Terraform config")
			car.Oidc = true
			// Override app_auth only when oidc=true
		}
	}

	if wsfedFlag, ok := d.GetOk("wsfed"); ok {
		if wsfedBool, ok := wsfedFlag.(bool); ok && wsfedBool {
			logger.Info("CREATE FLOW: Found wsfed=true in Terraform config")
			car.WSFED = true
		}
	}

	logger.Info("CREATE FLOW: Final app_auth value in payload:", advSettings.AppAuth)
	logger.Info("CREATE FLOW: After setting flags - SAML:", car.SAML)
	logger.Info("CREATE FLOW: After setting flags - Oidc:", car.Oidc)
	logger.Info("CREATE FLOW: After setting flags - WSFED:", car.WSFED)

	// Handle SAML settings for CREATE flow
	if car.SAML {
		// Use schema approach (nested blocks)
		if samlSettings, ok := d.GetOk("saml_settings"); ok {
			logger.Info("CREATE FLOW: Found saml_settings blocks")
			if samlSettingsList, ok := samlSettings.([]interface{}); ok && len(samlSettingsList) > 0 {
				// Convert nested blocks to SAMLConfig
				samlConfig, err := convertNestedBlocksToSAMLConfig(samlSettingsList[0].(map[string]interface{}))
				if err != nil {
					logger.Error("CREATE FLOW: Failed to convert nested blocks to SAML config:", err)
					return fmt.Errorf("failed to convert nested blocks to SAML config: %w", err)
				}
				car.SAMLSettings = []SAMLConfig{samlConfig}
				logger.Info("CREATE FLOW: Successfully converted nested blocks to SAML config")
			}
		} else {
			// No saml_settings provided but SAML is enabled - create default structure
			logger.Info("CREATE FLOW: No saml_settings found, creating defaults")
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
			logger.Info("CREATE FLOW: Found oidc_settings blocks")
			if oidcSettingsList, ok := oidcSettings.([]interface{}); ok && len(oidcSettingsList) > 0 {
				// Convert nested blocks to OIDCConfig
				oidcConfig, err := convertNestedBlocksToOIDCConfig(oidcSettingsList[0].(map[string]interface{}))
				if err != nil {
					logger.Error("CREATE FLOW: Failed to convert nested blocks to OIDC config:", err)
					return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
				}
				car.OIDCSettings = oidcConfig
				logger.Info("CREATE FLOW: Successfully converted nested blocks to OIDC config")
			}
		} else {
			logger.Info("CREATE FLOW: No oidc_settings found, creating defaults")
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
			logger.Info("CREATE FLOW: Found wsfed_settings as nested blocks")
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
				logger.Info("CREATE FLOW: Successfully merged WSFED config from nested blocks")
			}
		} else {
			// No wsfed_settings provided but WSFED is enabled - use default structure
			logger.Info("CREATE FLOW: No wsfed_settings found, using DefaultWSFEDConfig")
			car.WSFEDSettings = []WSFEDConfig{DefaultWSFEDConfig}
		}
	} else {
		car.WSFEDSettings = []WSFEDConfig{}
	}

	// Handle app_bundle field from top-level resource - use validated UUID
	if validatedAppBundleUUID != "" {
		car.AppBundle = validatedAppBundleUUID
		logger.Info("CREATE FLOW: Set app_bundle UUID on CreateAppRequest struct:", validatedAppBundleUUID)
	}

	logger.Info("CREATE FLOW: Setting car.AdvancedSettings with malformed defaults")
	logger.Info("CREATE FLOW: advSettings.AppAuth before assignment:", advSettings.AppAuth)
	car.AdvancedSettings = *advSettings
	logger.Info("CREATE FLOW: car.AdvancedSettings.AppAuth after assignment:", car.AdvancedSettings.AppAuth)

	return nil
}

// CreateMinimalApplication creates an application with minimal required fields only
func (mcar *MinimalCreateAppRequest) CreateMinimalApplication(ctx context.Context, ec *EaaClient) (*ApplicationResponse, error) {
	ec.Logger.Info("create minimal application")

	// Log the minimal payload being sent to API
	payloadBytes, _ := json.MarshalIndent(mcar, "", "  ")
	ec.Logger.Info("=== MINIMAL API PAYLOAD BEING SENT ===")
	ec.Logger.Info(string(payloadBytes))
	ec.Logger.Info("=== END MINIMAL API PAYLOAD ===")

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
	ec.Logger.Info("create minimal Application succeeded.", "name", mcar.Name)
	return &appResp, nil
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
	AppBundle   string      `json:"app_bundle,omitempty"`

	UUIDURL string `json:"uuid_url"`

	TLSSuiteType           *int    `json:"tlsSuiteType,omitempty"`
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
			ec.Logger.Info("UPDATE FLOW: App bundle '%s' validated, UUID: %s", appBundleStr, appBundleUUID)
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
			ec.Logger.Info("UPDATE FLOW: Using app_auth from advanced_settings:", advSettings.AppAuth)

			// Extract TLS Suite fields from advanced_settings and set them at the top level
			// Parse the advanced_settings JSON to extract TLS Suite fields
			ec.Logger.Info("UPDATE FLOW: TLS Suite extraction - advSettingsJSON:", advSettingsJSON)
			var userSettings map[string]interface{}
			if err := json.Unmarshal([]byte(advSettingsJSON), &userSettings); err == nil {
				ec.Logger.Info("UPDATE FLOW: TLS Suite extraction - parsed userSettings:", userSettings)

				// Extract tlsSuiteType
				if tlsSuiteTypeVal, exists := userSettings["tlsSuiteType"]; exists {
					ec.Logger.Info("UPDATE FLOW: TLS Suite extraction - found tlsSuiteType:", tlsSuiteTypeVal)

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
					ec.Logger.Info("UPDATE FLOW: Set tlsSuiteType from advanced_settings:", tlsSuiteTypeInt)
				} else {
					ec.Logger.Info("UPDATE FLOW: TLS Suite extraction - tlsSuiteType not found in userSettings")
				}

				// Extract tls_suite_name
				if tlsSuiteNameVal, exists := userSettings["tls_suite_name"]; exists {
					ec.Logger.Info("UPDATE FLOW: TLS Suite extraction - found tls_suite_name:", tlsSuiteNameVal)
					if tlsSuiteNameStr, ok := tlsSuiteNameVal.(string); ok {
						appUpdateReq.TLSSuiteName = &tlsSuiteNameStr
						ec.Logger.Info("UPDATE FLOW: Set tls_suite_name from advanced_settings:", tlsSuiteNameStr)
					}
				} else {
					ec.Logger.Info("UPDATE FLOW: TLS Suite extraction - tls_suite_name not found in userSettings")
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
				ec.Logger.Info("UPDATE FLOW: Set app_bundle UUID on Application struct:", validatedAppBundleUUID)
			}

			// Log the final advanced settings to see what's being sent
			ec.Logger.Info("UPDATE FLOW: Final advanced settings AppAuth:", appUpdateReq.AdvancedSettings.AppAuth)

			// Debug output for RDP fields

		}
	}

	// Set authentication flags based on Terraform boolean flags for UPDATE flow
	// This logic runs regardless of whether advanced_settings is provided

	samlFlag, samlOk := d.GetOk("saml")
	if samlOk {
		if samlBool, ok := samlFlag.(bool); ok && samlBool {
			ec.Logger.Info("UPDATE FLOW: Found saml=true in Terraform config")
			appUpdateReq.SAML = true
			appUpdateReq.Oidc = false
			appUpdateReq.WSFED = false

			// Use schema approach (nested blocks)
			if samlSettings, ok := d.GetOk("saml_settings"); ok {
				ec.Logger.Info("UPDATE FLOW: Found saml_settings blocks")
				if samlSettingsList, ok := samlSettings.([]interface{}); ok && len(samlSettingsList) > 0 {
					// Convert nested blocks to SAMLConfig
					samlConfig, err := convertNestedBlocksToSAMLConfig(samlSettingsList[0].(map[string]interface{}))
					if err != nil {
						ec.Logger.Error("UPDATE FLOW: Failed to convert nested blocks to SAML config:", err)
						return fmt.Errorf("failed to convert nested blocks to SAML config: %w", err)
					}
					appUpdateReq.SAMLSettings = []SAMLConfig{samlConfig}
					ec.Logger.Info("UPDATE FLOW: Successfully converted nested blocks to SAML config")
				}
			} else {
				// No saml_settings provided but SAML is enabled - use DefaultSAMLConfig
				ec.Logger.Info("UPDATE FLOW: No saml_settings found, using DefaultSAMLConfig")
				appUpdateReq.SAMLSettings = []SAMLConfig{DefaultSAMLConfig}
				ec.Logger.Info("UPDATE FLOW: Set SAMLSettings with DefaultSAMLConfig")
			}
		}
	}

	if oidcFlag, ok := d.GetOk("oidc"); ok {
		if oidcBool, ok := oidcFlag.(bool); ok && oidcBool {
			ec.Logger.Info("UPDATE FLOW: Found oidc=true in Terraform config")
			appUpdateReq.SAML = false
			appUpdateReq.Oidc = true
			appUpdateReq.WSFED = false
			// Override app_auth only when oidc=true
			appUpdateReq.AdvancedSettings.AppAuth = "oidc"
			appUpdateReq.SAMLSettings = []SAMLConfig{} // Clear SAML settings when OIDC is enabled

			// Handle OIDC settings for UPDATE flow
			if oidcSettings, ok := d.GetOk("oidc_settings"); ok {
				ec.Logger.Info("UPDATE FLOW: Found oidc_settings blocks")
				if oidcSettingsList, ok := oidcSettings.([]interface{}); ok && len(oidcSettingsList) > 0 {
					// Convert nested blocks to OIDCConfig
					oidcConfig, err := convertNestedBlocksToOIDCConfig(oidcSettingsList[0].(map[string]interface{}))
					if err != nil {
						ec.Logger.Error("UPDATE FLOW: Failed to convert nested blocks to OIDC config:", err)
						return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
					}
					appUpdateReq.OIDCSettings = oidcConfig
					ec.Logger.Info("UPDATE FLOW: Successfully converted nested blocks to OIDC config")
				}
			} else {
				ec.Logger.Info("UPDATE FLOW: No oidc_settings found, creating defaults")
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
		}
	}

	if wsfedFlag, ok := d.GetOk("wsfed"); ok {
		if wsfedBool, ok := wsfedFlag.(bool); ok && wsfedBool {
			ec.Logger.Info("UPDATE FLOW: Found wsfed=true in Terraform config")
			appUpdateReq.SAML = false
			appUpdateReq.Oidc = false
			appUpdateReq.WSFED = true
			appUpdateReq.SAMLSettings = []SAMLConfig{} // Clear SAML settings when WS-FED is enabled
		}
	}

	ec.Logger.Info("UPDATE FLOW: Final SAML flag:", appUpdateReq.SAML)
	ec.Logger.Info("UPDATE FLOW: Final Oidc flag:", appUpdateReq.Oidc)
	ec.Logger.Info("UPDATE FLOW: Final WSFED flag:", appUpdateReq.WSFED)
	ec.Logger.Info("UPDATE FLOW: Final SAMLSettings length:", len(appUpdateReq.SAMLSettings))

	// Handle WS-Federation settings for UPDATE flow
	if appUpdateReq.WSFED {
		if wsfedSettingsData, ok := d.GetOk("wsfed_settings"); ok {
			// User provided wsfed_settings as nested blocks - parse them
			ec.Logger.Info("UPDATE FLOW: Found wsfed_settings as nested blocks")
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
				appUpdateReq.WSFEDSettings = []WSFEDConfig{wsfedConfig}
				ec.Logger.Info("UPDATE FLOW: Successfully merged WSFED config from nested blocks")
			}
		} else {
			// No wsfed_settings provided but WSFED is enabled - use default structure
			ec.Logger.Info("UPDATE FLOW: No wsfed_settings found, using DefaultWSFEDConfig")
			appUpdateReq.WSFEDSettings = []WSFEDConfig{DefaultWSFEDConfig}
		}
	} else {
		appUpdateReq.WSFEDSettings = []WSFEDConfig{}
	}

	// Handle OIDC settings for UPDATE flow
	var oidcConfig *OIDCConfig

	if appUpdateReq.Oidc {
		if oidcSettingsData, ok := d.GetOk("oidc_settings"); ok {
			ec.Logger.Info("UPDATE FLOW: Found oidc_settings blocks")
			if oidcSettingsList, ok := oidcSettingsData.([]interface{}); ok && len(oidcSettingsList) > 0 {
				// Convert nested blocks to OIDCConfig (consistent with CREATE flow)
				convertedConfig, err := convertNestedBlocksToOIDCConfig(oidcSettingsList[0].(map[string]interface{}))
				if err != nil {
					ec.Logger.Error("UPDATE FLOW: Failed to convert nested blocks to OIDC config:", err)
					return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
				}
				oidcConfig = convertedConfig
				ec.Logger.Info("UPDATE FLOW: Successfully converted nested blocks to OIDC config")
			}
		} else {
			ec.Logger.Info("UPDATE FLOW: No oidc_settings found, creating defaults")
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

	// Debug: Log the final app bundle before sending to API
	ec.Logger.Info("FINAL PAYLOAD: AppBundle = '%s'", appUpdateReq.AppBundle)
	
	// Debug: Log the complete request payload
	payloadJSON, _ := json.MarshalIndent(appUpdateReq, "", "  ")
	ec.Logger.Info("COMPLETE REQUEST PAYLOAD:\n%s", string(payloadJSON))

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
	AppBundle        string                    `json:"app_bundle,omitempty"`

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
	Attribute     string `json:"attribute"`
}

type RemoteApp struct {
	RemoteApp     string `json:"remote_app"`
	RemoteAppArgs string `json:"remote_app_args"`
	RemoteAppDir  string `json:"remote_app_dir"`
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
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`
	RefreshStickyCookie          string                 `json:"refresh_sticky_cookie,omitempty"`
	DynamicIP                    string                 `json:"dynamic_ip,omitempty"`
	StickyCookies                string                 `json:"sticky_cookies,omitempty"`
	RDPRemoteApps                []RemoteApp            `json:"rdp_remote_apps,omitempty"`
	RDPInitialProgram            string                 `json:"rdp_initial_program,omitempty"`
	RDPLegacyMode                string                 `json:"rdp_legacy_mode,omitempty"`
	RDPTLS1                      string                 `json:"rdp_tls1,omitempty"`
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
	RDPRemoteApps                []RemoteApp            `json:"rdp_remote_apps,omitempty"`
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
	G2ONonce                     *string                `json:"g2o_nonce,omitempty"`
	G2OKey                       *string                `json:"g2o_key,omitempty"`
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
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`
	ForceIPRoute                 string                 `json:"force_ip_route,omitempty"`
	CustomHeaders                []CustomHeader         `json:"custom_headers,omitempty"`
	TLSSuiteType                 *int                   `json:"tlsSuiteType,omitempty"`
	TLSSuiteName                 *string                `json:"tls_suite_name,omitempty"`
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
				if val, ok := attrmapMap["value"].(string); ok {
					attrMapping.Val = val
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
	Meta struct {
		TotalCount int `json:"total_count"`
	} `json:"meta"`
	Applications []ApplicationDataModel `json:"objects"`
}

// ParseAdvancedSettingsWithDefaults parses JSON advanced settings and applies sensible defaults
// Moved to app_advanced_settings.go for better maintainability

// DefaultSAMLConfig provides a default SAML configuration with sensible defaults
var DefaultSAMLConfig = SAMLConfig{
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

// DefaultWSFEDConfig provides a default WS-Federation configuration with sensible defaults
var DefaultWSFEDConfig = WSFEDConfig{
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
