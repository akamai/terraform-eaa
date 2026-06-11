package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
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

func firstMapBlock(blocks []interface{}, fieldName string) (map[string]interface{}, error) {
	if len(blocks) == 0 {
		return nil, fmt.Errorf("invalid %s format: expected at least one block", fieldName)
	}

	block, ok := blocks[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid %s format: expected map[string]interface{}", fieldName)
	}

	return block, nil
}

// CreateMinimalAppRequestFromSchema creates a minimal app creation request with only essential fields
func (mcar *MinimalCreateAppRequest) CreateMinimalAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}

	// Validate and set the name field (required)
	if name, ok := d.GetOk("name"); ok {
		nameStr, ok := name.(string)
		if ok && nameStr != "" {
			mcar.Name = nameStr
		} else {
			logging.Error(ctx, "create Application failed: name is invalid", tags)
			return ErrInvalidValue
		}
	} else {
		logging.Error(ctx, "create Application failed: name is required", tags)
		return ErrInvalidValue
	}

	// Set app_type with default
	if appType, ok := d.GetOk("app_type"); ok {
		strAppType, ok := appType.(string)
		if !ok {
			logging.Error(ctx, "create Application failed: app_type is invalid", tags)
			return ErrInvalidType
		}
		atype := AppType(strAppType)
		value, err := atype.ToInt()
		if err != nil {
			logging.Error(ctx, "create Application failed: app_type is invalid", tags)
			return ErrInvalidValue
		}
		mcar.AppType = value
		logging.Debug(ctx, "appType", tags, map[string]any{"appType": appType})
		logging.Debug(ctx, "mcar.AppType", tags, map[string]any{"mcar.AppType": mcar.AppType})
	} else {
		logging.Debug(ctx, "appType is not present, defaulting to enterprise", tags)
		mcar.AppType = int(APP_TYPE_ENTERPRISE_HOSTED)
	}

	// Set app_profile with default
	if appProfile, ok := d.GetOk("app_profile"); ok {
		strappProfile, ok := appProfile.(string)
		if !ok {
			logging.Error(ctx, "create Application failed: app_profile is invalid", tags)
			return ErrInvalidType
		}
		aProfile := AppProfile(strappProfile)
		value, err := aProfile.ToInt()
		if err != nil {
			logging.Error(ctx, "create Application failed: app_profile is invalid", tags)
			return ErrInvalidValue
		}
		mcar.AppProfile = value
		logging.Debug(ctx, "appProfile", tags, map[string]any{"appProfile": appProfile})
		logging.Debug(ctx, "mcar.AppProfile", tags, map[string]any{"mcar.AppProfile": mcar.AppProfile})
	} else {
		logging.Debug(ctx, "appProfile is not present, defaulting to http", tags)
		mcar.AppProfile = int(APP_PROFILE_HTTP)
	}

	// Set client_app_mode with default
	if clientAppMode, ok := d.GetOk("client_app_mode"); ok {
		appMode, ok := clientAppMode.(string)
		if !ok {
			logging.Error(ctx, "create Application failed: clientAppMode is invalid", tags)
			return ErrInvalidType
		}
		aMode := AppMode(appMode)
		value, err := aMode.ToInt()
		if err != nil {
			logging.Error(ctx, "create Application failed: clientAppMode is invalid", tags)
			return ErrInvalidValue
		}
		mcar.ClientAppMode = value
		logging.Debug(ctx, "appMode", tags, map[string]any{"appMode": clientAppMode})
		logging.Debug(ctx, "mcar.ClientAppMode", tags, map[string]any{"mcar.ClientAppMode": mcar.ClientAppMode})
	} else {
		logging.Debug(ctx, "appMode is not present, defaulting to tcp", tags)
		mcar.ClientAppMode = int(CLIENT_APP_MODE_TCP)
	}

	logging.Debug(ctx, "minimal app creation request prepared successfully", tags)
	return nil
}

func (car *CreateAppRequest) CreateAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}

	if name, ok := d.GetOk("name"); ok {
		nameStr, ok := name.(string)
		if ok && nameStr != "" {
			car.Name = nameStr
		} else {
			logging.Error(ctx, "create Application failed: name must be a non-empty string", tags)
			return ErrInvalidValue
		}
	} else {
		logging.Error(ctx, "create Application failed: name is invalid", tags)
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
			logging.Error(ctx, "create Application failed: app_type is invalid", tags)
			return ErrInvalidType
		}
		atype := AppType(strAppType)
		value, err := atype.ToInt()
		if err != nil {
			logging.Error(ctx, "create Application failed: app_type is invalid", tags)
			return ErrInvalidValue
		}
		car.AppType = value
		logging.Debug(ctx, "appType", tags, map[string]any{"appType": appType})
		logging.Debug(ctx, "car.AppType", tags, map[string]any{"car.AppType": car.AppType})
	} else {
		logging.Debug(ctx, "appType is not present, defaulting to enterprise", tags)
		car.AppType = int(APP_TYPE_ENTERPRISE_HOSTED)
	}

	if appProfile, ok := d.GetOk("app_profile"); ok {
		strappProfile, ok := appProfile.(string)
		if !ok {
			logging.Error(ctx, "create Application failed: app_profile is invalid", tags)
			return ErrInvalidType
		}
		aProfile := AppProfile(strappProfile)
		value, err := aProfile.ToInt()
		if err != nil {
			logging.Error(ctx, "create Application failed: app_profile is invalid", tags)
			return ErrInvalidValue
		}
		car.AppProfile = value
		logging.Debug(ctx, "appProfile", tags, map[string]any{"appProfile": appProfile})
		logging.Debug(ctx, "car.AppProfile", tags, map[string]any{"car.AppProfile": car.AppProfile})
	} else {
		logging.Debug(ctx, "appProfile is not present, defaulting to http", tags)
		car.AppProfile = int(APP_PROFILE_HTTP)
	}

	if clientAppMode, ok := d.GetOk("client_app_mode"); ok {
		appMode, ok := clientAppMode.(string)
		if !ok {
			logging.Error(ctx, "create Application failed: clientAppMode is invalid", tags)
			return ErrInvalidType
		}
		aMode := AppMode(appMode)
		value, err := aMode.ToInt()
		if err != nil {
			logging.Error(ctx, "create Application failed: clientAppMode is invalid", tags)
			return ErrInvalidValue
		}
		car.ClientAppMode = value
		logging.Debug(ctx, "appMode", tags, map[string]any{"appMode": clientAppMode})
		logging.Debug(ctx, "car.ClientAppMode", tags, map[string]any{"car.ClientAppMode": car.ClientAppMode})
	} else {
		logging.Debug(ctx, "appMode is not present, defaulting to tcp", tags)
		car.ClientAppMode = int(CLIENT_APP_MODE_TCP)
	}

	// Handle app_bundle field - validate name and get UUID
	var validatedAppBundleUUID string
	if appBundle, ok := d.GetOk("app_bundle"); ok {
		if appBundleStr, ok := appBundle.(string); ok && appBundleStr != "" {
			logging.Debug(ctx, "CREATE FLOW: found app_bundle", tags, map[string]any{"app_bundle": appBundleStr})

			// Validate app bundle name and get UUID
			appBundleUUID, err := ec.GetAppBundleByName(ctx, appBundleStr)
			if err != nil {
				logging.Error(ctx, "CREATE FLOW: failed to validate app_bundle name", tags, map[string]any{"app_bundle": appBundleStr, "error": err.Error()})
				return fmt.Errorf("invalid app_bundle name '%s': %w", appBundleStr, err)
			}

			validatedAppBundleUUID = appBundleUUID
			logging.Debug(ctx, "CREATE FLOW: app_bundle validated", tags, map[string]any{"app_bundle": appBundleStr, "uuid": appBundleUUID})
		}
	}

	// Handle advanced settings for CREATE flow - ALWAYS set defaults

	// Build a settings map from the TypeMap block (or empty map if not set)
	var userSettings map[string]interface{}
	if advMap, ok := d.GetOk("advanced_settings"); ok {
		if m, ok := advMap.(map[string]interface{}); ok {
			userSettings = m
		}
	}
	if userSettings == nil {
		userSettings = map[string]interface{}{}
	}

	logging.Debug(ctx, "CREATE FLOW: using advanced_settings block", tags, map[string]any{"key_count": len(userSettings)})

	// ALWAYS parse and apply defaults
	advSettings, err := advancedSettingsFromBlock(userSettings)
	if err != nil {
		return fmt.Errorf("failed to parse advanced settings block: %w", err)
	}

	// tls_suite_name is read from the top-level Terraform schema attribute (not from the advanced_settings map)
	if tlsSuiteName, ok := d.GetOk("tls_suite_name"); ok {
		if tlsSuiteNameStr, ok := tlsSuiteName.(string); ok {
			if tlsSuiteNameStr != "" {
				car.TLSSuiteName = &tlsSuiteNameStr
				logging.Debug(ctx, "CREATE FLOW: tls_suite_name set", tags, map[string]any{"value": tlsSuiteNameStr})
			} else {
				logging.Warn(ctx, "CREATE FLOW: tls_suite_name is set to empty string; ignoring because the API does not support clearing", tags)
			}
		}
	}

	// Set authentication flags based on Terraform boolean flags for CREATE flow
	// Preserve user-provided app_auth value from advanced_settings
	logging.Debug(ctx, "CREATE FLOW: using app_auth from advanced_settings", tags, map[string]any{"app_auth": advSettings.AppAuth})

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
				samlBlock, err := firstMapBlock(samlSettingsList, "saml_settings")
				if err != nil {
					logging.Error(ctx, "failed to read nested SAML block", tags, map[string]any{"error": err.Error()})
					return err
				}
				samlConfig, err := convertNestedBlocksToSAMLConfig(samlBlock)
				if err != nil {
					logging.Error(ctx, "failed to convert nested SAML blocks", tags, map[string]any{"error": err.Error()})
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
			logging.Debug(ctx, "CREATE FLOW: Found oidc_settings blocks", tags)
			if oidcSettingsList, ok := oidcSettings.([]interface{}); ok && len(oidcSettingsList) > 0 {
				// Convert nested blocks to OIDCConfig
				oidcBlock, err := firstMapBlock(oidcSettingsList, "oidc_settings")
				if err != nil {
					logging.Error(ctx, "CREATE FLOW: failed to read nested OIDC block", tags, map[string]any{"error": err.Error()})
					return err
				}
				oidcConfig, err := convertNestedBlocksToOIDCConfig(oidcBlock)
				if err != nil {
					logging.Error(ctx, "CREATE FLOW: failed to convert nested OIDC blocks", tags, map[string]any{"error": err.Error()})
					return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
				}
				car.OIDCSettings = oidcConfig
				logging.Debug(ctx, "CREATE FLOW: Successfully converted nested blocks to OIDC config", tags)
			}
		} else {
			logging.Debug(ctx, "CREATE FLOW: No oidc_settings found, creating defaults", tags)
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
			logging.Debug(ctx, "CREATE FLOW: Found wsfed_settings as nested blocks", tags)
			if wsfedSettingsList, ok := wsfedSettingsData.([]interface{}); ok && len(wsfedSettingsList) > 0 {
				// Get the first (and only) wsfed_settings block
				wsfedBlock, err := firstMapBlock(wsfedSettingsList, "wsfed_settings")
				if err != nil {
					logging.Error(ctx, "CREATE FLOW: failed to read nested WSFED block", tags, map[string]any{"error": err.Error()})
					return err
				}

				// Start with DefaultWSFEDConfig as base
				wsfedConfig := DefaultWSFEDConfig

				// Merge SP settings
				if spBlocks, ok := wsfedBlock["sp"].([]interface{}); ok && len(spBlocks) > 0 {
					spBlock, err := firstMapBlock(spBlocks, "wsfed_settings.sp")
					if err != nil {
						logging.Error(ctx, "CREATE FLOW: failed to read nested WSFED SP block", tags, map[string]any{"error": err.Error()})
						return err
					}

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
					idpBlock, err := firstMapBlock(idpBlocks, "wsfed_settings.idp")
					if err != nil {
						logging.Error(ctx, "CREATE FLOW: failed to read nested WSFED IDP block", tags, map[string]any{"error": err.Error()})
						return err
					}

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
					subjectBlock, err := firstMapBlock(subjectBlocks, "wsfed_settings.subject")
					if err != nil {
						logging.Error(ctx, "CREATE FLOW: failed to read nested WSFED subject block", tags, map[string]any{"error": err.Error()})
						return err
					}

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
						attrMap, ok := attrBlock.(map[string]interface{})
						if !ok {
							logging.Warn(ctx, "skipping malformed WSFED attrmap entry", tags)
							continue
						}
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
					wsfedConfig.Attrmap = attrmap
				}

				// Use the merged configuration
				car.WSFEDSettings = []WSFEDConfig{wsfedConfig}
				logging.Debug(ctx, "CREATE FLOW: Successfully merged WSFED config from nested blocks", tags)
			}
		} else {
			// No wsfed_settings provided but WSFED is enabled - use default structure
			logging.Debug(ctx, "CREATE FLOW: No wsfed_settings found, using DefaultWSFEDConfig", tags)
			car.WSFEDSettings = []WSFEDConfig{DefaultWSFEDConfig}
		}
	} else {
		car.WSFEDSettings = []WSFEDConfig{}
	}

	// Handle app_bundle field from top-level resource - use validated UUID
	if validatedAppBundleUUID != "" {
		car.AppBundle = validatedAppBundleUUID
		logging.Debug(ctx, "CREATE FLOW: app_bundle UUID set", tags, map[string]any{"uuid": validatedAppBundleUUID})
	}

	car.AdvancedSettings = *advSettings

	return nil
}

// CreateMinimalApplication creates an application with minimal required fields only
func (mcar *MinimalCreateAppRequest) CreateMinimalApplication(ctx context.Context, ec *EaaClient) (*ApplicationResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}
	logging.Info(ctx, "create minimal application", tags)

	// Log the minimal payload being sent to API
	if payloadBytes, err := json.MarshalIndent(mcar, "", "  "); err == nil {
		logging.Trace(ctx, "minimal API payload being sent", tags, map[string]any{"payload": string(payloadBytes)})
	} else {
		logging.Warn(ctx, "failed to marshal minimal application payload for logging", tags, map[string]any{"error": err.Error()})
	}

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, APPS_URL)
	var appResp ApplicationResponse
	createAppResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", mcar, &appResp, false)

	if err != nil {
		return nil, logging.Wrapf(err, tags, "create minimal Application failed")
	}

	if createAppResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(createAppResp)
		return nil, logging.Wrapf(ErrAppCreate, tags, "%s", desc)
	}
	logging.Info(ctx, "create minimal Application succeeded", tags, map[string]any{"name": mcar.Name})
	return &appResp, nil
}

func (car *CreateAppRequest) CreateApplication(ctx context.Context, ec *EaaClient) (*ApplicationResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}
	logging.Info(ctx, "create application", tags)

	// Log the complete payload being sent to API
	if payloadBytes, err := json.MarshalIndent(car, "", "  "); err == nil {
		logging.Trace(ctx, "complete API payload being sent", tags, map[string]any{"payload": string(payloadBytes)})
	} else {
		logging.Warn(ctx, "failed to marshal application payload for logging", tags, map[string]any{"error": err.Error()})
	}

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, APPS_URL)
	var appResp ApplicationResponse
	createAppResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", car, &appResp, false)

	if err != nil {
		return nil, logging.Wrapf(err, tags, "create Application failed")
	}

	if createAppResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(createAppResp)
		return nil, logging.Wrapf(ErrAppCreate, tags, "%s", desc)
	}
	logging.Info(ctx, "create Application succeeded", tags, map[string]any{"name": car.Name})
	return &appResp, nil
}

// Configuration functions for Phase 2 of the two-phase approach

// ConfigureAgents assigns agents to an existing application
func ConfigureAgents(ctx context.Context, appID string, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}

	if agentsRaw, ok := d.GetOk("agents"); ok {
		agentsList, ok := agentsRaw.([]interface{})
		if !ok {
			logging.Error(ctx, "configure agents failed: agents is invalid", tags)
			return ErrInvalidType
		}
		var agents AssignAgents
		agents.AppID = appID
		for _, v := range agentsList {
			if name, ok := v.(string); ok {
				agents.AgentNames = append(agents.AgentNames, name)
			}
		}
		err := agents.AssignAgents(ctx, ec)
		if err != nil {
			return logging.Wrapf(err, tags, "configure agents failed")
		}
		logging.Debug(ctx, "configure agents succeeded", tags)
	}
	return nil
}

// ConfigureAuthentication configures authentication settings for an existing application
func ConfigureAuthentication(ctx context.Context, appID string, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}

	authEnabled := "false"
	if aE, ok := d.GetOk("auth_enabled"); ok {
		authEnabledValue, ok := aE.(string)
		if !ok {
			logging.Error(ctx, "configure authentication failed: auth_enabled is invalid", tags)
			return ErrInvalidType
		}
		authEnabled = authEnabledValue
	}

	if authEnabled == "true" {
		if appAuth, ok := d.GetOk("app_authentication"); ok {
			appAuthList, ok := appAuth.([]interface{})
			if !ok {
				logging.Error(ctx, "invalid authentication list", tags)
				return ErrInvalidType
			}
			if appAuthList == nil {
				logging.Error(ctx, "app_authentication list is nil", tags)
				return logging.Wrapf(ErrInvalidValue, tags, "app_authentication list is nil")
			}
			if len(appAuthList) > 0 {
				appAuthenticationMap, ok := appAuthList[0].(map[string]interface{})
				if !ok {
					logging.Error(ctx, "invalid authentication data", tags)
					return fmt.Errorf("invalid app_authentication: unexpected type, expected map[string]interface{}")
				}
				if appAuthenticationMap == nil {
					logging.Error(ctx, "empty authentication data", tags)
					return fmt.Errorf("invalid app_authentication data")
				}

				// Check if app_idp key is present
				if appIDPName, ok := appAuthenticationMap["app_idp"].(string); ok {
					idpData, err := GetIdpWithName(ctx, ec, appIDPName)
					if err != nil {
						return err
					}
					if idpData == nil {
						return logging.Errorf(tags, "IDP '%s' not found", appIDPName)
					}
					logging.Debug(ctx, "IDP assignment context", tags, map[string]any{"appID": appID, "app_idp_name": appIDPName, "idp_uuid_url": idpData.UUIDURL})
					logging.Debug(ctx, "assigning IDP to application", tags)

					appIdp := AppIdp{
						App: appID,
						IDP: idpData.UUIDURL,
					}
					err = appIdp.AssignIDP(ctx, ec)
					if err != nil {
						return logging.Wrapf(err, tags, "assigning IDP to the app failed")
					}
					logging.Debug(ctx, "IDP assigned successfully", tags, map[string]any{"appID": appID, "idp": appIDPName})

					// check if app_directories are present
					if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
						logging.Debug(ctx, "starting directory assignment", tags)
						err := idpData.AssignIdpDirectories(ctx, appDirs, appID, ec)
						if err != nil {
							return logging.Wrapf(err, tags, "assigning directories to the app failed")
						}
						logging.Debug(ctx, "directory assignment succeeded", tags)
					}
				}
			}
		}
	}
	return nil
}

// ConfigureAdvancedSettings configures advanced settings for an existing application
func ConfigureAdvancedSettings(ctx context.Context, appID string, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagUpdate}

	// Create update request with advanced settings
	updateRequest := ApplicationUpdateRequest{}

	// Get the current app data
	var appResp ApplicationResponse
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, appID)
	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to get app for advanced settings configuration")
	}
	if getResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(getResp)
		return logging.Errorf(tags, "failed to get app: %s", desc)
	}

	// Convert response to Application struct
	app := Application{}
	app.FromResponse(&appResp)
	updateRequest.Application = app

	// Update the request with advanced settings from schema
	err = updateRequest.UpdateAppRequestFromSchema(ctx, d, ec)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to prepare advanced settings update request")
	}

	// Apply authentication transformation logic using centralized helper
	authResult := applyAuthTransformation(d)
	if authResult.EnableSAML || authResult.EnableOIDC || authResult.EnableWSFED {
		updateRequest.SAML = authResult.EnableSAML
		updateRequest.Oidc = authResult.EnableOIDC
		updateRequest.WSFED = authResult.EnableWSFED
		updateRequest.AdvancedSettings.AppAuth = authResult.AppAuth
		if authResult.EnableOIDC {
			updateRequest.SAMLSettings = []SAMLConfig{}
		}
	}

	// Apply the update
	err = updateRequest.UpdateApplication(ctx, ec)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to apply advanced settings")
	}

	logging.Debug(ctx, "configure advanced settings succeeded", tags)
	return nil
}

// ConfigureService configures the access service and ACL rules for a newly created application.
// On create there are no pre-existing rules, so it simply enables the service and creates all rules.
func ConfigureService(ctx context.Context, appID string, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}

	servicesRaw, ok := d.GetOk("service")
	if !ok {
		return nil
	}
	services, ok := servicesRaw.([]interface{})
	if !ok || len(services) == 0 {
		return nil
	}

	appSrv, err := GetACLService(ctx, ec, appID)
	if err != nil {
		return err
	}

	aclSrv, err := ExtractACLService(ctx, d, ec)
	if err != nil {
		return err
	}

	if appSrv.Status != aclSrv.Status {
		appSrv.Status = aclSrv.Status
		if err := appSrv.EnableService(ctx, ec); err != nil {
			return err
		}
	}

	for _, rule := range aclSrv.ACLRules {
		if err := rule.CreateAccessRule(ctx, ec, appSrv.UUIDURL); err != nil {
			return err
		}
	}

	logging.Debug(ctx, "configure service succeeded", tags)
	return nil
}

// DeployExistingApplication deploys an existing application
func DeployExistingApplication(ctx context.Context, appID string, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagDeploy}

	// Get the current app data
	var appResp ApplicationResponse
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, appID)
	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to get app for deployment")
	}
	if getResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(getResp)
		return logging.Errorf(tags, "failed to get app: %s", desc)
	}

	// Convert response to Application struct
	app := Application{}
	app.FromResponse(&appResp)

	// Deploy the application
	err = app.DeployApplication(ctx, ec)
	if err != nil {
		return logging.Wrapf(err, tags, "deploy application failed")
	}

	logging.Debug(ctx, "deploy application succeeded", tags)
	return nil
}

type Application struct {
	Cert                   *string              `json:"cert"`
	Description            *string              `json:"description"`
	OIDCSettings           *OIDCConfig          `json:"oidc_settings,omitempty"`
	CName                  *string              `json:"cname"`
	Host                   *string              `json:"host"`
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

func (app *Application) UpdateG2O(ctx context.Context, ec *EaaClient) (*G2OResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagUpdate}
	logging.Debug(ctx, "updateG2O", tags)
	apiURL := fmt.Sprintf("%s://%s/%s/%s/g2o", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)

	var g2oResp G2OResponse
	g2ohttpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", nil, &g2oResp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "g2o request failed")
	}
	if g2ohttpResp.StatusCode < http.StatusOK || g2ohttpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(g2ohttpResp)
		return nil, logging.Wrapf(ErrAppUpdate, tags, "%s", desc)
	}
	return &g2oResp, nil
}

func (app *Application) UpdateEdgeAuthentication(ctx context.Context, ec *EaaClient) (*EdgeAuthResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagUpdate}
	logging.Debug(ctx, "UpdateEdgeAuthentication", tags)
	apiURL := fmt.Sprintf("%s://%s/%s/%s/edgekey", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)

	var edgeAuthResp EdgeAuthResponse
	edgeAuthhttpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", nil, &edgeAuthResp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "edge auth request failed")
	}
	if edgeAuthhttpResp.StatusCode < http.StatusOK || edgeAuthhttpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(edgeAuthhttpResp)
		return nil, logging.Wrapf(ErrAppUpdate, tags, "%s", desc)
	}
	return &edgeAuthResp, nil
}

func (app *Application) DeployApplication(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagDeploy}
	logging.Info(ctx, "deploying application", tags, map[string]any{"app": app.UUIDURL})
	apiURL := fmt.Sprintf("%s://%s/%s/%s/deploy", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)
	data := map[string]interface{}{
		"deploy_note": "deploying the app managed through terraform",
	}
	deployResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", data, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to deploy application")
	}

	if deployResp.StatusCode < http.StatusOK || deployResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(deployResp)
		return logging.Wrapf(ErrDeploy, tags, "HTTP %d: %s", deployResp.StatusCode, desc)
	}
	return nil
}

func (app *Application) DeleteApplication(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagDelete}
	logging.Info(ctx, "deleting application", tags, map[string]any{"app": app.UUIDURL})
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)

	deleteResp, err := ec.SendAPIRequest(ctx, apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to delete application")
	}

	if deleteResp.StatusCode < http.StatusOK || deleteResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(deleteResp)
		return logging.Wrapf(ErrAppDelete, tags, "HTTP %d: %s", deleteResp.StatusCode, desc)
	}
	return nil
}

type ApplicationUpdateRequest struct {
	OIDCSettings     *OIDCConfig              `json:"oidc_settings"`
	Domain           string                   `json:"domain"`
	AdvancedSettings AdvancedSettingsComplete `json:"advanced_settings"`
	SAMLSettings     []SAMLConfig             `json:"saml_settings"`
	WSFEDSettings    []WSFEDConfig            `json:"wsfed_settings"`
	Application
}

func (appUpdateReq *ApplicationUpdateRequest) UpdateAppRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagUpdate}
	logging.Debug(ctx, "updating application", tags)

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
			appBundleUUID, err := ec.GetAppBundleByName(ctx, appBundleStr)
			if err != nil {
				logging.Error(ctx, "UPDATE FLOW: failed to validate app_bundle name", tags, map[string]any{"app_bundle": appBundleStr, "error": err.Error()})
				return fmt.Errorf("invalid app_bundle name '%s': %w", appBundleStr, err)
			}

			validatedAppBundleUUID = appBundleUUID
			logging.Debug(ctx, "UPDATE FLOW: app_bundle validated", tags, map[string]any{"app_bundle": appBundleStr, "uuid": appBundleUUID})
		}
	}

	appUpdateReq.TunnelInternalHosts = []TunnelInternalHost{}
	if tunnelInternalHosts, ok := d.GetOk("tunnel_internal_hosts"); ok {
		if tunnelInternalHostsList, ok := tunnelInternalHosts.([]interface{}); ok {
			for _, th := range tunnelInternalHostsList {
				thData, ok := th.(map[string]interface{})
				if !ok {
					logging.Warn(ctx, "skipping malformed tunnel_internal_hosts entry", tags)
					continue
				}
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

	if ac, ok := d.GetOk("app_category"); ok {
		if acValue, ok := ac.(string); ok {

			if acValue != "" {
				uuid, err := GetAppCategoryUUID(ctx, ec, acValue)
				if err != nil {
					return fmt.Errorf("app_category lookup failed for %q: %w", acValue, err)
				}
				category := AppCategory{}
				category.Name = acValue
				category.UUID_URL = uuid
				appUpdateReq.AppCategory = category
			}
		}
	}

	// tls_suite_name is read from the top-level Terraform schema attribute (not from the advanced_settings map)
	if tlsSuiteName, ok := d.GetOk("tls_suite_name"); ok {
		if tlsSuiteNameStr, ok := tlsSuiteName.(string); ok {
			if tlsSuiteNameStr != "" {
				appUpdateReq.TLSSuiteName = &tlsSuiteNameStr
				logging.Debug(ctx, "UPDATE FLOW: tls_suite_name set", tags, map[string]any{"value": tlsSuiteNameStr})
			} else {
				logging.Warn(ctx, "UPDATE FLOW: tls_suite_name is set to empty string; ignoring because the API does not support clearing", tags)
			}
		}
	}

	// Handle advanced settings for UPDATE flow - read from TypeMap block
	var updateUserSettings map[string]interface{}
	if advMap, ok := d.GetOk("advanced_settings"); ok {
		if m, ok := advMap.(map[string]interface{}); ok {
			updateUserSettings = m
		}
	}

	if updateUserSettings != nil {
		// Parse and apply defaults
		advSettings, err := advancedSettingsFromBlock(updateUserSettings)
		if err != nil {
			return fmt.Errorf("failed to parse advanced settings block: %w", err)
		}

		// Preserve user-provided app_auth value from advanced_settings
		logging.Debug(ctx, "UPDATE FLOW: using app_auth from advanced_settings", tags, map[string]any{"app_auth": advSettings.AppAuth})

		// Note: SAML/OIDC/WS-FED settings are now handled outside this block
		// to ensure they run regardless of whether advanced_settings is provided

		// Handle special cases that require API calls
		if advSettings.G2OEnabled == STR_TRUE {
			g2oResp, err := appUpdateReq.UpdateG2O(ctx, ec)
			if err != nil {
				logging.Error(ctx, "g2o request failed", tags, map[string]any{"error": err.Error()})
				return err
			}
			advSettings.G2OKey = &g2oResp.G2OKey
			advSettings.G2ONonce = &g2oResp.G2ONonce
		}

		if advSettings.EdgeAuthenticationEnabled == STR_TRUE {
			edgeAuthResp, err := appUpdateReq.UpdateEdgeAuthentication(ctx, ec)
			if err != nil {
				logging.Error(ctx, "edge auth cookie request failed", tags, map[string]any{"error": err.Error()})
				return err
			}
			advSettings.EdgeCookieKey = &edgeAuthResp.EdgeCookieKey
			advSettings.SLAObjectURL = &edgeAuthResp.SLAObjectURL
		}

		// Use the UpdateAdvancedSettings function to properly update the struct
		UpdateAdvancedSettings(&appUpdateReq.AdvancedSettings, advSettings)

		// Explicitly set the AppAuth field to ensure it's preserved
		appUpdateReq.AdvancedSettings.AppAuth = advSettings.AppAuth

		// Log the final advanced settings to see what's being sent
		logging.Debug(ctx, "UPDATE FLOW: Final advanced settings AppAuth", tags, map[string]any{"app_auth": appUpdateReq.AdvancedSettings.AppAuth})
	}

	// Set the app bundle UUID on the Application struct (top-level field)
	// This must run regardless of whether advanced_settings is provided.
	if validatedAppBundleUUID != "" {
		appUpdateReq.AppBundle = validatedAppBundleUUID
		logging.Debug(ctx, "UPDATE FLOW: Set app_bundle UUID on Application struct", tags, map[string]any{"uuid": validatedAppBundleUUID})
	}

	// Set authentication flags based on Terraform boolean flags for UPDATE flow
	// This logic runs regardless of whether advanced_settings is provided

	// Determine SAML automatically based on business logic for UPDATE flow
	// Get app_auth from the structured advanced_settings block
	var appAuth string
	if updateUserSettings != nil {
		if appAuthVal, ok := updateUserSettings["app_auth"].(string); ok {
			appAuth = appAuthVal
		}
	}

	// Check if SAML should be enabled based on app configuration
	samlResult := shouldEnableAuthForCreate(d, appAuth, getAuthProtocolConfig(AuthProtocolTypeSAML))

	if samlResult {
		logging.Debug(ctx, "SAML automatically enabled based on app configuration", tags)
		appUpdateReq.SAML = true
		appUpdateReq.Oidc = false
		appUpdateReq.WSFED = false
		// Override app_auth to "none" when SAML is enabled
		appUpdateReq.AdvancedSettings.AppAuth = "none"
		logging.Debug(ctx, "SAML enabled, app_auth set to 'none'", tags)

		// Use schema approach (nested blocks)
		if samlSettings, ok := d.GetOk("saml_settings"); ok {
			logging.Debug(ctx, "UPDATE FLOW: Found saml_settings blocks", tags)
			if samlSettingsList, ok := samlSettings.([]interface{}); ok && len(samlSettingsList) > 0 {
				// Defensively check type of first element before asserting
				if samlBlock, ok := samlSettingsList[0].(map[string]interface{}); ok {
					// Convert nested blocks to SAMLConfig
					samlConfig, err := convertNestedBlocksToSAMLConfig(samlBlock)
					if err != nil {
						logging.Error(ctx, "UPDATE FLOW: Failed to convert nested blocks to SAML config", tags, map[string]any{"error": err.Error()})
						return fmt.Errorf("failed to convert nested blocks to SAML config: %w", err)
					}
					appUpdateReq.SAMLSettings = []SAMLConfig{samlConfig}
					logging.Debug(ctx, "UPDATE FLOW: Successfully converted nested blocks to SAML config", tags)
				} else {
					logging.Error(ctx, "UPDATE FLOW: saml_settings[0] is not a map[string]interface{}", tags)
					return fmt.Errorf("invalid saml_settings format: expected map[string]interface{}")
				}
			} else {
				// No saml_settings provided but SAML is enabled - use DefaultSAMLConfig
				logging.Debug(ctx, "UPDATE FLOW: No saml_settings found, using DefaultSAMLConfig", tags)
				appUpdateReq.SAMLSettings = []SAMLConfig{DefaultSAMLConfig}
				logging.Debug(ctx, "UPDATE FLOW: Set SAMLSettings with DefaultSAMLConfig", tags)
			}
		}
	} else {
		oidcResult := shouldEnableAuthForCreate(d, appAuth, getAuthProtocolConfig(AuthProtocolTypeOIDC))

		if oidcResult {
			logging.Debug(ctx, "OIDC automatically enabled based on app configuration", tags)
			appUpdateReq.SAML = false
			appUpdateReq.Oidc = true
			appUpdateReq.WSFED = false
			// Override app_auth only when oidc=true
			appUpdateReq.AdvancedSettings.AppAuth = "oidc"
			appUpdateReq.SAMLSettings = []SAMLConfig{} // Clear SAML settings when OIDC is enabled

			// Handle OIDC settings for UPDATE flow
			if oidcSettings, ok := d.GetOk("oidc_settings"); ok {
				logging.Debug(ctx, "UPDATE FLOW: Found oidc_settings blocks", tags)
				if oidcSettingsList, ok := oidcSettings.([]interface{}); ok && len(oidcSettingsList) > 0 {
					// Defensively check type of first element before asserting
					if oidcBlock, ok := oidcSettingsList[0].(map[string]interface{}); ok {
						// Convert nested blocks to OIDCConfig
						oidcConfig, err := convertNestedBlocksToOIDCConfig(oidcBlock)
						if err != nil {
							logging.Error(ctx, "UPDATE FLOW: Failed to convert nested blocks to OIDC config", tags, map[string]any{"error": err.Error()})
							return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
						}
						appUpdateReq.OIDCSettings = oidcConfig
						logging.Debug(ctx, "UPDATE FLOW: Successfully converted nested blocks to OIDC config", tags)
					} else {
						logging.Error(ctx, "UPDATE FLOW: oidc_settings[0] is not a map[string]interface{}", tags)
						return fmt.Errorf("invalid oidc_settings format: expected map[string]interface{}")
					}
				} else {
					logging.Debug(ctx, "UPDATE FLOW: No oidc_settings found, creating defaults", tags)
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
				logging.Debug(ctx, "UPDATE FLOW: No oidc_settings found, creating defaults", tags)
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
			logging.Debug(ctx, "WSFED automatically enabled based on app configuration", tags)
			appUpdateReq.SAML = false
			appUpdateReq.Oidc = false
			appUpdateReq.WSFED = true
			// Override app_auth to "none" when WSFED is enabled
			appUpdateReq.AdvancedSettings.AppAuth = "none"
			logging.Debug(ctx, "WSFED enabled, app_auth set to 'none'", tags)
			appUpdateReq.SAMLSettings = []SAMLConfig{} // Clear SAML settings when WS-FED is enabled
		}
	}

	// Handle WS-Federation settings for UPDATE flow
	if appUpdateReq.WSFED {
		if wsfedSettingsData, ok := d.GetOk("wsfed_settings"); ok {
			// User provided wsfed_settings as nested blocks - parse them
			logging.Debug(ctx, "UPDATE FLOW: Found wsfed_settings as nested blocks", tags)
			if wsfedSettingsList, ok := wsfedSettingsData.([]interface{}); ok && len(wsfedSettingsList) > 0 {
				// Defensively check type of first element before asserting
				wsfedBlock, ok := wsfedSettingsList[0].(map[string]interface{})
				if !ok {
					logging.Error(ctx, "UPDATE FLOW: wsfed_settings[0] is not a map[string]interface{}", tags)
					return fmt.Errorf("invalid wsfed_settings format: expected map[string]interface{}")
				}

				// Start with DefaultWSFEDConfig as base
				wsfedConfig := DefaultWSFEDConfig

				// Merge SP settings
				if spBlocks, ok := wsfedBlock["sp"].([]interface{}); ok && len(spBlocks) > 0 {
					spBlock, err := firstMapBlock(spBlocks, "wsfed_settings.sp")
					if err != nil {
						logging.Error(ctx, "UPDATE FLOW: Failed to read nested WSFED SP block", tags, map[string]any{"error": err.Error()})
						return err
					}

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
					idpBlock, err := firstMapBlock(idpBlocks, "wsfed_settings.idp")
					if err != nil {
						logging.Error(ctx, "UPDATE FLOW: Failed to read nested WSFED IDP block", tags, map[string]any{"error": err.Error()})
						return err
					}

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
					subjectBlock, err := firstMapBlock(subjectBlocks, "wsfed_settings.subject")
					if err != nil {
						logging.Error(ctx, "UPDATE FLOW: Failed to read nested WSFED subject block", tags, map[string]any{"error": err.Error()})
						return err
					}

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
						attrMap, ok := attrBlock.(map[string]interface{})
						if !ok {
							logging.Warn(ctx, "skipping malformed WSFED attrmap entry", tags)
							continue
						}
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
					wsfedConfig.Attrmap = attrmap
				}

				// Use the merged configuration
				appUpdateReq.WSFEDSettings = []WSFEDConfig{wsfedConfig}
				logging.Debug(ctx, "UPDATE FLOW: Successfully merged WSFED config from nested blocks", tags)
			}
		} else {
			// No wsfed_settings provided but WSFED is enabled - use default structure
			logging.Debug(ctx, "UPDATE FLOW: No wsfed_settings found, using DefaultWSFEDConfig", tags)
			appUpdateReq.WSFEDSettings = []WSFEDConfig{DefaultWSFEDConfig}
		}
	} else {
		appUpdateReq.WSFEDSettings = []WSFEDConfig{}
	}

	// Handle OIDC settings for UPDATE flow
	var oidcConfig *OIDCConfig

	if appUpdateReq.Oidc {
		if oidcSettingsData, ok := d.GetOk("oidc_settings"); ok {
			logging.Debug(ctx, "UPDATE FLOW: Found oidc_settings blocks", tags)
			if oidcSettingsList, ok := oidcSettingsData.([]interface{}); ok && len(oidcSettingsList) > 0 {
				// Convert nested blocks to OIDCConfig (consistent with CREATE flow)
				oidcBlock, err := firstMapBlock(oidcSettingsList, "oidc_settings")
				if err != nil {
					logging.Error(ctx, "UPDATE FLOW: Failed to read nested OIDC block", tags, map[string]any{"error": err.Error()})
					return err
				}
				convertedConfig, err := convertNestedBlocksToOIDCConfig(oidcBlock)
				if err != nil {
					logging.Error(ctx, "UPDATE FLOW: Failed to convert nested blocks to OIDC config", tags, map[string]any{"error": err.Error()})
					return fmt.Errorf("failed to convert nested blocks to OIDC config: %w", err)
				}
				oidcConfig = convertedConfig
				logging.Debug(ctx, "UPDATE FLOW: Successfully converted nested blocks to OIDC config", tags)
			}
		} else {
			logging.Debug(ctx, "UPDATE FLOW: No oidc_settings found, creating defaults", tags)
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
				sData, ok := s.(map[string]interface{})
				if !ok {
					logging.Warn(ctx, "skipping malformed server entry", tags)
					continue
				}
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
			if popregionstr != "" {
				popname, uuid, err := GetPopUUID(ctx, ec, popregionstr)
				if err != nil {
					logging.Error(ctx, "POP region lookup failed", tags, map[string]any{"popregion": popregionstr, "error": err.Error()})
					return logging.Wrapf(err, tags, "failed to resolve POP region '%s'", popregionstr)
				}
				appUpdateReq.POPName = popname
				appUpdateReq.POP = uuid
			}
		}
	}

	if domain, ok := d.GetOk("domain"); ok {
		if strDomain, ok := domain.(string); ok {
			appDomain := Domain(strDomain)
			value, err := appDomain.ToInt()
			if err != nil {
				logging.Error(ctx, "Update Application failed. Domain is invalid", tags)
				return ErrInvalidValue
			}
			appUpdateReq.Domain = strconv.Itoa(value)

			if appDomain == AppDomainCustom {
				if err := processCustomDomain(ctx, ec, appUpdateReq, d); err != nil {
					logging.Error(ctx, "custom domain processing failed", tags, map[string]any{"error": err.Error()})
					return err
				}
			}
		}
	} else {
		appUpdateReq.Domain = strconv.Itoa(int(APP_DOMAIN_WAPP))
	}

	return nil
}
func processCustomDomain(ctx context.Context, ec *EaaClient, appUpdateReq *ApplicationUpdateRequest, d *schema.ResourceData) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagUpdate}
	logging.Debug(ctx, "Custom domain", tags)

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
	logging.Debug(ctx, "certificate type", tags, map[string]any{"cert_type": appCert})

	if appCert == CertSelfSigned && (appUpdateReq.Host == nil || *appUpdateReq.Host == "") {
		logging.Warn(ctx, "Skipping custom domain certificate processing because host is empty", tags)
		return nil
	}

	// Check if the certificate type is self-signed
	if appCert == CertSelfSigned {
		// Check if a self-signed certificate exists for the given hostname
		certObj, err := DoesSelfSignedCertExistForHost(ctx, ec, *appUpdateReq.Host)
		if err != nil {
			return fmt.Errorf("failed to check self-signed certificate existence: %w", err)
		}

		if certObj != nil {
			// Use existing self-signed certificate
			appUpdateReq.Cert = &certObj.UUIDURL
			logging.Debug(ctx, "using existing self-signed certificate", tags, map[string]any{"cert": appUpdateReq.Cert})
			return nil
		}

		logging.Debug(ctx, "Generating self-signed certificate", tags)
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
		logging.Debug(ctx, "generated self-signed certificate", tags, map[string]any{"cert": appUpdateReq.Cert})
		return nil
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
		certObj, err := DoesUploadedCertExist(ctx, ec, certStr)
		if err != nil {
			return logging.Wrapf(err, tags, "failed to check uploaded certificate '%s'", certStr)
		}
		if certObj == nil {
			return logging.Errorf(tags, "uploaded certificate '%s' not found", certStr)
		}

		// Use existing self-signed certificate
		appUpdateReq.Cert = &certObj.UUIDURL
		logging.Debug(ctx, "using uploaded cert", tags, map[string]any{"cert": appUpdateReq.Cert})
	}

	return nil
}

func (appUpdateReq *ApplicationUpdateRequest) UpdateApplication(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagUpdate}
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, appUpdateReq.UUIDURL)
	logging.Debug(ctx, "API URL", tags, map[string]any{"url": apiURL})

	// Debug: Log the final app bundle before sending to API
	logging.Debug(ctx, "FINAL PAYLOAD", tags, map[string]any{"app_bundle": appUpdateReq.AppBundle})

	// Debug: Log the complete request payload
	if payloadJSON, err := json.MarshalIndent(appUpdateReq, "", "  "); err == nil {
		logging.Debug(ctx, "complete request payload", tags, map[string]any{"payload": string(payloadJSON)})
	} else {
		logging.Warn(ctx, "failed to marshal application update payload for logging", tags, map[string]any{"error": err.Error()})
	}

	appUpdResp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", appUpdateReq, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "update application failed")
	}

	if appUpdResp.StatusCode < http.StatusOK || appUpdResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(appUpdResp)
		return logging.Wrapf(ErrAppUpdate, tags, "HTTP %d: %s", appUpdResp.StatusCode, desc)
	}

	// Post-success: log response for diagnostics (non-fatal if this fails)
	responseBody, err := io.ReadAll(appUpdResp.Body)
	if err != nil {
		logging.Warn(ctx, "failed to read application update response body for logging", tags, map[string]any{"error": err.Error()})
		return nil
	}
	var responseData map[string]interface{}
	if err := json.Unmarshal(responseBody, &responseData); err != nil {
		logging.Warn(ctx, "failed to unmarshal application update response for diagnostics", tags, map[string]any{"error": err.Error()})
		return nil
	}
	logging.Debug(ctx, "API RESPONSE", tags)
	if responseJSON, err := json.MarshalIndent(responseData, "", "  "); err == nil {
		logging.Debug(ctx, string(responseJSON), tags)
	} else {
		logging.Warn(ctx, "failed to marshal application update response for logging", tags, map[string]any{"error": err.Error()})
	}

	// Show specific advanced settings from response
	if advancedSettings, ok := responseData["advanced_settings"].(map[string]interface{}); ok {
		logging.Debug(ctx, "ADVANCED SETTINGS FROM RESPONSE", tags)
		if appAuthDomain, exists := advancedSettings["app_auth_domain"]; exists {
			logging.Debug(ctx, fmt.Sprintf("app_auth_domain: %v (type: %T)", appAuthDomain, appAuthDomain), tags)
		} else {
			logging.Debug(ctx, "app_auth_domain: not present in response", tags)
		}
		if appClientCertAuth, exists := advancedSettings["app_client_cert_auth"]; exists {
			logging.Debug(ctx, fmt.Sprintf("app_client_cert_auth: %v (type: %T)", appClientCertAuth, appClientCertAuth), tags)
		} else {
			logging.Debug(ctx, "app_client_cert_auth: not present in response", tags)
		}
		if acceleration, exists := advancedSettings["acceleration"]; exists {
			logging.Debug(ctx, fmt.Sprintf("acceleration: %v (type: %T)", acceleration, acceleration), tags)
		} else {
			logging.Debug(ctx, "acceleration: not present in response", tags)
		}
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
	AdvancedSettings       AdvancedSettingsComplete `json:"advanced_settings"`
	AppCategory            AppCategory              `json:"app_category"`
	WSFEDSettings          []WSFEDConfig            `json:"wsfed_settings,omitempty"`
	SAMLSettings           []SAMLConfig             `json:"saml_settings,omitempty"`
	Servers                []Server                 `json:"servers"`
	OIDCClients            []OIDCClient             `json:"oidcclients,omitempty"`
	OIDCSettings           *OIDCSettings            `json:"oidc_settings,omitempty"`
	OriginHost             *string                  `json:"origin_host"`
	Host                   *string                  `json:"host"`
	AppLogo                *string                  `json:"app_logo"`
	Description            *string                  `json:"description"`
	AppProfileID           *string                  `json:"app_profile_id"`
	CName                  *string                  `json:"cname"`
	TLSSuiteName           *string                  `json:"tls_suite_name"`
	Cert                   *string                  `json:"cert"`
	CreatedAt              string                   `json:"created_at"`
	DomainSuffix           string                   `json:"domain_suffix"`
	AuthEnabled            string                   `json:"auth_enabled"`
	RDPVersion             string                   `json:"rdp_version"`
	UUIDURL                string                   `json:"uuid_url"`
	Resource               string                   `json:"resource"`
	BookmarkURL            string                   `json:"bookmark_url"`
	POP                    string                   `json:"pop"`
	FailoverPopName        string                   `json:"failover_popName"`
	SSLCACert              string                   `json:"ssl_ca_cert"`
	POPRegion              string                   `json:"popRegion"`
	ModifiedAt             string                   `json:"modified_at"`
	Name                   string                   `json:"name"`
	POPName                string                   `json:"popName"`
	OrigTLS                string                   `json:"orig_tls"`
	AppBundle              string                   `json:"app_bundle,omitempty"`
	TunnelInternalHosts    []TunnelInternalHost     `json:"tunnel_internal_hosts"`
	Domain                 int                      `json:"domain"`
	AuthType               int                      `json:"auth_type"`
	AppStatus              int                      `json:"app_status"`
	OriginPort             int                      `json:"origin_port"`
	AppOperational         int                      `json:"app_operational"`
	AppProfile             int                      `json:"app_profile"`
	Status                 int                      `json:"status"`
	SupportedClientVersion int                      `json:"supported_client_version"`
	ClientAppMode          int                      `json:"client_app_mode"`
	AppType                int                      `json:"app_type"`
	FQDNBridgeEnabled      bool                     `json:"fqdn_bridge_enabled"`
	WSFED                  bool                     `json:"wsfed"`
	SAML                   bool                     `json:"saml"`
	Oidc                   bool                     `json:"oidc"`
	AppDeployed            bool                     `json:"app_deployed"`
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

type G2OResponse struct {
	G2OEnabled string `json:"g2o_enabled,omitempty"`
	G2ONonce   string `json:"g2o_nonce,omitempty"`
	G2OKey     string `json:"g2o_key,omitempty"`
}

type EdgeAuthResponse struct {
	EdgeCookieKey string `json:"edge_cookie_key,omitempty"`
	SLAObjectURL  string `json:"sla_object_url,omitempty"`
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
	SLAObjectURL                 *string                `json:"sla_object_url,omitempty"`
	UserName                     *string                `json:"user_name"`
	SessionStickyServerCookie    *string                `json:"session_sticky_server_cookie"`
	RequestParameters            *string                `json:"request_parameters"`
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
	ExtraFields                  map[string]interface{} `json:"-"`
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
	AppServerReadTimeout         FlexString             `json:"app_server_read_timeout,omitempty"`
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
	OffloadOnPremiseTraffic      string                 `json:"offload_onpremise_traffic,omitempty"`
	Onramp                       string                 `json:"onramp,omitempty"`
	XWappReadTimeout             FlexString             `json:"x_wapp_read_timeout,omitempty"`
	PreauthConsent               string                 `json:"preauth_consent,omitempty"`
	PreauthEnforceURL            string                 `json:"preauth_enforce_url,omitempty"`
	ProxyBufferSizeKB            string                 `json:"proxy_buffer_size_kb,omitempty"`
	ProxyDisableClipboard        string                 `json:"proxy_disable_clipboard,omitempty"`
	RateLimit                    string                 `json:"rate_limit,omitempty"`
	KerberosNegotiateOnce        string                 `json:"kerberos_negotiate_once,omitempty"`
	KeyedKeepaliveEnable         string                 `json:"keyed_keepalive_enable,omitempty"`
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
	XWappPoolSize                FlexString             `json:"x_wapp_pool_size,omitempty"`
	XWappPoolTimeout             FlexString             `json:"x_wapp_pool_timeout,omitempty"`
	RDPKeyboardLang              string                 `json:"rdp_keyboard_lang,omitempty"`
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`
	RefreshStickyCookie          string                 `json:"refresh_sticky_cookie,omitempty"`
	RDPInitialProgram            string                 `json:"rdp_initial_program,omitempty"`
	RDPRemoteApps                []RemoteApp            `json:"rdp_remote_apps,omitempty"`
	FormPostAttributes           []string               `json:"form_post_attributes,omitempty"`
	CustomHeaders                []CustomHeader         `json:"custom_headers,omitempty"`
}

// MarshalJSON merges typed struct fields with any unrecognised passthrough keys in ExtraFields.
func (a *AdvancedSettings) MarshalJSON() ([]byte, error) {
	type Alias AdvancedSettings
	base, err := json.Marshal(Alias(*a))
	if err != nil {
		return nil, err
	}
	if len(a.ExtraFields) == 0 {
		return base, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range a.ExtraFields {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshaling extra field %q: %w", k, err)
		}
		merged[k] = raw
	}
	return json.Marshal(merged)
}

type AdvancedSettingsComplete struct {
	AppCookieDomain              *string                `json:"app_cookie_domain,omitempty"`
	LogoutURL                    *string                `json:"logout_url,omitempty"`
	InternalHostname             *string                `json:"internal_hostname,omitempty"`
	CookieDomain                 *string                `json:"cookie_domain"`
	RequestParameters            *string                `json:"request_parameters"`
	IDPIdleExpiry                *string                `json:"idp_idle_expiry,omitempty"`
	IDPMaxExpiry                 *string                `json:"idp_max_expiry,omitempty"`
	AppLocation                  *string                `json:"app_location"`
	TLSSuiteName                 *string                `json:"tls_suite_name,omitempty"`
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
	AppServerReadTimeout         FlexString             `json:"app_server_read_timeout,omitempty"`
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
	XWappReadTimeout             FlexString             `json:"x_wapp_read_timeout,omitempty"`
	XWappPoolEnabled             string                 `json:"x_wapp_pool_enabled,omitempty"`
	XWappPoolSize                FlexString             `json:"x_wapp_pool_size,omitempty"`
	XWappPoolTimeout             FlexString             `json:"x_wapp_pool_timeout,omitempty"`
	RDPKeyboardLang              string                 `json:"rdp_keyboard_lang,omitempty"`
	RDPWindowColorDepth          string                 `json:"rdp_window_color_depth,omitempty"`
	RDPWindowHeight              string                 `json:"rdp_window_height,omitempty"`
	RDPWindowWidth               string                 `json:"rdp_window_width,omitempty"`
	ForceIPRoute                 string                 `json:"force_ip_route,omitempty"`
	ExtraFields                  map[string]interface{} `json:"-"`
	CustomHeaders                []CustomHeader         `json:"custom_headers,omitempty"`
	RDPRemoteApps                []RemoteApp            `json:"rdp_remote_apps,omitempty"`
	FormPostAttributes           []string               `json:"form_post_attributes,omitempty"`
}

func (a *AdvancedSettingsComplete) MarshalJSON() ([]byte, error) {
	type Alias AdvancedSettingsComplete
	base, err := json.Marshal(Alias(*a))
	if err != nil {
		return nil, err
	}
	if len(a.ExtraFields) == 0 {
		return base, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range a.ExtraFields {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshaling extra field %q: %w", k, err)
		}
		merged[k] = raw
	}
	return json.Marshal(merged)
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

// SAMLConfig matches the SAML configuration shape returned by the API.
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

// WSFEDConfig groups WS-Federation configuration sections from the API.
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

// OIDCConfig groups OIDC client configuration from the API.
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

// SAMLSettings preserves the legacy response shape used during SAML parsing.
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
		spData, err := firstMapBlock(spBlocks, "saml_settings.sp")
		if err != nil {
			return config, err
		}

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
		idpData, err := firstMapBlock(idpBlocks, "saml_settings.idp")
		if err != nil {
			return config, err
		}

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
		subjectData, err := firstMapBlock(subjectBlocks, "saml_settings.subject")
		if err != nil {
			return config, err
		}

		if subjectFmt, ok := subjectData["fmt"].(string); ok {
			config.Subject.Fmt = subjectFmt
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
			attrmapMap, ok := attrmapData.(map[string]interface{})
			if !ok {
				continue // SAML attrmap entries come from Terraform schema; type assertion failure here is unexpected
			}
			attrMapping := AttrMapping{}
			if name, ok := attrmapMap["name"].(string); ok {
				attrMapping.Name = name
			}
			if fname, ok := attrmapMap["fname"].(string); ok {
				attrMapping.Fname = fname
			}
			if attrFmt, ok := attrmapMap["fmt"].(string); ok {
				attrMapping.Fmt = attrFmt
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
			clientMap, ok := clientData.(map[string]interface{})
			if !ok {
				continue // OIDC client entries come from Terraform schema; type assertion failure here is unexpected
			}
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
					claimMap, ok := claimData.(map[string]interface{})
					if !ok {
						continue // OIDC claim entries come from Terraform schema; type assertion failure here is unexpected
					}
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
			config.OIDCClients = append(config.OIDCClients, client)
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
