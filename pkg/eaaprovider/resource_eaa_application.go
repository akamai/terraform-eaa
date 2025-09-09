package eaaprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrGetApp      = errors.New("app get failed")
	ErrInvalidData = errors.New("invalid data in schema")
)

func resourceEaaApplication() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaApplicationCreateWrapper,
		ReadContext:   resourceEaaApplicationRead,
		UpdateContext: resourceEaaApplicationUpdate,
		DeleteContext: resourceEaaApplicationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"app_profile": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"app_type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"client_app_mode": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"host": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"bookmark_url": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"domain": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"origin_host": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"orig_tls": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"origin_port": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"tunnel_internal_hosts": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"host": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"port_range": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"proto_type": {
							Type:     schema.TypeInt,
							Optional: true,
						},
					},
				},
			},
			"servers": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"origin_host": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"orig_tls": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"origin_port": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"origin_protocol": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"pop": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"popname": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"popregion": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"auth_enabled": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "false",
			},
			"saml": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"saml_settings": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "SAML settings as a JSON string. Example: '{\"sp\":{\"entity_id\":\"test\",\"acs_url\":\"https://example.com/acs\"},\"idp\":{\"entity_id\":\"test\"},\"subject\":{\"fmt\":\"email\",\"src\":\"user.email\"},\"attrmap\":[]}'",
			},
			"wsfed": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"wsfed_settings": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "WS-Federation settings as a JSON string. Example: '{\"sp\":{\"entity_id\":\"test\",\"slo_url\":\"https://example.com/slo\"},\"idp\":{\"entity_id\":\"test\",\"self_signed\":true},\"subject\":{\"fmt\":\"email\",\"src\":\"user.email\"},\"attrmap\":[]}'",
			},

			"oidc": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"oidc_settings": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "OpenID Connect settings as a JSON string. Example: '{\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"oidc_clients\":[{\"client_name\":\"test\",\"client_id\":\"test_id\",\"response_type\":[\"code\"]}]}'",
			},

			"app_operational": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},
			"app_status": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"app_deployed": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"cname": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"uuid_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"agents": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"app_category": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cert_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cert_type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cert": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"generate_self_signed_cert": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"advanced_settings": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Advanced settings in JSON format or as HCL map.",
				Default:     "{}",
			},
			"service": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"service_type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"status": {
							Type:     schema.TypeString,
							Required: true,
						},
						"access_rule": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"status": {
										Type:     schema.TypeString,
										Required: true,
									},
									"rule": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"operator": {
													Type:     schema.TypeString,
													Required: true,
												},
												"type": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},

			"app_authentication": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"app_idp": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"app_directories": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"enable_mfa": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"app_groups": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"name": {
													Type:     schema.TypeString,
													Required: true,
												},
												"enable_mfa": {
													Type:     schema.TypeString,
													Optional: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
// Wrapper function that handles cleanup on failure
func resourceEaaApplicationCreateWrapper(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
    // Step 1: Call the original create function
    diags := resourceEaaApplicationCreate(ctx, d, m)
    
    // Step 2: Check if creation was successful
    if len(diags) == 0 {
        // Success - nothing to do
        return diags
    }
    
    // Step 3: Check if we have any errors
    hasError := false
    for _, diagnostic := range diags {
        if diagnostic.Severity == diag.Error {
            hasError = true
            break
        }
    }
    
    if !hasError {
        // Only warnings, no errors - return as is
        return diags
    }
    
    // Step 4: We have errors - check if app was created
    appID := d.Id()
    if appID == "" {
        // No ID set, original function failed early - return original error
        return diags
    }
    
    // Step 5: App was created but something failed later
    // This is our problem case - clean up the orphaned app
    eaaclient := m.(*client.EaaClient)
    logger := eaaclient.Logger
    
    logger.Warn("App creation failed but app exists in EAA, cleaning up...")
    
    // Clean up the orphaned app
    cleanupSuccess := cleanupOrphanedApp(ctx, eaaclient, appID)
    
    // Clear the state
    d.SetId("")
    
    if cleanupSuccess {
        logger.Info("Successfully cleaned up orphaned app:", appID)
    } else {
        logger.Error("Failed to clean up orphaned app:", appID)
        // Add a warning about manual cleanup needed
        diags = append(diags, diag.Diagnostic{
            Severity: diag.Warning,
            Summary:  "App creation failed and cleanup was incomplete",
            Detail:   fmt.Sprintf("App %s may still exist in EAA and needs manual cleanup", appID),
        })
    }
    
    // Return the original error
    return diags
}

// Cleanup function for orphaned apps
func cleanupOrphanedApp(ctx context.Context, eaaclient *client.EaaClient, appID string) bool {
    logger := eaaclient.Logger
    logger.Info("Starting cleanup for orphaned app:", appID)
    
    // Check if app exists in EAA
    var appResp client.ApplicationDataModel
    apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, appID)
    
    getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
    if err != nil || getResp.StatusCode != 200 {
        logger.Info("App not found in EAA, no cleanup needed")
        return true
    }
    
    logger.Info("App found in EAA, proceeding with deletion...")
    
    // Delete the app directly
    deleteErr := appResp.DeleteApplication(eaaclient)
    if deleteErr != nil {
        logger.Error("Failed to delete app during cleanup:", deleteErr)
        return false
    }

    verifyResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
    if err == nil && verifyResp.StatusCode == 200 {
        logger.Error("App still exists after deletion attempt")
        return false
    }
    
    logger.Info("App successfully deleted and verified")
    return true
}

// resourceEaaApplicationCreate function is responsible for creating a new EAA application.
// constructs the application creation request using data from the schema and creates the application.
// also handles assigning agents and handling authentication settings if auth_enabled is true.
// updates the application and deploys it, then sets the resource ID.

func resourceEaaApplicationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	createRequest := client.CreateAppRequest{}
	err = createRequest.CreateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		logger.Error("create Application failed. err ", err)
		return diag.FromErr(err)
	}

	appResp, err := createRequest.CreateApplication(ctx, eaaclient)
	if err != nil {
		logger.Error("create Application failed. err ", err)
		return diag.FromErr(err)
	}

	app_uuid_url := appResp.UUIDURL
	app := client.Application{}
	app.FromResponse(appResp)
	
	// Set the resource ID early so cleanup can work if later steps fail
	d.SetId(app_uuid_url)

	if agentsRaw, ok := d.GetOk("agents"); ok {
		agentsList := agentsRaw.([]interface{})
		var agents client.AssignAgents
		agents.AppId = app_uuid_url
		for _, v := range agentsList {
			if name, ok := v.(string); ok {
				agents.AgentNames = append(agents.AgentNames, name)
			}
		}
		err := agents.AssignAgents(ctx, eaaclient)
		if err != nil {
			return diag.FromErr(err)
		}
		logger.Info("create Application: assigning agents succeeded.")
	}

	// Store the update request for later use after IDP assignment
	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = app
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	auth_enabled := "false"

	if aE, ok := d.GetOk("auth_enabled"); ok {
		auth_enabled = aE.(string)
	}

	if auth_enabled == "true" {
		if appAuth, ok := d.GetOk("app_authentication"); ok {
			appAuthList := appAuth.([]interface{})
			if appAuthList == nil {
				return diag.FromErr(ErrInvalidData)
			}
			if len(appAuthList) > 0 {
				appAuthenticationMap := appAuthList[0].(map[string]interface{})
				if appAuthenticationMap == nil {
					logger.Error("invalid authentication data")
					return diag.FromErr(ErrInvalidData)
				}

				// Check if app_idp key is present
				if app_idp_name, ok := appAuthenticationMap["app_idp"].(string); ok {
					idpData, err := client.GetIdpWithName(ctx, eaaclient, app_idp_name)
					if err != nil || idpData == nil {
						logger.Error("get idp with name error, err ", err)
						return diag.FromErr(err)
					}
					logger.Info("app.Name: ", app.Name, "app_idp_name: ", app_idp_name, "idpData.UUIDURL: ", idpData.UUIDURL)

					logger.Info("Assigning IDP to application")
					
					appIdp := client.AppIdp{
						App: app_uuid_url,
						IDP: idpData.UUIDURL,
					}
					err = appIdp.AssignIDP(eaaclient)
					if err != nil {
						logger.Error("IDP assign error: ", err)
						return diag.Errorf("assigning IDP to the app failed: %v", err)
					}
					logger.Info("IDP assigned successfully, app.Name = ", app.Name, "idp = ", app_idp_name)

					// check if app_directories are present
					if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
						logger.Info("Starting directory assignment...")
						err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
						if err != nil {
							logger.Error("Directory assignment error: ", err)
							return diag.FromErr(err)
						}
						logger.Info("Directory assignment completed successfully")
					} else {
						logger.Info("No app_directories found, skipping directory assignment")
					}
				}
			}
		}
	}
	
	// Verify IDP assignment is complete before proceeding
	if auth_enabled == "true" {
		logger.Info("=== DEBUG: Starting IDP assignment verification ===")
		logger.Info("DEBUG: auth_enabled = ", auth_enabled)
		logger.Info("DEBUG: app_uuid_url = ", app_uuid_url)
		
		logger.Info("DEBUG: Waiting 30 seconds for IDP assignment to propagate...")
		//time.Sleep(30 * time.Second) // Give time for IDP assignment to propagate
		
		// Verify the application has the correct authentication settings
		apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, app_uuid_url)
		logger.Info("DEBUG: Fetching application details from: ", apiURL)
		
		var appResp client.ApplicationResponse
		getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
		if err != nil {
			logger.Error("DEBUG: Failed to verify authentication settings: ", err)
			return diag.FromErr(err)
		}
		if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
			logger.Error("DEBUG: Failed to verify authentication settings - bad status code: ", getResp.StatusCode)
			return diag.FromErr(fmt.Errorf("failed to verify authentication settings"))
		}
		
		logger.Info("DEBUG: Application response received successfully")
		logger.Info("DEBUG: appResp.AuthEnabled = ", appResp.AuthEnabled)
		logger.Info("DEBUG: appResp.Name = ", appResp.Name)
		logger.Info("DEBUG: appResp.SAML = ", appResp.SAML)
		logger.Info("DEBUG: appResp.Oidc = ", appResp.Oidc)
		logger.Info("DEBUG: appResp.WSFED = ", appResp.WSFED)
		
		// Check if the application has authentication enabled
		if appResp.AuthEnabled != "true" {
			logger.Info("DEBUG: Authentication not yet enabled, waiting additional 30 seconds...")
			//time.Sleep(30 * time.Second) // Additional wait if needed
			
			// Check again after additional wait
			_, err = eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
			if err != nil {
				logger.Error("DEBUG: Failed to verify authentication settings after additional wait: ", err)
				return diag.FromErr(err)
			}
			logger.Info("DEBUG: After additional wait - appResp.AuthEnabled = ", appResp.AuthEnabled)
		} else {
			logger.Info("DEBUG: Authentication is properly enabled!")
		}
		
		logger.Info("=== DEBUG: IDP assignment verification complete ===")
	}
	
	// Now perform the PUT call to update advanced settings AFTER IDP assignment is complete
	logger.Info("=== DEBUG: Performing PUT call after IDP assignment ===")
	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
	if err != nil {
		logger.Error("DEBUG: PUT call failed after IDP assignment: ", err)
		return diag.FromErr(err)
	}
	logger.Info("=== DEBUG: PUT call completed successfully ===")
	
	_, ok := d.Get("service").([]interface{})
	if ok {
		aclSrv, err := client.ExtractACLService(ctx, d, eaaclient)
		if err != nil {
			return diag.FromErr(err)
		}
		appSrv, err := client.GetACLService(eaaclient, app_uuid_url)
		if err != nil {
			return diag.FromErr(err)
		}
		if appSrv.Status != aclSrv.Status {
			appSrv.Status = aclSrv.Status
			err := appSrv.EnableService(eaaclient)
			if err != nil {
				return diag.FromErr(err)
			}
		}
		if len(aclSrv.ACLRules) > 0 {
			for _, aclRule := range aclSrv.ACLRules {
				err := aclRule.CreateAccessRule(ctx, eaaclient, appSrv.UUIDURL)
				if err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	logger.Info("deploying application after all configuration steps are complete...")
	err = app.DeployApplication(eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	// Resource ID already set earlier, just return the read result
	return resourceEaaApplicationRead(ctx, d, m)
}

// resourceEaaApplicationRead function reads an existing EAA application.
// fetches application details using and maps the response to the schema attributes.

func resourceEaaApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	id := d.Id()
	eaaclient := m.(*client.EaaClient)
	var appResp client.ApplicationResponse

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := client.FormatErrorResponse(getResp)
		getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
		return diag.FromErr(getAppErrMsg)
	}
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

	// DomainSuffix is already a string, no need to convert
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
	attrs["saml"] = appResp.SAML
	attrs["oidc"] = appResp.Oidc
	attrs["wsfed"] = appResp.WSFED

	if appResp.CName != nil {
		attrs["cname"] = *appResp.CName
	}

	// Add missing fields that are showing as null in state
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
	
	// Add more fields to populate null values
	// Note: ssl_ca_cert is not in the schema, so we can't set it

	if err := client.SetAttrs(d, attrs); err != nil {
		return diag.FromErr(err)
	}

	servers := make([]map[string]interface{}, len(appResp.Servers))
	for i, server := range appResp.Servers {
		servers[i] = map[string]interface{}{
			"origin_host":     server.OriginHost,
			"orig_tls":        server.OrigTLS,
			"origin_port":     server.OriginPort,
			"origin_protocol": server.OriginProtocol,
		}
	}

	err = d.Set("servers", servers)
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

	// Convert advanced settings to JSON format
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
	advSettingsMap["health_check_type"] = mapHealthCheckTypeToDescriptive(appResp.AdvancedSettings.HealthCheckType)
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
	advSettingsMap["service_principle_name"] = appResp.AdvancedSettings.ServicePrincipleName
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

	// Handle custom headers - now just strings
	fmt.Printf("DEBUG: CustomHeaders from API response: %+v\n", appResp.AdvancedSettings.CustomHeaders)
	fmt.Printf("DEBUG: CustomHeaders length: %d\n", len(appResp.AdvancedSettings.CustomHeaders))
	if len(appResp.AdvancedSettings.CustomHeaders) > 0 {
		advSettingsMap["custom_headers"] = appResp.AdvancedSettings.CustomHeaders
		fmt.Printf("DEBUG: Added custom_headers to advSettingsMap\n")
	} else {
		fmt.Printf("DEBUG: No custom_headers found in API response\n")
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

	// Create Application struct from response to call methods
	app := client.Application{}
	app.FromResponse(&appResp)

	appAgents, err := app.GetAppAgents(eaaclient)
	if err == nil {
		err = d.Set("agents", appAgents)
		if err != nil {
			return diag.FromErr(err) // Return the error wrapped in a diag.Diagnostic
		}
	}
	if appResp.AuthEnabled == "true" {
		appAuthData, err := app.CreateAppAuthenticationStruct(eaaclient)
		if err == nil {
			err = d.Set("app_authentication", appAuthData)
			if err != nil {
				return diag.FromErr(err) // Return the error wrapped in a diag.Diagnostic
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
	} else {
		appSvcData, err := aclSrv.CreateAppServiceStruct(eaaclient)
		if err == nil && appSvcData != nil {
			err = d.Set("service", appSvcData)
			if err != nil {
				return diag.FromErr(err) // Return the error wrapped in a diag.Diagnostic
			}
		}
	}

	// Set SAML settings in state as JSON string
	// Always set saml_settings to ensure it appears in state (empty array if no settings)
	var samlSettings string

	if len(appResp.SAMLSettings) > 0 {
		// Use MarshalIndent to create beautifully formatted JSON for the state file
		samlSettingsBytes, err := json.MarshalIndent(appResp.SAMLSettings, "", "  ")
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to marshal SAML settings to JSON: %w", err))
		}
		samlSettings = string(samlSettingsBytes)
	} else {
		samlSettings = "[]"
	}
	
	// Always set saml_settings (empty array if no settings)
	err = d.Set("saml_settings", samlSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set WS-Federation settings in state
	if len(appResp.WSFEDSettings) > 0 {
		wsfedSettings := make([]map[string]interface{}, len(appResp.WSFEDSettings))
		for i, wsfedConfig := range appResp.WSFEDSettings {
			wsfedSettings[i] = map[string]interface{}{
				"sp": map[string]interface{}{
					"entity_id":  wsfedConfig.SP.EntityID,
					"slo_url":    wsfedConfig.SP.SLOURL,
					"dst_url":    wsfedConfig.SP.DSTURL,
					"resp_bind":  wsfedConfig.SP.RespBind,
					"token_life": wsfedConfig.SP.TokenLife,
					"encr_algo":  wsfedConfig.SP.EncrAlgo,
				},
				"idp": map[string]interface{}{
					"entity_id":   wsfedConfig.IDP.EntityID,
					"sign_algo":   wsfedConfig.IDP.SignAlgo,
					"sign_cert":   wsfedConfig.IDP.SignCert,
					"sign_key":    wsfedConfig.IDP.SignKey,
					"self_signed": wsfedConfig.IDP.SelfSigned,
				},
				"subject": map[string]interface{}{
					"fmt":        wsfedConfig.Subject.Fmt,
					"custom_fmt": wsfedConfig.Subject.CustomFmt,
					"src":        wsfedConfig.Subject.Src,
					"val":        wsfedConfig.Subject.Val,
					"rule":       wsfedConfig.Subject.Rule,
				},
				"attrmap": func() []map[string]interface{} {
					attrMaps := make([]map[string]interface{}, len(wsfedConfig.Attrmap))
					for j, attrMap := range wsfedConfig.Attrmap {
						attrMaps[j] = map[string]interface{}{
							"name":       attrMap.Name,
							"fmt":        attrMap.Fmt,
							"custom_fmt": attrMap.CustomFmt,
							"val":        attrMap.Val,
							"src":        attrMap.Src,
							"rule":       attrMap.Rule,
						}
					}
					return attrMaps
				}(),
			}
		}
		// Format wsfed_settings as JSON string for better readability
		var wsfedSettingsJSON string
		if len(wsfedSettings) > 0 {
			wsfedSettingsBytes, err := json.MarshalIndent(wsfedSettings, "", "  ")
			if err != nil {
				return diag.FromErr(fmt.Errorf("failed to marshal WS-Federation settings to JSON: %w", err))
			}
			wsfedSettingsJSON = string(wsfedSettingsBytes)
		} else {
			wsfedSettingsJSON = "[]"
		}
		err = d.Set("wsfed_settings", wsfedSettingsJSON)
		if err != nil {
			return diag.FromErr(err)
		}
	} else {
		// Always set wsfed_settings (empty array if no settings)
		err = d.Set("wsfed_settings", "[]")
		if err != nil {
			return diag.FromErr(err)
		}
	}

	// Format oidc_settings as JSON string for better readability
	var oidcSettingsJSON string
	if appResp.OIDCSettings != nil {
		// Create OIDC config structure for JSON marshalling
		oidcConfig := &client.OIDCConfig{
			OIDCClients: appResp.OIDCClients,
		}
		
		// Add endpoint fields if they exist
		if appResp.OIDCSettings.AuthorizationEndpoint != "" ||
		   appResp.OIDCSettings.TokenEndpoint != "" ||
		   appResp.OIDCSettings.UserinfoEndpoint != "" ||
		   appResp.OIDCSettings.JWKSURI != "" ||
		   appResp.OIDCSettings.DiscoveryURL != "" ||
		   appResp.OIDCSettings.CertsURI != "" ||
		   appResp.OIDCSettings.CheckSessionIframe != "" ||
		   appResp.OIDCSettings.EndSessionEndpoint != "" ||
		   appResp.OIDCSettings.OpenIDMetadata != "" {
			
			// Create a map with all OIDC settings
			oidcSettingsMap := map[string]interface{}{
				"authorization_endpoint": appResp.OIDCSettings.AuthorizationEndpoint,
				"certs_uri":              appResp.OIDCSettings.CertsURI,
				"check_session_iframe":   appResp.OIDCSettings.CheckSessionIframe,
				"discovery_url":          appResp.OIDCSettings.DiscoveryURL,
				"end_session_endpoint":   appResp.OIDCSettings.EndSessionEndpoint,
				"jwks_uri":               appResp.OIDCSettings.JWKSURI,
				"openid_metadata":        appResp.OIDCSettings.OpenIDMetadata,
				"token_endpoint":         appResp.OIDCSettings.TokenEndpoint,
				"userinfo_endpoint":      appResp.OIDCSettings.UserinfoEndpoint,
				"oidc_clients":           oidcConfig.OIDCClients,
			}
			
			oidcSettingsBytes, err := json.MarshalIndent(oidcSettingsMap, "", "  ")
			if err != nil {
				return diag.FromErr(fmt.Errorf("failed to marshal OIDC settings to JSON: %w", err))
			}
			oidcSettingsJSON = string(oidcSettingsBytes)
		} else {
			// Only OIDC clients, no endpoints
			oidcSettingsBytes, err := json.MarshalIndent(oidcConfig, "", "  ")
			if err != nil {
				return diag.FromErr(fmt.Errorf("failed to marshal OIDC settings to JSON: %w", err))
			}
			oidcSettingsJSON = string(oidcSettingsBytes)
		}
	} else {
		oidcSettingsJSON = "{}"
	}
	
	err = d.Set("oidc_settings", oidcSettingsJSON)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// resourceEaaApplicationUpdate function updates an existing EAA application.
// fetches the application, updates it based on the changed attributes, and deploys the application.
// then calls the read function to ensure the updated data is correctly populated in the schema.

func resourceEaaApplicationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Set the resource ID
	id := d.Id()
	eaaclient := m.(*client.EaaClient)
	var appResp client.Application

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := client.FormatErrorResponse(getResp)
		getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
		return diag.FromErr(getAppErrMsg)
	}

	// Store the update request for later use after IDP assignment
	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = appResp
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	currAgents, err := appResp.GetAppAgents(eaaclient)
	if err == nil {
		if agentsRaw, ok := d.GetOk("agents"); ok {
			agentList := agentsRaw.([]interface{})
			var desiredAgents []string
			for _, agent := range agentList {
				if str, ok := agent.(string); ok {
					desiredAgents = append(desiredAgents, str)
				}
			}

			agentsToAssign := client.DifferenceIgnoreCase(desiredAgents, currAgents)
			agentsToUnassign := client.DifferenceIgnoreCase(currAgents, desiredAgents)

			if len(agentsToAssign) > 0 {
				var agents client.AssignAgents
				agents.AppId = id
				agents.AgentNames = append(agents.AgentNames, agentsToAssign...)
				err := agents.AssignAgents(ctx, eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
			}
			if len(agentsToUnassign) > 0 {
				var agents client.AssignAgents
				agents.AppId = id
				agents.AgentNames = append(agents.AgentNames, agentsToUnassign...)

				err := agents.UnAssignAgents(ctx, eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}
	if d.HasChange("app_authentication") {
		auth_enabled := "false"

		if aE, ok := d.GetOk("auth_enabled"); ok {
			auth_enabled = aE.(string)
		}

		if auth_enabled == "true" {
			if appAuth, ok := d.GetOk("app_authentication"); ok {
				app_uuid_url := id
				appIDPMembership, err := appResp.GetAppIdpMembership(eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
				if appIDPMembership != nil {
					appIdp := client.AppIdp{
						App: app_uuid_url,
						IDP: appIDPMembership.UUIDURL,
					}
					err = appIdp.UnAssignIDP(eaaclient)
					if err != nil {
						eaaclient.Logger.Error("idp unassign error err ", err)
						return diag.FromErr(err)
					}
				}
				appAuthList := appAuth.([]interface{})
				if appAuthList == nil {
					return diag.FromErr(ErrInvalidData)
				}
				if len(appAuthList) > 0 {
					appAuthenticationMap := appAuthList[0].(map[string]interface{})
					if appAuthenticationMap == nil {
						eaaclient.Logger.Error("invalid authentication data")
						return diag.FromErr(ErrInvalidData)
					}

					// Check if app_idp key is present
					if app_idp_name, ok := appAuthenticationMap["app_idp"].(string); ok {
						idpData, err := client.GetIdpWithName(ctx, eaaclient, app_idp_name)
						if err != nil || idpData == nil {
							eaaclient.Logger.Error("get idp with name error, err ", err)
							return diag.FromErr(err)
						}

						eaaclient.Logger.Info("=== DEBUG: Starting IDP assignment in UPDATE flow ===")
						eaaclient.Logger.Info("DEBUG: Assigning IDP to application in UPDATE")
						eaaclient.Logger.Info("DEBUG: app_uuid_url = ", app_uuid_url)
						eaaclient.Logger.Info("DEBUG: idpData.UUIDURL = ", idpData.UUIDURL)
						
						appIdp := client.AppIdp{
							App: app_uuid_url,
							IDP: idpData.UUIDURL,
						}
						err = appIdp.AssignIDP(eaaclient)
						if err != nil {
							eaaclient.Logger.Error("DEBUG: IDP assign error in UPDATE: ", err)
							return diag.FromErr(err)
						}
						eaaclient.Logger.Info("DEBUG: IDP assigned successfully in UPDATE, app.Name = ", appResp.Name, "idp = ", app_idp_name)

						// check if app_directories are present
						if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
							eaaclient.Logger.Info("DEBUG: Starting directory assignment in UPDATE...")
							err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
							if err != nil {
								eaaclient.Logger.Error("DEBUG: Directory assignment error in UPDATE: ", err)
								return diag.FromErr(err)
							}
							eaaclient.Logger.Info("DEBUG: Directory assignment completed successfully in UPDATE")
						} else {
							eaaclient.Logger.Info("DEBUG: No app_directories found in UPDATE, skipping directory assignment")
						}
						
						eaaclient.Logger.Info("=== DEBUG: IDP assignment complete in UPDATE flow ===")
					}
				}
			}
		}
	}

	// Check if the "service" attribute is present and has changed
	if d.HasChange("service") {
		// Get the service attribute as a list (since it is defined as a list in the schema)
		services := d.Get("service").([]interface{})

		if len(services) > 0 {
			app_uuid_url := appResp.UUIDURL
			appSrv, err := client.GetACLService(eaaclient, app_uuid_url)
			if err != nil {
				return diag.FromErr(err)
			}

			aclSrv, err := client.ExtractACLService(ctx, d, eaaclient)
			if err != nil {
				return diag.FromErr(err)
			}

			if appSrv.Status != aclSrv.Status {
				appSrv.Status = aclSrv.Status
				err := appSrv.EnableService(eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
			}
			if d.HasChange("service.0.access_rule") {
				// Fetch existing rules
				existingACLResponse, err := client.GetAccessControlRules(eaaclient, appSrv.UUIDURL)
				if err != nil {
					return diag.FromErr(err)
				}
				existingRulesMap := make(map[string]client.AccessRule)
				for _, rule := range existingACLResponse.ACLRules {
					existingRulesMap[rule.Name] = rule
				}

				// Convert new rules into a map for easy comparison
				newRulesMap := make(map[string]client.AccessRule)
				for _, rule := range aclSrv.ACLRules {
					newRulesMap[rule.Name] = rule
				}

				// Handle deletions
				for name, existingRule := range existingRulesMap {
					if _, exists := newRulesMap[name]; !exists {
						if err := existingRule.DeleteAccessRule(ctx, eaaclient, appSrv.UUIDURL); err != nil {
							return diag.FromErr(err)
						}
					}
				}

				// Handle creations and modifications
				for name, newRule := range newRulesMap {
					if existingRule, exists := existingRulesMap[name]; exists {
						if !existingRule.IsEqual(newRule) {
							newRule.UUID_URL = existingRule.UUID_URL
							if err := newRule.ModifyAccessRule(ctx, eaaclient, appSrv.UUIDURL); err != nil {
								return diag.FromErr(err)
							}
						}
					} else {
						// Create new rule
						if err := newRule.CreateAccessRule(ctx, eaaclient, appSrv.UUIDURL); err != nil {
							return diag.FromErr(err)
						}
					}
				}
			}
		}
	}
	
	// Now perform the PUT call to update advanced settings AFTER IDP assignment is complete
	eaaclient.Logger.Info("=== DEBUG: Performing PUT call after IDP assignment in UPDATE flow ===")
	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
	if err != nil {
		eaaclient.Logger.Error("DEBUG: PUT call failed after IDP assignment in UPDATE: ", err)
		return diag.FromErr(err)
	}
	eaaclient.Logger.Info("=== DEBUG: PUT call completed successfully in UPDATE flow ===")

	// Add delay before deploy in UPDATE flow to ensure all operations are complete
	eaaclient.Logger.Info("waiting before deploy in UPDATE flow...")
	//time.Sleep(10 * time.Second)

	err = appUpdateReq.DeployApplication(eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceEaaApplicationRead(ctx, d, m)
}

// resourceEaaApplicationDelete function deletes an existing EAA application.
// sends a delete request to the EAA client to remove the application.
func resourceEaaApplicationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Read the resource ID from d
	id := d.Id()
	eaaclient := m.(*client.EaaClient)
	var appResp client.ApplicationDataModel

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)
	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := client.FormatErrorResponse(getResp)
		getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
		return diag.FromErr(getAppErrMsg)
	}
	err = appResp.DeleteApplication(eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID to mark it as deleted
	d.SetId("")

	return nil
}

// mapHealthCheckTypeToDescriptive converts numeric health check type values to descriptive values
func mapHealthCheckTypeToDescriptive(numericValue string) string {
	switch numericValue {
	case "0":
		return "Default"
	case "1":
		return "HTTP"
	case "2":
		return "HTTPS"
	case "3":
		return "TLS"
	case "4":
		return "SSLv3"
	case "5":
		return "TCP"
	case "6":
		return "None"
	default:
		return numericValue // fallback to original value
	}
}

// mapHealthCheckTypeToNumeric converts descriptive health check type values to numeric values
func mapHealthCheckTypeToNumeric(descriptiveValue string) string {
	switch descriptiveValue {
	case "Default":
		return "0"
	case "HTTP":
		return "1"
	case "HTTPS":
		return "2"
	case "TLS":
		return "3"
	case "SSLv3":
		return "4"
	case "TCP":
		return "5"
	case "None":
		return "6"
	default:
		return descriptiveValue // fallback to original value (assumes it's already numeric)
	}
}

// convertStringToInt converts string to int, returns 0 if conversion fails
func convertStringToInt(value string) int {
	if value == "" {
		return 0
	}
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	return 0
}

// convertStringPointerToString converts *string to string, returns null string for nil
func convertStringPointerToString(value *string) string {
	if value == nil {
		return "null"
	}
	return *value
}

// ValidationRule defines a validation rule for a field
type ValidationRule struct {
	FieldName string
	Type      string
	Types     []string // Support multiple types
	Enum      []string
	Pattern   string
	Required  bool
	Nullable  bool
	Min       int // Minimum value for numeric fields
	Max       int // Maximum value for numeric fields
}

// validateAdvancedSettings validates the advanced_settings JSON string using a configuration-driven approach
func validateAdvancedSettings(v interface{}, k string) (ws []string, errors []error) {
	value, ok := v.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected string, got %T", v))
		return
	}

	// If empty, it's valid (will use defaults)
	if value == "" || value == "{}" {
		return
	}

	// Parse the JSON to validate structure
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(value), &settings); err != nil {
		errors = append(errors, fmt.Errorf("invalid JSON format: %v", err))
		return
	}

	// Define validation rules in a single place - easy to maintain and extend
	validationRules := []ValidationRule{
		{FieldName: "acceleration", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "allow_cors", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "anonymous_server_conn_limit", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "anonymous_server_request_limit", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "app_auth", Type: "string", Required: true},
		{FieldName: "app_auth_domain", Type: "string", Required: false, Nullable: true},
		{FieldName: "app_client_cert_auth", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "app_cookie_domain", Type: "string", Required: false, Nullable: true},
		{FieldName: "app_location", Type: "string", Required: false, Nullable: true},
		{FieldName: "app_server_read_timeout", Types: []string{"string", "integer"}, Pattern: "^[0-9]+$"},
		{FieldName: "authenticated_server_conn_limit", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "authenticated_server_request_limit", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "client_cert_auth", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "client_cert_user_param", Type: "string"},
		{FieldName: "cookie_domain", Type: "string"},
		{FieldName: "cors_header_list", Type: "string"},
		{FieldName: "cors_max_age", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "cors_method_list", Type: "string"},
		{FieldName: "cors_origin_list", Type: "string"},
		{FieldName: "cors_support_credential", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "disable_user_agent_check", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "domain_exception_list", Type: "string"},
		{FieldName: "edge_authentication_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "edge_cookie_key", Type: "string"},
		{FieldName: "edge_transport_manual_mode", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "edge_transport_property_id", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "enable_client_side_xhr_rewrite", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "external_cookie_domain", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "force_ip_route", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "force_mfa", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "form_post_url", Type: "string"},
		{FieldName: "forward_ticket_granting_ticket", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "g2o_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "g2o_key", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "g2o_nonce", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "health_check_fall", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "health_check_http_host_header", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "health_check_http_url", Type: "string"},
		{FieldName: "health_check_http_version", Type: "string"},
		{FieldName: "health_check_interval", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "health_check_rise", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "health_check_timeout", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "health_check_type", Type: "string", Pattern: "^(Default|HTTP|HTTPS|SSL|TCP|None|[0-9]+)$"},
		{FieldName: "hidden_app", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "host_key", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "hsts_age", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "http_only_cookie", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "https_sslv3", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "idle_close_time_seconds", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "idle_conn_ceil", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "idle_conn_floor", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "idle_conn_step", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "idp_idle_expiry", Types: []string{"string", "null"}, Pattern: "^[0-9]+$", Nullable: true},
		{FieldName: "idp_max_expiry", Types: []string{"string", "null"}, Pattern: "^[0-9]+$", Nullable: true},
		{FieldName: "ignore_bypass_mfa", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "ignore_cname_resolution", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "inject_ajax_javascript", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "intercept_url", Type: "string"},
		{FieldName: "internal_host_port", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "ip_access_allow", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "is_brotli_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "is_ssl_verification_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "jwt_audience", Type: "string"},
		{FieldName: "jwt_grace_period", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "jwt_issuers", Type: "string"},
		{FieldName: "jwt_return_option", Type: "string"},
		{FieldName: "jwt_return_url", Type: "string"},
		{FieldName: "jwt_username", Type: "string"},
		{FieldName: "keepalive_connection_pool", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "keepalive_enable", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "keepalive_timeout", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "kerberos_negotiate_once", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "keyed_keepalive_enable", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "keytab", Type: "string"},
		{FieldName: "load_balancing_metric", Type: "string"},
		{FieldName: "logging_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "login_timeout", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "login_url", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "logout_url", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "mdc_enable", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "mfa", Type: "string"},
		{FieldName: "offload_onpremise_traffic", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "onramp", Type: "string"},
		{FieldName: "pass_phrase", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "preauth_consent", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "preauth_enforce_url", Type: "string"},
		{FieldName: "private_key", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "proxy_buffer_size_kb", Types: []string{"string", "null"}, Pattern: "^[0-9]+$", Nullable: true},
		{FieldName: "proxy_disable_clipboard", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "rate_limit", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "rdp_initial_program", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "rdp_keyboard_lang", Type: "string"},
		{FieldName: "rdp_legacy_mode", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "rdp_tls1", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "rdp_window_color_depth", Type: "string"},
		{FieldName: "rdp_window_height", Type: "string"},
		{FieldName: "rdp_window_width", Type: "string"},
		{FieldName: "refresh_sticky_cookie", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "remote_spark_audio", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "remote_spark_disk", Type: "string"},
		{FieldName: "remote_spark_mapClipboard", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "remote_spark_mapDisk", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "remote_spark_mapPrinter", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "remote_spark_printer", Type: "string"},
		{FieldName: "remote_spark_recording", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "request_body_rewrite", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "saas_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "segmentation_policy_enable", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "sentry_redirect_401", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "sentry_restore_form_post", Type: "string", Enum: []string{"on", "off"}},
		{FieldName: "server_cert_validate", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "server_request_burst", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "service_principle_name", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "session_sticky", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "session_sticky_cookie_maxage", Type: "string", Pattern: "^[0-9]+$"},
		{FieldName: "session_sticky_server_cookie", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "single_host_content_rw", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "single_host_cookie_domain", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "single_host_enable", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "single_host_fqdn", Type: "string"},
		{FieldName: "single_host_path", Type: "string"},
		{FieldName: "sla_object_url", Type: "string"},
		{FieldName: "spdy_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "ssh_audit_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "sso", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "sticky_agent", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "user_name", Types: []string{"string", "null"}, Nullable: true},
		{FieldName: "wapp_auth", Type: "string"},
		{FieldName: "websocket_enabled", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "wildcard_internal_hostname", Type: "string", Enum: []string{"true", "false"}},
		{FieldName: "x_wapp_pool_enabled", Type: "string", Enum: []string{"true", "false", "inherit"}},
		{FieldName: "x_wapp_pool_size", Types: []string{"integer"}, Min: 1, Max: 50},
		{FieldName: "x_wapp_pool_timeout", Types: []string{"integer"}, Min: 60, Max: 3600},
		{FieldName: "x_wapp_read_timeout", Types: []string{"string", "integer"}, Min: 1, Max: 3600},
	}

	// Apply validation rules
	for _, rule := range validationRules {
		if fieldValue, exists := settings[rule.FieldName]; exists {
			if err := validateField(fieldValue, rule); err != nil {
				errors = append(errors, err)
			}
		}
	}

	return
}

// validateField validates a single field against its rule
func validateField(value interface{}, rule ValidationRule) error {
	// Handle null values for nullable fields
	if value == nil {
		if rule.Nullable {
			return nil // null is valid for nullable fields
		}
		return fmt.Errorf("%s cannot be null", rule.FieldName)
	}

	// Check if multiple types are supported
	if len(rule.Types) > 0 {
		validType := false
		for _, allowedType := range rule.Types {
			switch allowedType {
			case "string":
				if _, ok := value.(string); ok {
					validType = true
					break
				}
			case "integer":
				switch value.(type) {
				case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
					validType = true
					break
				case float32, float64:
					// JSON numbers become float64, so accept them and convert to int
					validType = true
					break
				}
			}
		}
		if !validType {
			return fmt.Errorf("%s must be one of types %v, got %T (value: %v)", rule.FieldName, rule.Types, value, value)
		}
	} else {
		// Fall back to single type validation
		switch rule.Type {
		case "string":
			if strVal, ok := value.(string); ok {
				// Check enum values if specified
				if len(rule.Enum) > 0 {
					valid := false
					for _, validValue := range rule.Enum {
						if strVal == validValue {
							valid = true
							break
						}
					}
					if !valid {
						return fmt.Errorf("%s must be one of %v, got '%s'", rule.FieldName, rule.Enum, strVal)
					}
				}

				// Check pattern if specified
				if rule.Pattern != "" {
					matched, err := regexp.MatchString(rule.Pattern, strVal)
					if err != nil {
						return fmt.Errorf("validation error for %s: %v", rule.FieldName, err)
					}
					if !matched {
						return fmt.Errorf("%s must match pattern '%s', got '%s'", rule.FieldName, rule.Pattern, strVal)
					}
				}
			} else {
				// Strict validation: reject any non-string values
				return fmt.Errorf("%s must be a string, got %T (value: %v). No automatic conversion allowed.", rule.FieldName, value, value)
			}
		}
	}

	// Apply pattern validation for all types if specified
	if rule.Pattern != "" {
		var strVal string
		switch v := value.(type) {
		case string:
			strVal = v
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			strVal = fmt.Sprintf("%v", v)
		default:
			return fmt.Errorf("%s cannot apply pattern validation to type %T", rule.FieldName, value)
		}

		matched, err := regexp.MatchString(rule.Pattern, strVal)
		if err != nil {
			return fmt.Errorf("validation error for %s: %v", rule.FieldName, err)
		}
		if !matched {
			return fmt.Errorf("%s must match pattern '%s', got '%s'", rule.FieldName, rule.Pattern, strVal)
		}
	}

	// Apply range validation for numeric fields if specified
	if rule.Min > 0 || rule.Max > 0 {
		var numVal int64
		switch v := value.(type) {
		case string:
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
				numVal = parsed
			} else {
				return fmt.Errorf("%s must be a valid integer for range validation, got '%s'", rule.FieldName, v)
			}
		case int:
			numVal = int64(v)
		case int8:
			numVal = int64(v)
		case int16:
			numVal = int64(v)
		case int32:
			numVal = int64(v)
		case int64:
			numVal = v
		case uint:
			numVal = int64(v)
		case uint8:
			numVal = int64(v)
		case uint16:
			numVal = int64(v)
		case uint32:
			numVal = int64(v)
		case uint64:
			numVal = int64(v)
		case float32:
			numVal = int64(v)
		case float64:
			numVal = int64(v)
		default:
			return fmt.Errorf("%s cannot apply range validation to type %T", rule.FieldName, value)
		}

		if rule.Min > 0 && numVal < int64(rule.Min) {
			return fmt.Errorf("%s must be at least %d, got %d", rule.FieldName, rule.Min, numVal)
		}
		if rule.Max > 0 && numVal > int64(rule.Max) {
			return fmt.Errorf("%s must be at most %d, got %d", rule.FieldName, rule.Max, numVal)
		}
	}

	return nil
}
