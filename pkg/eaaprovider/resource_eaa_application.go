package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

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
		CreateContext: resourceEaaApplicationCreate,
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
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"is_ssl_verification_enabled": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "false",
						},
						"edge_authentication_enabled": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "false",
						},
						"ignore_cname_resolution": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "false",
						},
						"g2o_enabled": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "false",
						},
						"g2o_nonce": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"g2o_key": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"x_wapp_read_timeout": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"internal_hostname": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"internal_host_port": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"ip_access_allow": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"wildcard_internal_hostname": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"edge_cookie_key": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"sla_object_url": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
					},
				},
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

	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = app
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
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

					appIdp := client.AppIdp{
						App: app_uuid_url,
						IDP: idpData.UUIDURL,
					}
					err = appIdp.AssignIDP(eaaclient)
					if err != nil {
						logger.Error("idp assign error err ", err)
						return diag.FromErr(err)
					}
					logger.Info("idp assigned successfully, app.Name ", app.Name, "idp ", app_idp_name)

					// check if app_directories are present
					if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
						err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
						if err != nil {
							return diag.FromErr(err)
						}
					}
				}
			}
		}
	}
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

	err = app.DeployApplication(eaaclient)

	if err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID
	d.SetId(app_uuid_url)
	return resourceEaaApplicationRead(ctx, d, m)
}

// resourceEaaApplicationRead function reads an existing EAA application.
// fetches application details using and maps the response to the schema attributes.

func resourceEaaApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	id := d.Id()
	eaaclient := m.(*client.EaaClient)
	var appResp client.ApplicationDataModel

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
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

	aDomain := client.DomainInt(appResp.Domain)
	domainString, err := aDomain.String()
	if err != nil {
		eaaclient.Logger.Info("error converting domain")
	}
	attrs["domain"] = domainString

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

	if appResp.CName != nil {
		attrs["cname"] = *appResp.CName
	}

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

	advSettings := make([]map[string]interface{}, 1)

	advSettings[0] = map[string]interface{}{
		"g2o_enabled":                 appResp.AdvancedSettings.G2OEnabled,
		"g2o_nonce":                   appResp.AdvancedSettings.G2ONonce,
		"g2o_key":                     appResp.AdvancedSettings.G2OKey,
		"is_ssl_verification_enabled": appResp.AdvancedSettings.IsSSLVerificationEnabled,
		"ignore_cname_resolution":     appResp.AdvancedSettings.IgnoreCnameResolution,
		"edge_authentication_enabled": appResp.AdvancedSettings.EdgeAuthenticationEnabled,
		"edge_cookie_key":             appResp.AdvancedSettings.EdgeCookieKey,
		"sla_object_url":              appResp.AdvancedSettings.SlaObjectUrl,
	}

	if client.ClientAppTypeInt(appResp.AppType) == client.APP_TYPE_TUNNEL {
		advSettings[0]["x_wapp_read_timeout"] = appResp.AdvancedSettings.XWappReadTimeout
		advSettings[0]["internal_hostname"] = appResp.AdvancedSettings.InternalHostname
		advSettings[0]["internal_host_port"] = appResp.AdvancedSettings.InternalHostPort
		advSettings[0]["wildcard_internal_hostname"] = appResp.AdvancedSettings.WildcardInternalHostname
		advSettings[0]["ip_access_allow"] = appResp.AdvancedSettings.IPAccessAllow
	}

	err = d.Set("advanced_settings", advSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	appAgents, err := appResp.Application.GetAppAgents(eaaclient)
	if err == nil {
		err = d.Set("agents", appAgents)
		if err != nil {
			return diag.FromErr(err) // Return the error wrapped in a diag.Diagnostic
		}
	}
	if appResp.AuthEnabled == "true" {
		appAuthData, err := appResp.Application.CreateAppAuthenticationStruct(eaaclient)
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
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := client.FormatErrorResponse(getResp)
		getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
		return diag.FromErr(getAppErrMsg)
	}

	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = appResp
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
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

						appIdp := client.AppIdp{
							App: app_uuid_url,
							IDP: idpData.UUIDURL,
						}
						err = appIdp.AssignIDP(eaaclient)
						if err != nil {
							eaaclient.Logger.Error("idp assign error err ", err)
							return diag.FromErr(err)
						}

						// check if app_directories are present
						if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
							err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
							if err != nil {
								return diag.FromErr(err)
							}
						}
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

	err = appUpdateReq.Application.DeployApplication(eaaclient)
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

	// Send the delete application REST endpoint
	err := eaaclient.SendDeleteApplicationEndpoint(id)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID to mark it as deleted
	d.SetId("")

	return nil
}
