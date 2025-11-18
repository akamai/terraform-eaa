package eaaprovider

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// assignAgentsToApplication assigns agents to an application during creation
func assignAgentsToApplication(ctx context.Context, d *schema.ResourceData, appUUIDURL string, eaaclient *client.EaaClient) diag.Diagnostics {
	if agentsRaw, ok := d.GetOk("agents"); ok {
		agentsList := agentsRaw.([]interface{})
		var agents client.AssignAgents
		agents.AppId = appUUIDURL
		for _, v := range agentsList {
			if name, ok := v.(string); ok {
				agents.AgentNames = append(agents.AgentNames, name)
			}
		}
		err := agents.AssignAgents(ctx, eaaclient)
		if err != nil {
			return diag.FromErr(err)
		}
		eaaclient.Logger.Debug("create Application: assigning agents succeeded.")
	}
	return nil
}

// assignIDPToApplication handles IDP assignment and directory assignment during creation
func assignIDPToApplication(ctx context.Context, d *schema.ResourceData, appUUIDURL string, app *client.Application, eaaclient *client.EaaClient) diag.Diagnostics {
	logger := eaaclient.Logger

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
				logger.Debug("app.Name: ", app.Name, "app_idp_name: ", app_idp_name, "idpData.UUIDURL: ", idpData.UUIDURL)

				logger.Debug("Assigning IDP to application")

				appIdp := client.AppIdp{
					App: appUUIDURL,
					IDP: idpData.UUIDURL,
				}
				err = appIdp.AssignIDP(eaaclient)
				if err != nil {
					logger.Error("IDP assign error: ", err)
					return diag.Errorf("assigning IDP to the app failed: %v", err)
				}
				logger.Debug("IDP assigned successfully, app.Name = ", app.Name, "idp = ", app_idp_name)

				// check if app_directories are present
				if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
					logger.Debug("Starting directory assignment...")
					err := idpData.AssignIdpDirectories(ctx, appDirs, appUUIDURL, eaaclient)
					if err != nil {
						logger.Error("Directory assignment error: ", err)
						return diag.FromErr(err)
					}
					logger.Debug("Directory assignment completed successfully")
				} else {
					logger.Debug("No app_directories found, skipping directory assignment")
				}
			}
		}
	}

	return nil
}

// verifyIDPAssignment verifies that IDP assignment is complete
func verifyIDPAssignment(ctx context.Context, appUUIDURL string, eaaclient *client.EaaClient) diag.Diagnostics {
	logger := eaaclient.Logger

	logger.Debug("Starting IDP assignment verification")
	logger.Debug("app_uuid_url", "value", appUUIDURL)
	logger.Debug("Waiting 30 seconds for IDP assignment to propagate...")

	// Verify the application has the correct authentication settings
	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, appUUIDURL)
	logger.Debug("Fetching application details", "url", apiURL)

	var appResp client.ApplicationResponse
	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		logger.Error("Failed to verify authentication settings", "error", err)
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		logger.Error("Failed to verify authentication settings - bad status code", "status_code", getResp.StatusCode)
		return diag.FromErr(client.ErrAuthSettingsVerificationFailed)
	}

	// Check if the application has authentication enabled
	if appResp.AuthEnabled != "true" {
		logger.Debug("Authentication not yet enabled, waiting additional 30 seconds...")

		// Check again after additional wait
		_, err = eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
		if err != nil {
			logger.Error("Failed to verify authentication settings after additional wait", "error", err)
			return diag.FromErr(err)
		}
		logger.Debug("After additional wait - appResp.AuthEnabled", "value", appResp.AuthEnabled)
	} else {
		logger.Debug("Authentication is properly enabled!")
	}

	logger.Debug("IDP assignment verification complete")
	return nil
}

// configureServiceForApplication configures service (ACL) for an application during creation
func configureServiceForApplication(ctx context.Context, d *schema.ResourceData, appUUIDURL string, eaaclient *client.EaaClient) diag.Diagnostics {
	_, ok := d.Get("service").([]interface{})
	if ok {
		aclSrv, err := client.ExtractACLService(ctx, d, eaaclient)
		if err != nil {
			return diag.FromErr(err)
		}
		appSrv, err := client.GetACLService(eaaclient, appUUIDURL)
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
	return nil
}
