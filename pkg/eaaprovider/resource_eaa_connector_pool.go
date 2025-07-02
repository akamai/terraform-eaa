package eaaprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrGetConnectorPool    = errors.New("connector pool get failed")
	ErrInvalidConnPoolData = errors.New("invalid connector pool data in schema")
)

func resourceEaaConnectorPool() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaConnectorPoolCreate,
		ReadContext:   resourceEaaConnectorPoolRead,
		UpdateContext: resourceEaaConnectorPoolUpdate,
		DeleteContext: resourceEaaConnectorPoolDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the connector pool (mandatory)",
			},
			"package_type": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "Package type for the connector pool (mandatory)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Description of the connector pool",
			},
			"infra_type": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Infrastructure type for the connector pool (optional)",
			},
			"operating_mode": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Operating mode for the connector pool (optional)",
			},
			"connector_pool_create_api_response": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON response from connector pool create API call",
			},
			"connector_pool_get_api_response": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON response from connector pool GET API call",
			},
			"app_access_groups_api_response": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON response from app access groups API call",
			},
		},
	}
}

// resourceEaaConnectorPoolCreate function is responsible for creating a new EAA Connector Pool.
func resourceEaaConnectorPoolCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	createRequest := &client.CreateConnectorPoolRequest{}
	createRequest.Name = d.Get("name").(string)
	createRequest.Description = d.Get("description").(string)
	createRequest.PackageType = d.Get("package_type").(int)
	// Optional fields
	createRequest.InfraType = nil
	if v, ok := d.GetOk("infra_type"); ok {
		value := v.(int)
		createRequest.InfraType = &value
	}
	createRequest.OperatingMode = nil
	if v, ok := d.GetOk("operating_mode"); ok {
		value := v.(int)
		createRequest.OperatingMode = &value
	}

	contract_id := eaaclient.ContractID

	connPoolResp, err := createRequest.CreateConnectorPool(ctx, eaaclient, contract_id, "")
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(connPoolResp.UUIDURL)

	// Store the full create response as JSON for debugging
	createRespJson, _ := json.Marshal(connPoolResp)
	d.Set("connector_pool_create_api_response", string(createRespJson))
	eaaclient.Logger.Info("Set connector_pool_create_api_response:", string(createRespJson))

	// Call GET API after successful creation
	getResponse, err := callConnectorPoolGetAPI(eaaclient, connPoolResp.UUIDURL, contract_id)
	if err != nil {
		eaaclient.Logger.Error("Failed to call GET API after creation:", err)
		// Don't fail the creation if GET fails, just log the error
	} else {
		d.Set("connector_pool_get_api_response", getResponse)
		eaaclient.Logger.Info("Set connector_pool_get_api_response:", getResponse)
	}

	// Call app-access-groups API after successful creation
	appAccessGroupsResponse, err := callAppAccessGroupsAPI(eaaclient, connPoolResp.UUIDURL, contract_id)
	if err != nil {
		eaaclient.Logger.Error("Failed to call app-access-groups API after creation:", err)
		// Don't fail the creation if app-access-groups API fails, just log the error
	} else {
		d.Set("app_access_groups_api_response", appAccessGroupsResponse)
		eaaclient.Logger.Info("Set app_access_groups_api_response:", appAccessGroupsResponse)
	}

	return nil
}

// resourceEaaConnectorPoolRead function reads an existing EAA connector pool.
func resourceEaaConnectorPoolRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Persist the create response in state if present
	if v, ok := d.GetOk("connector_pool_create_api_response"); ok {
		d.Set("connector_pool_create_api_response", v)
	}
	return nil
}

// resourceEaaConnectorPoolUpdate updates an existing EAA connector pool.
func resourceEaaConnectorPoolUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	// Create update request with current values
	updateRequest := &client.CreateConnectorPoolRequest{}
	updateRequest.Name = d.Get("name").(string)
	updateRequest.Description = d.Get("description").(string)
	updateRequest.PackageType = d.Get("package_type").(int)
	
	// Optional fields
	updateRequest.InfraType = nil
	if v, ok := d.GetOk("infra_type"); ok {
		value := v.(int)
		updateRequest.InfraType = &value
	}
	updateRequest.OperatingMode = nil
	if v, ok := d.GetOk("operating_mode"); ok {
		value := v.(int)
		updateRequest.OperatingMode = &value
	}

	// Update the connector pool using PUT
	id := d.Id()
	contract_id := eaaclient.ContractID
	apiURL := fmt.Sprintf("%s://%s/%s/%s?contractId=%s", client.URL_SCHEME, eaaclient.Host, client.CONNECTOR_POOLS_URL, id, contract_id)
	
	logger.Info("Updating connector pool with URL:", apiURL)
	
	// Log the actual JSON that will be sent
	jsonData, _ := json.Marshal(updateRequest)
	logger.Info("Update request JSON body:", string(jsonData))

	resp, err := eaaclient.SendAPIRequest(apiURL, "PUT", updateRequest, nil, false)
	if err != nil {
		logger.Error("Update API request failed:", err)
		return diag.FromErr(err)
	}

	logger.Info("Update response status:", resp.StatusCode)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := client.FormatErrorResponse(resp)
		updateErrMsg := fmt.Errorf("connector pool update failed: %s", desc)
		logger.Error("Update failed with status:", resp.StatusCode, "error:", desc)
		return diag.FromErr(updateErrMsg)
	}

	return resourceEaaConnectorPoolRead(ctx, d, m)
}

// resourceEaaConnectorPoolDelete deletes an existing EAA connector pool.
func resourceEaaConnectorPoolDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	id := d.Id()
	contract_id := eaaclient.ContractID
	err = client.DeleteConnectorPool(ctx, eaaclient, id, contract_id, "")
	if err != nil {
		logger.Error("delete connector pool failed. err ", err)
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

// callConnectorPoolGetAPI calls the connector pool GET API using mgmt-pop endpoint and returns the response as string
func callConnectorPoolGetAPI(eaaclient *client.EaaClient, uuidURL, contractID string) (string, error) {
	url := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/connector-pools/%s?contractId=%s", 
		eaaclient.Host, uuidURL, contractID)
	
	eaaclient.Logger.Info("Calling GET API with URL:", url)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	eaaclient.Signer.SignRequest(req)
	
	resp, err := eaaclient.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	eaaclient.Logger.Info("GET API response status:", resp.StatusCode)
	eaaclient.Logger.Info("GET API response body:", string(body))
	
	return string(body), nil
}

// callConnectorPoolAPI calls the connector pool API and returns the response as string
func callConnectorPoolAPI(eaaclient *client.EaaClient, uuidURL, contractID string) (string, error) {
	url := fmt.Sprintf("https://%s/crux/v1/zt/connector-pools/%s?contractId=%s", 
		eaaclient.Host, uuidURL, contractID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	eaaclient.Signer.SignRequest(req)
	
	resp, err := eaaclient.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return string(body), nil
}

// callAppAccessGroupsAPI calls the app access groups API and returns the response as string
func callAppAccessGroupsAPI(eaaclient *client.EaaClient, uuidURL, contractID string) (string, error) {
	url := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/app-access-groups?connector_pool_uuid_url=%s&contractId=%s", 
		eaaclient.Host, uuidURL, contractID)
	
	eaaclient.Logger.Info("Calling app-access-groups API with URL:", url)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	eaaclient.Signer.SignRequest(req)
	
	resp, err := eaaclient.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	eaaclient.Logger.Info("App-access-groups API response status:", resp.StatusCode)
	eaaclient.Logger.Info("App-access-groups API response body:", string(body))
	
	return string(body), nil
}
