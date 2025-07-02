package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrConnectorPoolCreate = errors.New("connector pool creation failed")
	ErrConnectorPoolGet    = errors.New("connector pool get failed")
	ErrConnectorPoolUpdate = errors.New("connector pool update failed")
	ErrConnectorPoolDelete = errors.New("connector pool delete failed")
)

// ConnectorPool represents a connector pool
type ConnectorPool struct {
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	PackageType             int      `json:"package_type"`
	InfraType               int      `json:"infra_type"`
	OperatingMode           int      `json:"operating_mode"`
	UUIDURL                 string   `json:"uuid_url,omitempty"`
	CIDRs                   []string `json:"cidrs,omitempty"`
	ApplicationAccessGroup  []string `json:"application_access_group,omitempty"`
	ApplicationAccessGroups []string `json:"application_access_groups,omitempty"`
	Applications            []string `json:"applications,omitempty"`
	Connectors              []string `json:"connectors,omitempty"`
	CreatedAt               string   `json:"created_at,omitempty"`
	Directories             []string `json:"directories,omitempty"`
	DNSList                 []string `json:"dns_list,omitempty"`
	DNSOverride             bool     `json:"dns_override,omitempty"`
	EDNS                    []string `json:"edns,omitempty"`
	IsEnabled               bool     `json:"is_enabled,omitempty"`
	Localization            string   `json:"localization,omitempty"`
	LocationFreetext        *string  `json:"location_freetext,omitempty"`
	ModifiedAt              string   `json:"modified_at,omitempty"`
	ResourceURI             struct {
		Href string `json:"href,omitempty"`
	} `json:"resource_uri,omitempty"`
	SendAlerts bool `json:"send_alerts,omitempty"`
}

// CreateConnectorPoolRequest represents the request to create a connector pool
type CreateConnectorPoolRequest struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	PackageType   int    `json:"package_type"`
	InfraType     *int   `json:"infra_type,omitempty"`
	OperatingMode *int   `json:"operating_mode,omitempty"`
}

// CreateConnectorPoolResponse represents the response from creating a connector pool
type CreateConnectorPoolResponse struct {
	CIDRs         []string `json:"cidrs"`
	UUIDURL       string   `json:"uuid_url"`
	OperatingMode *int     `json:"operating_mode,omitempty"`
}

// CreateConnectorPoolRequestFromSchema creates a CreateConnectorPoolRequest from the schema
func (ccpr *CreateConnectorPoolRequest) CreateConnectorPoolRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	ccpr.Name = d.Get("name").(string)
	ccpr.Description = d.Get("description").(string)
	ccpr.PackageType = d.Get("package_type").(int)
	
	// Explicitly set pointers to nil to ensure they are not sent
	ccpr.InfraType = nil
	ccpr.OperatingMode = nil
	
	// Only set infra_type if it's present in the schema
	if infraType, ok := d.GetOk("infra_type"); ok {
		value := infraType.(int)
		ccpr.InfraType = &value
		ec.Logger.Info("Setting infra_type to:", value)
	} else {
		ec.Logger.Info("infra_type not found in schema, leaving as nil")
	}
	
	// Only set operating_mode if it's present in the schema
	if operatingMode, ok := d.GetOk("operating_mode"); ok {
		value := operatingMode.(int)
		ccpr.OperatingMode = &value
		ec.Logger.Info("Setting operating_mode to:", value)
	} else {
		ec.Logger.Info("operating_mode not found in schema, leaving as nil")
	}
	
	// Debug: log the final struct values
	ec.Logger.Info("Final struct - InfraType:", ccpr.InfraType, "OperatingMode:", ccpr.OperatingMode)
	
	return nil
}

// CreateConnectorPool creates a new connector pool
func (ccpr *CreateConnectorPoolRequest) CreateConnectorPool(ctx context.Context, ec *EaaClient, contractID, gid string) (*CreateConnectorPoolResponse, error) {
	apiURL := fmt.Sprintf("%s://%s/%s?contractId=%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, contractID)

	ec.Logger.Info("Creating connector pool with URL:", apiURL)
	
	// Log the actual JSON that will be sent
	jsonData, _ := json.Marshal(ccpr)
	ec.Logger.Info("Request JSON body:", string(jsonData))
	ec.Logger.Info("Request body struct:", ccpr)

	var response CreateConnectorPoolResponse
	resp, err := ec.SendAPIRequest(apiURL, "POST", ccpr, &response, false)
	if err != nil {
		ec.Logger.Error("API request failed:", err)
		return nil, err
	}

	ec.Logger.Info("Response status:", resp.StatusCode)
	ec.Logger.Info("Response body:", response)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		createErrMsg := fmt.Errorf("%w: %s", ErrConnectorPoolCreate, desc)
		ec.Logger.Error("Create failed with status:", resp.StatusCode, "error:", desc)
		return nil, createErrMsg
	}

	return &response, nil
}

// GetConnectorPool retrieves a connector pool by UUID
func GetConnectorPool(ctx context.Context, ec *EaaClient, uuid, contractID, gid string) (*ConnectorPool, error) {
	apiURL := fmt.Sprintf("%s://%s/%s/%s?contractId=%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, uuid, contractID)

	ec.Logger.Info("Getting connector pool with URL:", apiURL)

	var connectorPool ConnectorPool
	resp, err := ec.SendAPIRequest(apiURL, "GET", nil, &connectorPool, false)
	if err != nil {
		ec.Logger.Error("Get API request failed:", err)
		return nil, err
	}

	ec.Logger.Info("Get response status:", resp.StatusCode)
	ec.Logger.Info("Get response body:", connectorPool)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		getErrMsg := fmt.Errorf("%w: %s", ErrConnectorPoolGet, desc)
		ec.Logger.Error("Get failed with status:", resp.StatusCode, "error:", desc)
		return nil, getErrMsg
	}

	return &connectorPool, nil
}

// UpdateConnectorPool updates an existing connector pool
func (cp *ConnectorPool) UpdateConnectorPool(ctx context.Context, ec *EaaClient, contractID, gid string) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s?contractId=%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, cp.UUIDURL, contractID)

	resp, err := ec.SendAPIRequest(apiURL, "PUT", cp, nil, false)
	if err != nil {
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		updateErrMsg := fmt.Errorf("%w: %s", ErrConnectorPoolUpdate, desc)
		return updateErrMsg
	}

	return nil
}

// DeleteConnectorPool deletes a connector pool
func DeleteConnectorPool(ctx context.Context, ec *EaaClient, uuid, contractID, gid string) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s?contractId=%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, uuid, contractID)

	resp, err := ec.SendAPIRequest(apiURL, "DELETE", nil, nil, false)
	if err != nil {
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		deleteErrMsg := fmt.Errorf("%w: %s", ErrConnectorPoolDelete, desc)
		return deleteErrMsg
	}

	return nil
}
