package eaaprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ============================================================================
// HELPER FUNCTIONS FOR DATA SOURCE OPERATIONS
// ============================================================================

// convertConnectorPoolToMap converts a ConnectorPool to a map for the schema with detailed connector information
func convertConnectorPoolToMap(pool *client.ConnectorPool, eaaclient *client.EaaClient) map[string]interface{} {

	// Build the pool data directly from the raw response instead of using client.ConvertConnectorPoolToMap
	poolData := map[string]interface{}{
		"name":        pool.Name,
		"description": "",
		"uuid_url":    pool.UUIDURL,
		"created_at":  pool.CreatedAt,
		"modified_at": pool.ModifiedAt,
		"is_enabled":  pool.IsEnabled,
		"send_alerts": pool.SendAlerts,
		"apps":        []interface{}{}, // Will be populated if needed
		"connectors":  []interface{}{}, // Will be populated with detailed info
	}

	// Handle optional description field
	if pool.Description != nil {
		poolData["description"] = *pool.Description
	}

	// Convert enum fields to human-readable strings
	packageTypeStr := client.ConvertIntToEnumString(pool.PackageType, func(i int) (string, error) {
		return client.ConnPackageTypeInt(i).String()
	})
	poolData["package_type"] = packageTypeStr

	infraTypeStr := client.ConvertIntToEnumString(pool.InfraType, func(i int) (string, error) {
		return client.InfraTypeInt(i).String()
	})
	poolData["infra_type"] = infraTypeStr

	operatingModeStr := client.ConvertIntToEnumString(pool.OperatingMode, func(i int) (string, error) {
		return client.OperatingModeInt(i).String()
	})
	poolData["operating_mode"] = operatingModeStr

	// Process connectors with detailed information from individual API calls
	if len(pool.Connectors) > 0 {

		// Unmarshal the raw JSON connectors data
		var rawConnectors []struct {
			Description    *string `json:"description"`
			LoadStatus     *string `json:"load_status"`
			Name           string  `json:"name"`
			UUIDURL        string  `json:"uuid_url"`
			CreatedAt      string  `json:"created_at"`
			Localization   string  `json:"localization"`
			Package        int     `json:"package"`
			State          int     `json:"state"`
			Status         int     `json:"status"`
			Reach          int     `json:"reach"`
			AgentInfraType int     `json:"agent_infra_type"`
		}

		if err := json.Unmarshal(pool.Connectors, &rawConnectors); err == nil {
			var detailedConnectors []interface{}

			for _, connector := range rawConnectors {
				if connector.UUIDURL != "" {
					// Fetch detailed connector information from the agents API
					detailedConnector := fetchDetailedConnectorInfo(eaaclient, connector.UUIDURL)
					if detailedConnector != nil {
						detailedConnectors = append(detailedConnectors, detailedConnector)
					} else {
						// Fallback to basic connector info if detailed fetch fails
						description := ""
						if connector.Description != nil {
							description = *connector.Description
						}

						loadStatus := ""
						if connector.LoadStatus != nil {
							loadStatus = *connector.LoadStatus
						}

						basicConnector := map[string]interface{}{
							"name":             connector.Name,
							"uuid_url":         connector.UUIDURL,
							"package":          connector.Package,
							"state":            connector.State,
							"status":           connector.Status,
							"created_at":       connector.CreatedAt,
							"description":      description,
							"load_status":      loadStatus,
							"localization":     connector.Localization,
							"reach":            connector.Reach,
							"agent_infra_type": connector.AgentInfraType,
						}
						detailedConnectors = append(detailedConnectors, basicConnector)
					}
				}
			}

			poolData["connectors"] = detailedConnectors
		}
	}

	return poolData
}

// fetchDetailedConnectorInfo fetches detailed connector information from the agents API
func fetchDetailedConnectorInfo(client *client.EaaClient, uuidURL string) map[string]interface{} {
	// Build API URL to get detailed connector info with expanded fields
	apiURL := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/agents?uuid_url=%s&expand=true&fields=name,uuid_url,package,state,status,created_at,description,load_status,localization,reach,agent_infra_type,geo_location,last_checkin,is_enabled,modified_at,resource_uri,operating_mode,package_type,infra_type", client.Host, uuidURL)

	// Define comprehensive response structure
	var response struct {
		Objects []struct {
			GeoLocation  *string `json:"geo_location"`
			LastCheckin  *string `json:"last_checkin"`
			Localization string  `json:"localization"`
			ResourceURI  struct {
				Href string `json:"href"`
			} `json:"resource_uri"`
			ModifiedAt     string `json:"modified_at"`
			CreatedAt      string `json:"created_at"`
			Description    string `json:"description"`
			LoadStatus     string `json:"load_status"`
			Name           string `json:"name"`
			UUIDURL        string `json:"uuid_url"`
			AgentInfraType int    `json:"agent_infra_type"`
			Package        int    `json:"package"`
			Reach          int    `json:"reach"`
			Status         int    `json:"status"`
			State          int    `json:"state"`
			OperatingMode  int    `json:"operating_mode"`
			PackageType    int    `json:"package_type"`
			InfraType      int    `json:"infra_type"`
			IsEnabled      bool   `json:"is_enabled"`
		} `json:"objects"`
	}

	// Make API request
	resp, err := client.SendAPIRequest(apiURL, "GET", nil, &response, false)
	if err != nil {

		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {

		return nil
	}

	// Return first connector's details if available
	if len(response.Objects) > 0 {
		connector := response.Objects[0]

		// Handle optional fields
		geoLocation := ""
		if connector.GeoLocation != nil {
			geoLocation = *connector.GeoLocation
		}

		lastCheckin := ""
		if connector.LastCheckin != nil {
			lastCheckin = *connector.LastCheckin
		}

		// For now, return the raw values without enum conversion to avoid compilation issues
		detailedConnector := map[string]interface{}{
			"name":             connector.Name,
			"uuid_url":         connector.UUIDURL,
			"package":          connector.Package,
			"state":            connector.State,
			"status":           connector.Status,
			"created_at":       connector.CreatedAt,
			"description":      connector.Description,
			"load_status":      connector.LoadStatus,
			"localization":     connector.Localization,
			"reach":            connector.Reach,
			"agent_infra_type": connector.AgentInfraType,
			"geo_location":     geoLocation,
			"last_checkin":     lastCheckin,
			"is_enabled":       connector.IsEnabled,
			"modified_at":      connector.ModifiedAt,
			"resource_uri":     connector.ResourceURI.Href,
			"operating_mode":   connector.OperatingMode, // Raw integer value
		}

		return detailedConnector
	}

	return nil
}

// ============================================================================
// DATA SOURCE SCHEMA DEFINITION
// ============================================================================

func dataSourceEaaConnectorPools() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceEaaConnectorPoolsRead,

		Schema: map[string]*schema.Schema{
			"connector_pools": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of connector pools",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Name of the connector pool",
						},
						"description": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Description of the connector pool",
						},
						"connectors": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "Connectors in the pool",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Name of the connector",
									},
									"package": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Package type of the connector",
									},
									"state": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "State of the connector",
									},
									"status": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Status of the connector",
									},
									"uuid_url": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "UUID URL of the connector",
									},
									"created_at": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Creation timestamp of the connector",
									},
									"description": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Description of the connector",
									},
									"load_status": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Load status of the connector",
									},
									"localization": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Localization of the connector",
									},
									"reach": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Reach status of the connector",
									},
									"agent_infra_type": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Agent infrastructure type of the connector",
									},
									"geo_location": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Geographic location of the connector",
									},
									"last_checkin": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Last check-in timestamp of the connector",
									},
									"is_enabled": {
										Type:        schema.TypeBool,
										Computed:    true,
										Description: "Whether the connector is enabled",
									},
									"modified_at": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Last modification timestamp of the connector",
									},
									"resource_uri": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Resource URI of the connector",
									},

									"operating_mode": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Operating mode of the connector (connector, peb, combined, cpag_public, cpag_private, connector_with_china_acceleration)",
									},
								},
							},
						},
						"apps": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "Applications associated with the connector pool",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Name of the application",
									},
									"uuid_url": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "UUID URL of the application",
									},
								},
							},
						},
						"uuid_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "UUID URL of the connector pool",
						},
						"package_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Package type for the connector pool (vmware, vbox, aws, kvm, hyperv, docker, aws_classic, azure, google, softlayer, fujitsu_k5)",
						},
						"infra_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Infrastructure type for the connector pool (eaa, unified, broker, cpag)",
						},
						"operating_mode": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Operating mode for the connector pool (connector, peb, combined, cpag_public, cpag_private, connector_with_china_acceleration)",
						},
						"created_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Creation timestamp of the connector pool",
						},
						"modified_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Last modification timestamp of the connector pool",
						},
						"is_enabled": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether the connector pool is enabled",
						},
						"send_alerts": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether the connector pool sends alerts",
						},
						"registration_tokens": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "Registration tokens for the connector pool",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"uuid_url": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "UUID URL of the registration token",
									},
									"name": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Name of the registration token",
									},
									"max_use": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Maximum number of times the token can be used",
									},
									"connector_pool": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Connector pool UUID",
									},
									"agents": {
										Type:        schema.TypeList,
										Computed:    true,
										Description: "Agents associated with the token",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"expires_in_days": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Days until the token expires",
									},
									"expires_at": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Expiration timestamp of the token",
									},
									"image_url": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Image URL for the token",
									},
									"token": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "The actual token value",
									},
									"used_count": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Number of times the token has been used",
									},
									"token_suffix": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Token suffix",
									},
									"modified_at": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Last modification timestamp of the token",
									},
									"generate_embedded_img": {
										Type:        schema.TypeBool,
										Computed:    true,
										Description: "Whether to generate embedded image for the token",
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

// ============================================================================
// DATA SOURCE READ OPERATION
// ============================================================================

func dataSourceEaaConnectorPoolsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	// Implement smart pagination directly here for maximum performance
	var allPools []interface{}
	offset := 0
	var apiLimit int // Will be set from API response meta

	for {
		// Build URL - first request without limit/offset, subsequent requests with API's limit
		var apiURL string
		if offset == 0 {
			// First request: let API use its default limit
			apiURL = fmt.Sprintf("https://%s/crux/v1/mgmt-pop/connector-pools", eaaclient.Host)
		} else {
			// Subsequent requests: use the limit we got from API response meta
			apiURL = fmt.Sprintf("https://%s/crux/v1/mgmt-pop/connector-pools?limit=%d&offset=%d", eaaclient.Host, apiLimit, offset)
		}

		// Define the response structure to read ALL meta information
		type connectorPoolsListResponse struct {
			Objects []client.ConnectorPool `json:"objects"`
			Meta    struct {
				Next       *string `json:"next"`
				Previous   *string `json:"previous"`
				Limit      int     `json:"limit"`
				Offset     int     `json:"offset"`
				TotalCount int     `json:"total_count"`
			} `json:"meta"`
		}

		var response connectorPoolsListResponse
		resp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &response, false)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to get connector pools: %w", err))
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			desc, _ := client.FormatErrorResponse(resp)
			getErrMsg := fmt.Errorf("get connector pools failed: %s", desc)

			return diag.FromErr(getErrMsg)
		}

		// Set the API limit from the first response (if not already set)
		if offset == 0 {
			apiLimit = response.Meta.Limit

		}

		// Process each pool in this batch
		for _, pool := range response.Objects {
			poolData := convertConnectorPoolToMap(&pool, eaaclient)

			allPools = append(allPools, poolData)
		}

		// SMART PAGINATION: Use meta information to determine when to stop

		// Check 1: No more pages available (meta.next is null)
		if response.Meta.Next == nil {

			break
		}

		// Check 2: We've retrieved all pools according to API total count
		if response.Meta.TotalCount > 0 && len(allPools) >= response.Meta.TotalCount {

			break
		}

		// Check 3: API returned fewer objects than its own limit (end of data)
		if len(response.Objects) < response.Meta.Limit {

			break
		}

		// Move to next batch using the API's limit
		offset += response.Meta.Limit

		// Safety check to prevent infinite loops
		if offset > 10000 {

			break
		}

		// Add a small delay to prevent overwhelming the API

		time.Sleep(100 * time.Millisecond)
	}

	// Set data source ID and results
	d.SetId("eaa_connector_pools")

	err = d.Set("connector_pools", allPools)
	if err != nil {

		return diag.FromErr(fmt.Errorf("failed to set connector_pools: %w", err))
	}

	return nil
}
