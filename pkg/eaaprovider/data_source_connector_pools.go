package eaaprovider

import (
	"context"
	"fmt"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ============================================================================
// HELPER FUNCTIONS FOR DATA SOURCE OPERATIONS
// ============================================================================

// convertConnectorPoolToMap converts a ConnectorPool to a map for the schema
func convertConnectorPoolToMap(pool *client.ConnectorPool, eaaclient *client.EaaClient) map[string]interface{} {
	return client.ConvertConnectorPoolToMap(pool, eaaclient)
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
										Type:     schema.TypeList,
										Computed: true,
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

	// Get connector pools from API
	connectorPools, err := client.GetConnectorPools(ctx, eaaclient)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to get connector pools: %w", err))
	}

	// Convert connector pools to schema format using helper function
	var poolsList []interface{}
	for _, pool := range connectorPools {
		poolData := convertConnectorPoolToMap(&pool, eaaclient)
		poolsList = append(poolsList, poolData)
	}

	// Set data source ID and results
	d.SetId("eaa_connector_pools")
	d.Set("connector_pools", poolsList)

	eaaclient.Logger.Info("Successfully retrieved", len(connectorPools), "connector pools")
	return nil
}
