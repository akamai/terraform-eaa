package eaaprovider

import (
	"context"
	"fmt"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAppAccessGroups() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceAppAccessGroupsRead,

		Schema: map[string]*schema.Schema{
			"connector_pool_uuid_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "UUID URL of the connector pool to get app access groups for",
			},
			"limit": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     10,
				Description: "Number of app access groups to return",
			},
			"offset": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     0,
				Description: "Offset for pagination",
			},
			"order": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "asc",
				Description: "Sort order (asc or desc)",
			},
			"sort_by": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "name",
				Description: "Field to sort by",
			},
			"app_access_groups": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of app access groups",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"uuid": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "UUID of the app access group",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Name of the app access group",
						},
						"description": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Description of the app access group",
						},
						"is_enabled": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether the app access group is enabled",
						},
						"created_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Creation timestamp",
						},
						"modified_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Modification timestamp",
						},
						"resource_uri": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "Resource URI information",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"href": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Resource URI href",
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

func dataSourceAppAccessGroupsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaClient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	connectorPoolUUID := d.Get("connector_pool_uuid_url").(string)
	contractID := eaaClient.ContractID
	limit := d.Get("limit").(int)
	offset := d.Get("offset").(int)
	order := d.Get("order").(string)
	sortBy := d.Get("sort_by").(string)

	// Get app access groups (GID is not used in the API call)
	appAccessGroups, err := client.GetAppAccessGroups(ctx, eaaClient, connectorPoolUUID, contractID, "", limit, offset, order, sortBy)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to get app access groups for connector pool %s: %w", connectorPoolUUID, err))
	}

	// Set the ID to the connector pool UUID
	d.SetId(connectorPoolUUID)

	// Convert app access groups to schema format
	var groups []map[string]interface{}
	for _, group := range appAccessGroups {
		groupMap := map[string]interface{}{
			"uuid":        group.UUID,
			"name":        group.Name,
			"description": group.Description,
			"is_enabled":  group.IsEnabled,
			"created_at":  group.CreatedAt,
			"modified_at": group.ModifiedAt,
		}

		// Handle resource_uri
		if group.ResourceURI.Href != "" {
			resourceURI := []map[string]interface{}{
				{
					"href": group.ResourceURI.Href,
				},
			}
			groupMap["resource_uri"] = resourceURI
		}

		groups = append(groups, groupMap)
	}

	d.Set("app_access_groups", groups)

	return nil
}
