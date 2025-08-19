package eaaprovider

import (
	"context"
	"errors"
	"fmt"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrAppsGet = errors.New("apps get failed")
)

func dataSourceApps() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceAppsRead,

		Schema: map[string]*schema.Schema{
			"apps": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of all applications",
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
		},
	}
}

func dataSourceAppsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaClient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	// Get all applications using the existing GetApps function with smart pagination
	apps, err := client.GetApps(eaaClient)
	if err != nil {
		return diag.FromErr(fmt.Errorf("%w: %w", ErrAppsGet, err))
	}

	// Convert apps to the expected schema format
	var appDataList []interface{}
	for _, app := range apps {
		appData := map[string]interface{}{
			"name":     app.Name,
			"uuid_url": app.UUIDURL,
		}
		appDataList = append(appDataList, appData)
	}

	// Set the apps data in the schema
	if err := d.Set("apps", appDataList); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set apps data: %w", err))
	}

	// Set the resource ID
	d.SetId("eaa_apps")

	return nil
}
