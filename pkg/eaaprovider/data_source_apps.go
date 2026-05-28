package eaaprovider

import (
	"context"
	"errors"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

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
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagRead}
	logging.Info(ctx, "reading apps data source", tags)

	eaaClient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Get all applications using the existing GetApps function with smart pagination
	apps, err := client.GetApps(ctx, eaaClient)
	if err != nil {
		return logging.DiagFromErrf(err, tags, "apps get failed")
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
		return logging.DiagFromErr(err, tags, "failed to set apps data")
	}

	// Set the resource ID
	d.SetId("eaa_apps")

	logging.Info(ctx, "apps data source read successfully", tags)
	return nil
}
