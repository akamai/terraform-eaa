package eaaprovider

import (
	"context"
	"errors"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrAppCategoriesGet = errors.New("appCategories get failed")
)

type AppCategory struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

type AppCategoriesResponse struct {
	Meta struct {
		TotalCount int `json:"total_count"`
	} `json:"meta"`
	AppCategories []AppCategory `json:"objects"`
}

func dataSourceAppCategories() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceAppCategoriesRead,

		Schema: map[string]*schema.Schema{

			"appcategories": &schema.Schema{
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"uuid_url": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceAppCategoriesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	eaaClient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	appCats, err := client.GetAppCategories(eaaClient)
	if err != nil {
		return diag.FromErr(err)
	}

	var acDataList []interface{}
	for _, ac := range appCats {
		acData := map[string]interface{}{
			"name":     ac.Name,
			"uuid_url": ac.UUIDURL,
		}
		acDataList = append(acDataList, acData)
	}

	if err := d.Set("appcategories", acDataList); err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID
	d.SetId("eaa_appcategories")

	return nil

}
