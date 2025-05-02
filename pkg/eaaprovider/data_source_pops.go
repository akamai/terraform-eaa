package eaaprovider

import (
	"context"
	"errors"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrPopsGet = errors.New("pops get failed")
)

func dataSourcePops() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourcePopsRead,

		Schema: map[string]*schema.Schema{

			"pops": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of pops",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"region": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The region of the pop",
						},
						"description": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The description of the pop",
						},
						"facility": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The facility of the pop",
						},
						"name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The name of the pop",
						},
						"pop_category": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "List of pop categories",
							Elem:        schema.TypeString,
						},
						"pop_type": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The type of the pop",
						},
						"related_failover_pop": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The related failover pop",
						},
						"related_failover_name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The name of the related failover pop",
						},
						"uuid_url": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The UUID URL of the pop",
						},
					},
				},
			},
		},
	}
}

func dataSourcePopsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaClient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	pops, err := client.GetPops(eaaClient)
	if err != nil {
		return diag.FromErr(err)
	}

	var popDataList []interface{}
	for _, pop := range pops {
		popData := map[string]interface{}{
			"region":                pop.Region,
			"description":           pop.Description,
			"facility":              pop.Facility,
			"name":                  pop.Name,
			"pop_category":          pop.PopCategory,
			"pop_type":              pop.PopType,
			"related_failover_pop":  pop.RelatedFailoverPop,
			"related_failover_name": pop.RelatedFailoverName,
			"uuid_url":              pop.UUIDURL,
		}
		popDataList = append(popDataList, popData)
	}

	if err := d.Set("pops", popDataList); err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID
	d.SetId("eaa_pops")

	return nil

}
