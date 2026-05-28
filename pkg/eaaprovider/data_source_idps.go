package eaaprovider

import (
	"context"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceIdps() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceIdpsRead,

		Schema: map[string]*schema.Schema{
			"idps": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"uuid_url": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"directories": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"uuid": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"groups": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"name": {
													Type:     schema.TypeString,
													Computed: true,
												},
												"uuid_url": {
													Type:     schema.TypeString,
													Computed: true,
												},
											},
										},
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

func dataSourceIdpsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagIDP, logging.TagRead}
	logging.Info(ctx, "reading IDPs data source", tags)

	eaaClient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	idps, err := client.GetIDPS(ctx, eaaClient)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get IDPs")
	}

	if idps != nil {
		idpListSchema := convertToSchemaType(idps.IDPS)

		if err := d.Set("idps", idpListSchema); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set IDPs data")
		}

		// Set the resource ID
		d.SetId("eaa_idps")
	}

	logging.Info(ctx, "IDPs data source read successfully", tags)
	return nil

}

func convertToSchemaType(idps []client.IDPData) []interface{} {
	var idpList []interface{}
	for _, idp := range idps {
		idpData := map[string]interface{}{
			"name":     idp.Name,
			"uuid_url": idp.UUIDURL,
		}

		var directories []interface{}
		for _, dir := range idp.Directories {
			dirData := map[string]interface{}{
				"name": dir.Name,
				"uuid": dir.UUID,
			}

			var groups []interface{}
			for _, group := range dir.Groups {
				groupData := map[string]interface{}{
					"name":     group.Name,
					"uuid_url": group.UUID_URL,
				}
				groups = append(groups, groupData)
			}

			if len(groups) > 0 {
				dirData["groups"] = groups
			}

			directories = append(directories, dirData)
		}

		if len(directories) > 0 {
			idpData["directories"] = directories
		}

		idpList = append(idpList, idpData)
	}

	return idpList
}
