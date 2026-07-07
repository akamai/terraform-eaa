package eaaprovider

import (
	"context"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceDirectories() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceDirectoriesRead,

		Schema: map[string]*schema.Schema{
			"directories": {
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
						"service": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"status": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"directory_type": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"user_count": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"group_count": {
							Type:     schema.TypeInt,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceDirectoriesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagDirectory, logging.TagRead}
	logging.Info(ctx, "reading directories data source", tags)

	eaaClient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	dirs, err := client.ListDirectories(ctx, eaaClient)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to list directories")
	}

	var dirList []interface{}
	for _, dir := range dirs {
		dirList = append(dirList, map[string]interface{}{
			"name":           dir.Name,
			"uuid_url":       dir.UUIDURL,
			"service":        dir.Service,
			"status":         dir.Status,
			"directory_type": dir.DirectoryType,
			"user_count":     dir.UserCount,
			"group_count":    dir.GroupCount,
		})
	}

	if err := d.Set("directories", dirList); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set directories data")
	}

	d.SetId("eaa_directories")

	logging.Info(ctx, "directories data source read successfully", tags)
	return nil
}
