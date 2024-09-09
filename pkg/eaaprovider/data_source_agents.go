package eaaprovider

import (
	"context"
	"errors"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrAgentsGet = errors.New("agents get failed")
)

func dataSourceAgents() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceAgentsRead,

		Schema: map[string]*schema.Schema{

			"agents": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of agents",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "name of the agent",
						},
						"reach": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "reachability of the agent",
						},
						"state": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "state of the agent",
						},
						"os_version": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OS version of the agent",
						},
						"public_ip": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "public IP of the agent",
						},
						"private_ip": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "private IP of the agent",
						},
						"type": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "type of the agent",
						},
						"region": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "region of the agent",
						},
						"uuid_url": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceAgentsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaClient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	agents, err := client.GetAgents(eaaClient)
	if err != nil {
		return diag.FromErr(err)
	}
	var connDataList []interface{}
	for _, conn := range agents {
		connData := map[string]interface{}{
			"name":       conn.Name,
			"uuid_url":   conn.UUIDURL,
			"reach":      conn.Reach,
			"state":      conn.State,
			"os_version": conn.OSVersion,
			"public_ip":  conn.PublicIP,
			"private_ip": conn.PrivateIP,
			"type":       conn.AgentType,
			"region":     conn.Region,
		}
		connDataList = append(connDataList, connData)
	}

	if err := d.Set("agents", connDataList); err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID
	d.SetId("eaa_agents")

	return nil

}
