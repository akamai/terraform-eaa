package eaaprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceEaaConnectorPool() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceEaaConnectorPoolRead,

		Schema: map[string]*schema.Schema{
			"uuid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "UUID of the connector pool to retrieve",
			},
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
			"package_type": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Package type for the connector pool",
			},
			"infra_type": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Infrastructure type for the connector pool",
			},
			"operating_mode": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Operating mode for the connector pool",
			},
			"uuid_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "UUID URL of the connector pool",
			},
			"cidrs": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "CIDRs associated with the connector pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"connectors": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Connectors in the pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"applications": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Applications associated with the connector pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"is_enabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the connector pool is enabled",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Creation timestamp of the connector pool",
			},
			"modified_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Modification timestamp of the connector pool",
			},
			"localization": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Localization of the connector pool",
			},
			"send_alerts": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether alerts are sent for the connector pool",
			},
			"dns_override": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether DNS override is enabled",
			},
			"dns_list": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "DNS list for the connector pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"edns": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "EDNS for the connector pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"directories": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Directories associated with the connector pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"application_access_group": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Application access groups",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"application_access_groups": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Application access groups (plural)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"location_freetext": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Free text location",
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
	}
}

func dataSourceEaaConnectorPoolRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	eaaclient.Logger.Info("=== ENTERED dataSourceEaaConnectorPoolRead ===")

	uuid := d.Get("uuid").(string)
	contractID := eaaclient.ContractID

	url := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/connector-pools/%s?contractId=%s", 
		eaaclient.Host, uuid, contractID)
	
	eaaclient.Logger.Info("Getting connector pool with URL:", url)

	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		eaaclient.Logger.Info("Attempt", attempt, "of", maxRetries, "to get connector pool")

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to create request: %w", err))
		}

		req.Header.Set("Content-Type", "application/json")
		eaaclient.Signer.SignRequest(req)

		// Log all request headers
		for k, v := range req.Header {
			eaaclient.Logger.Info("Request header:", k, v)
		}

		resp, err := eaaclient.Client.Do(req)
		if err != nil {
			eaaclient.Logger.Error("Request failed:", err)
			if attempt == maxRetries {
				return diag.FromErr(fmt.Errorf("failed to get connector pool with UUID %s after %d attempts: %w", uuid, maxRetries, err))
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		defer resp.Body.Close()

		eaaclient.Logger.Info("GET API response status:", resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			eaaclient.Logger.Error("Failed to read response body:", err)
			if attempt == maxRetries {
				return diag.FromErr(fmt.Errorf("failed to read response body: %w", err))
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		eaaclient.Logger.Info("GET API response body:", string(body))

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			eaaclient.Logger.Error("GET failed with status:", resp.StatusCode, "error:", string(body))
			if attempt == maxRetries {
				return diag.FromErr(fmt.Errorf("failed to get connector pool with UUID %s: status %d - %s", uuid, resp.StatusCode, string(body)))
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		// Parse the response
		var connPool client.ConnectorPool
		if err := json.Unmarshal(body, &connPool); err != nil {
			eaaclient.Logger.Error("Failed to parse response:", err)
			if attempt == maxRetries {
				return diag.FromErr(fmt.Errorf("failed to parse connector pool response: %w", err))
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		d.SetId(uuid)
		d.Set("name", connPool.Name)
		d.Set("description", connPool.Description)
		d.Set("package_type", connPool.PackageType)
		d.Set("infra_type", connPool.InfraType)
		d.Set("operating_mode", connPool.OperatingMode)
		d.Set("uuid_url", connPool.UUIDURL)
		d.Set("cidrs", connPool.CIDRs)
		d.Set("connectors", connPool.Connectors)
		d.Set("applications", connPool.Applications)
		d.Set("is_enabled", connPool.IsEnabled)
		d.Set("created_at", connPool.CreatedAt)
		d.Set("modified_at", connPool.ModifiedAt)
		d.Set("localization", connPool.Localization)
		d.Set("send_alerts", connPool.SendAlerts)
		d.Set("dns_override", connPool.DNSOverride)
		d.Set("dns_list", connPool.DNSList)
		d.Set("edns", connPool.EDNS)
		d.Set("directories", connPool.Directories)
		d.Set("application_access_group", connPool.ApplicationAccessGroup)
		d.Set("application_access_groups", connPool.ApplicationAccessGroups)
		d.Set("location_freetext", connPool.LocationFreetext)

		if connPool.ResourceURI.Href != "" {
			resourceURI := []map[string]interface{}{
				{"href": connPool.ResourceURI.Href},
			}
			d.Set("resource_uri", resourceURI)
		}

		eaaclient.Logger.Info("Successfully retrieved connector pool:", connPool.Name)
		return nil
	}

	return diag.FromErr(fmt.Errorf("failed to get connector pool with UUID %s after %d attempts", uuid, maxRetries))
}
