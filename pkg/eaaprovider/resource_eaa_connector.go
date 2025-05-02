package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrGetConnector    = errors.New("connector get failed")
	ErrInvalidConnData = errors.New("invalid connector data in schema")
)

func resourceEaaConnector() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaConnectorCreate,
		ReadContext:   resourceEaaConnectorRead,
		UpdateContext: resourceEaaConnectorUpdate,
		DeleteContext: resourceEaaConnectorDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"debug_channel_permitted": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"package": {
				Type:     schema.TypeString,
				Required: true,
			},
			"reach": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "reachability of the agent",
			},
			"state": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "state of the agent",
			},
			"os_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "OS version of the agent",
			},
			"public_ip": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "public IP of the agent",
			},
			"private_ip": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "private IP of the agent",
			},
			"type": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "type of the agent",
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "region of the agent",
			},
			"download_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"uuid_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"advanced_settings": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"network_info": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
		},
	}
}

// resourceEaaConnectorCreate function is responsible for creating a new EAA Connector.
// constructs the connector creation request using data from the schema and creates the connector.
func resourceEaaConnectorCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	createRequest := client.CreateConnectorRequest{}
	err = createRequest.CreateConnectorRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		logger.Error("create connector failed. err ", err)
		return diag.FromErr(err)
	}

	connResp, err := createRequest.CreateConnector(ctx, eaaclient)
	if err != nil {
		logger.Error("create connector failed. err ", err)
		return diag.FromErr(err)
	}

	// Set the resource ID
	d.SetId(connResp.UUIDURL)
	return resourceEaaConnectorRead(ctx, d, m)
}

// resourceEaaConnectorRead function reads an existing EAA connector.
// fetches connector details and maps the response to the schema attributes.

func resourceEaaConnectorRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	id := d.Id()
	eaaclient := m.(*client.EaaClient)
	var connResp client.Connector

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.AGENTS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &connResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := client.FormatErrorResponse(getResp)
		getConnErrMsg := fmt.Errorf("%w: %s", ErrGetConnector, desc)
		return diag.FromErr(getConnErrMsg)
	}
	attrs := make(map[string]interface{})
	attrs["name"] = connResp.Name
	attrs["uuid_url"] = connResp.UUIDURL
	attrs["reach"] = connResp.Reach
	attrs["os_version"] = connResp.OSVersion
	attrs["public_ip"] = connResp.PublicIP
	attrs["private_ip"] = connResp.PrivateIP
	attrs["type"] = connResp.AgentType
	attrs["region"] = connResp.Region
	attrs["download_url"] = connResp.DownloadURL

	connPackage := client.ConnPackageTypeInt(connResp.Package)
	connPackageString, err := connPackage.String()
	if err != nil {
		eaaclient.Logger.Info("error converting package")
	}
	attrs["package"] = connPackageString

	connState := client.ConnPackageStateInt(connResp.State)
	connStateString, err := connState.String()
	if err != nil {
		eaaclient.Logger.Info("error converting connector state")
	}
	attrs["state"] = connStateString

	if err := client.SetAttrs(d, attrs); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

// resourceEaaConnectorUpdate approves the connector if it is ready to be approved
func resourceEaaConnectorUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Set the resource ID
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	var connResp client.Connector

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.AGENTS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &connResp, false)
	if err != nil {
		return diag.FromErr(err)
	}

	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := client.FormatErrorResponse(getResp)
		getConnErrMsg := fmt.Errorf("%w: %s", ErrGetConnector, desc)
		return diag.FromErr(getConnErrMsg)
	}

	_, err = connResp.UpdateConnector(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	// Check if the 'state' has changed, if so approve
	if d.HasChange("state") {

		apiURL := fmt.Sprintf("%s://%s/%s/%s/approve", client.URL_SCHEME, eaaclient.Host, client.AGENTS_URL, id)

		getResp, err := eaaclient.SendAPIRequest(apiURL, "POST", nil, nil, false)
		if err != nil {
			return diag.FromErr(err)
		}
		if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
			logger.Error("approve connector failed. err ", err)
		}
	}

	return resourceEaaConnectorRead(ctx, d, m)
}

// resourceEaaConnectorDelete function deletes an existing EAA connector.
// sends a delete request to the EAA client to remove the connector.
func resourceEaaConnectorDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Read the resource ID from d
	id := d.Id()
	eaaclient := m.(*client.EaaClient)

	// Send the delete connector REST endpoint
	err := client.DeleteConnector(eaaclient, id)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID to mark it as deleted
	d.SetId("")

	return nil
}
