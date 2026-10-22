package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

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
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Package type for the connector. Valid values: vmware, vbox, aws, kvm, hyperv, docker, azure, google, softlayer, fujitsu_k5. Note: aws_classic is no longer supported for new resources; use aws instead.",
				ValidateFunc: validatePackageType,
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
	tags := []logging.Tag{logging.TagProvider, logging.TagConnector, logging.TagCreate}
	logging.Info(ctx, "creating connector", tags)

	if v, ok := d.GetOk("package"); ok {
		if pkgType, isStr := v.(string); isStr && pkgType == string(client.ConnPackageTypeAWSClassic) {
			return logging.DiagErrorf(tags, "\"aws_classic\" is no longer supported for new connectors, please use \"aws\" instead")
		}
	}

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	createRequest := client.CreateConnectorRequest{}
	err = createRequest.CreateConnectorRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		logging.Warn(ctx, "create connector failed", tags, map[string]any{"error": err.Error()})
		return logging.DiagFromErr(err, tags, "create connector failed")
	}

	connResp, err := createRequest.CreateConnector(ctx, eaaclient)
	if err != nil {
		logging.Warn(ctx, "create connector failed", tags, map[string]any{"error": err.Error()})
		return logging.DiagFromErr(err, tags, "create connector failed")
	}

	// Set the resource ID
	d.SetId(connResp.UUIDURL)

	logging.Info(ctx, "connector created successfully", tags)
	return resourceEaaConnectorRead(ctx, d, m)
}

// resourceEaaConnectorRead function reads an existing EAA connector.
// fetches connector details and maps the response to the schema attributes.

func resourceEaaConnectorRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagConnector, logging.TagRead}
	logging.Info(ctx, "reading connector", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}
	var connResp client.Connector

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.AGENTS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "GET", nil, &connResp, false)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to read connector")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := client.FormatErrorDescription(getResp)
		getConnErrMsg := fmt.Errorf("%w: %s", ErrGetConnector, desc)
		return logging.DiagFromErr(getConnErrMsg, tags, "connector get failed")
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
		logging.Warn(ctx, "error converting package type", tags, map[string]any{"raw_value": connResp.Package, "error": err.Error()})
	}
	attrs["package"] = connPackageString

	connState := client.ConnPackageStateInt(connResp.State)
	connStateString, err := connState.String()
	if err != nil {
		logging.Warn(ctx, "error converting connector state", tags, map[string]any{"raw_value": connResp.State, "error": err.Error()})
	}
	attrs["state"] = connStateString

	if err := client.SetAttrs(d, attrs); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set connector attributes")
	}

	logging.Info(ctx, "connector read successfully", tags)
	return nil
}

// resourceEaaConnectorUpdate approves the connector if it is ready to be approved
func resourceEaaConnectorUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagConnector, logging.TagUpdate}
	logging.Info(ctx, "updating connector", tags)

	if d.HasChange("package") {
		if v, ok := d.GetOk("package"); ok {
			if pkgType, isStr := v.(string); isStr && pkgType == string(client.ConnPackageTypeAWSClassic) {
				return logging.DiagErrorf(tags, "\"aws_classic\" is no longer supported, please use \"aws\" instead")
			}
		}
	}

	// Set the resource ID
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	var connResp client.Connector

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.AGENTS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "GET", nil, &connResp, false)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to read connector for update")
	}

	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := client.FormatErrorDescription(getResp)
		getConnErrMsg := fmt.Errorf("%w: %s", ErrGetConnector, desc)
		return logging.DiagFromErr(getConnErrMsg, tags, "connector get failed")
	}

	_, err = connResp.UpdateConnector(ctx, d, eaaclient)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to update connector")
	}

	// Check if the 'state' has changed, if so approve
	if d.HasChange("state") {

		apiURL := fmt.Sprintf("%s://%s/%s/%s/approve", client.URL_SCHEME, eaaclient.Host, client.AGENTS_URL, id)

		getResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "POST", map[string]interface{}{}, nil, false)
		if err != nil {
			return logging.DiagFromErr(err, tags, "failed to approve connector")
		}
		if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
			desc := client.FormatErrorDescription(getResp)
			logging.Warn(ctx, "approve connector failed", tags, map[string]any{"status_code": getResp.StatusCode, "error": desc})
			return logging.DiagErrorf(tags, "approve connector failed: %s", desc)
		}
	}

	logging.Info(ctx, "connector updated successfully", tags)
	return resourceEaaConnectorRead(ctx, d, m)
}

// resourceEaaConnectorDelete function deletes an existing EAA connector.
// sends a delete request to the EAA client to remove the connector.
func resourceEaaConnectorDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagConnector, logging.TagDelete}
	logging.Info(ctx, "deleting connector", tags)

	// Read the resource ID from d
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Send the delete connector REST endpoint
	err = client.DeleteConnector(ctx, eaaclient, id)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to delete connector")
	}

	// Set the resource ID to mark it as deleted
	d.SetId("")

	logging.Info(ctx, "connector deleted successfully", tags)
	return nil
}
