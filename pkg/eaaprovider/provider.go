package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v6/pkg/edgegrid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrInvalidEdgercConfig = errors.New("edgerc config file is not valid")
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"contractid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The contract ID for the provider.",
			},
			"accountswitchkey": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The account switch key for the provider.",
			},
			"edgerc": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The edgerc file path key for the provider.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"eaa_application": resourceEaaApplication(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"eaa_data_source_pops":          dataSourcePops(),
			"eaa_data_source_appcategories": dataSourceAppCategories(),
			"eaa_data_source_agents":        dataSourceAgents(),
			"eaa_data_source_idps":          dataSourceIdps(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	contractID := d.Get("contractid").(string)
	accountSwitchKey := d.Get("accountswitchkey").(string)

	edgercPath := d.Get("edgerc").(string)

	edgerc, err := edgegrid.New(edgegrid.WithFile(edgercPath))
	if err != nil {
		return nil, diag.Errorf("%s: %s", ErrInvalidEdgercConfig, err.Error())
	}

	if err := edgerc.Validate(); err != nil {
		return nil, diag.FromErr(err)
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "eaa_terraform",
		Level:      hclog.Info,
		TimeFormat: time.RFC3339,
	})

	eaaClient := &client.EaaClient{
		Client:           http.DefaultClient,
		ContractID:       contractID,
		AccountSwitchKey: accountSwitchKey,
		Signer:           edgerc,
		Host:             edgerc.Host,
		Logger:           logger,
	}

	// Return the configured client as the provider configuration
	return eaaClient, nil
}

func Client(meta interface{}) (*client.EaaClient, error) {
	eaaClient, ok := meta.(*client.EaaClient)
	if !ok {
		return nil, fmt.Errorf("Invalid client")
	}

	return eaaClient, nil
}
