package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

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
				Optional:    true,
				Description: "The edgerc file path key for the provider.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"eaa_application":            resourceEaaApplication(),
			"eaa_connector":              resourceEaaConnector(),
			"eaa_connector_pool":         resourceEaaConnectorPool(),
			"eaa_custom_app_certificate": resourceEaaCustomAppCertificate(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"eaa_data_source_pops":              dataSourcePops(),
			"eaa_data_source_appcategories":     dataSourceAppCategories(),
			"eaa_data_source_agents":            dataSourceAgents(),
			"eaa_data_source_idps":              dataSourceIdps(),
			"eaa_data_source_tls_cipher_suites": dataSourceTLSCipherSuites(),
			"eaa_connector_pools":               dataSourceEaaConnectorPools(),
			"eaa_data_source_apps":              dataSourceApps(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	contractID, ok := d.Get("contractid").(string)
	if !ok || contractID == "" {
		return nil, logging.DiagErrorf([]logging.Tag{logging.TagConfig, logging.TagValidate}, "contractid must be a non-empty string")
	}
	accountSwitchKey, ok := d.Get("accountswitchkey").(string)
	if !ok {
		return nil, logging.DiagErrorf([]logging.Tag{logging.TagConfig, logging.TagValidate}, "accountswitchkey must be a string")
	}

	edgercPath, ok := d.Get("edgerc").(string)
	if !ok {
		return nil, logging.DiagErrorf([]logging.Tag{logging.TagConfig, logging.TagValidate}, "edgerc must be a string")
	}

	edgerc, err := edgegrid.New(edgegrid.WithEnv(true), edgegrid.WithFile(edgercPath))
	if err != nil {
		return nil, logging.DiagErrorf([]logging.Tag{logging.TagConfig, logging.TagValidate}, "%s: %s", ErrInvalidEdgercConfig, err.Error())
	}

	if err := edgerc.Validate(); err != nil {
		return nil, logging.DiagFromErr(err, []logging.Tag{logging.TagConfig, logging.TagValidate}, "edgerc validation failed")
	}

	eaaClient := &client.EaaClient{
		Client:           http.DefaultClient,
		ContractID:       contractID,
		AccountSwitchKey: accountSwitchKey,
		Signer:           edgerc,
		Host:             edgerc.Host,
	}

	// Return the configured client as the provider configuration
	return eaaClient, nil
}

func Client(meta interface{}) (*client.EaaClient, error) {
	eaaClient, ok := meta.(*client.EaaClient)
	if !ok {
		return nil, fmt.Errorf("invalid client")
	}

	return eaaClient, nil
}
