package eaaprovider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

func dataSourceTLSCipherSuites() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceTLSCipherSuitesRead,
		Schema: map[string]*schema.Schema{
			"app_uuid_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The UUID URL of the application to get TLS cipher suites for",
			},
			"cipher_suites": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of available TLS cipher suites",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"default": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"selected": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"ssl_cipher": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ssl_protocols": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"weak_cipher": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},
			"cipher_suite_names": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of available TLS cipher suite names",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"default_suite_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The default TLS cipher suite name",
			},
		},
	}
}

func dataSourceTLSCipherSuitesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCipher, logging.TagRead}
	logging.Info(ctx, "reading TLS cipher suites data source", tags)

	var diags diag.Diagnostics

	// Get the EAA client
	eaaClient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Get the app_uuid_url parameter
	appUUIDURL, ok := d.Get("app_uuid_url").(string)
	if !ok || appUUIDURL == "" {
		return logging.DiagErrorf(tags, "app_uuid_url must be a non-empty string")
	}

	// Make API call to get TLS cipher suites
	tlsResponse, err := client.GetTLSCipherSuites(ctx, eaaClient, appUUIDURL)
	if err != nil {
		return logging.DiagFromErrf(err, tags, "failed to fetch TLS cipher suites")
	}

	cipherSuiteNames := make([]string, 0, len(tlsResponse.TLSCipherSuite))
	for name := range tlsResponse.TLSCipherSuite {
		cipherSuiteNames = append(cipherSuiteNames, name)
	}
	sort.Strings(cipherSuiteNames)

	cipherSuitesList := make([]map[string]interface{}, 0, len(tlsResponse.TLSCipherSuite))
	var defaultSuiteName string

	for _, name := range cipherSuiteNames {
		suite := tlsResponse.TLSCipherSuite[name]

		if suite.Default {
			defaultSuiteName = name
		}

		suiteMap := map[string]interface{}{
			"name":          name,
			"default":       suite.Default,
			"selected":      suite.Selected,
			"ssl_cipher":    suite.SSLCipher,
			"ssl_protocols": suite.SSLProtocols,
			"weak_cipher":   suite.WeakCipher,
		}
		cipherSuitesList = append(cipherSuitesList, suiteMap)
	}

	d.SetId(appUUIDURL)
	if err := d.Set("cipher_suites", cipherSuitesList); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set cipher_suites")
	}
	if err := d.Set("cipher_suite_names", cipherSuiteNames); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set cipher_suite_names")
	}
	if err := d.Set("default_suite_name", defaultSuiteName); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set default_suite_name")
	}

	logging.Info(ctx, "TLS cipher suites data source read successfully", tags)
	return diags
}
