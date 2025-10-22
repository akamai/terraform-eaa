package eaaprovider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
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
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of available TLS cipher suites",
				Elem: &schema.Schema{
					Type: schema.TypeMap,
					Elem: &schema.Schema{
						Type: schema.TypeString,
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
	var diags diag.Diagnostics

	// Get the EAA client
	eaaClient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	// Get the app_uuid_url parameter
	appUUIDURL := d.Get("app_uuid_url").(string)

	// Make API call to get TLS cipher suites
	tlsResponse, err := client.GetTLSCipherSuites(eaaClient, appUUIDURL)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Failed to fetch TLS cipher suites",
			Detail:   fmt.Sprintf("Error calling API: %v", err),
		})
		return diags
	}

	// Convert cipher suites to map format for Terraform
	cipherSuitesMap := make(map[string]interface{})
	cipherSuiteNames := make([]string, 0, len(tlsResponse.TLSCipherSuite))
	var defaultSuiteName string

	for name, suite := range tlsResponse.TLSCipherSuite { // Add to names list
		cipherSuiteNames = append(cipherSuiteNames, name)

		// Track default suite
		if suite.Default {
			defaultSuiteName = name
		}

		// Convert suite to map for Terraform
		suiteMap := map[string]interface{}{
			"default":       suite.Default,
			"selected":      suite.Selected,
			"ssl_cipher":    suite.SSLCipher,
			"ssl_protocols": suite.SSLProtocols,
			"weak_cipher":   suite.WeakCipher,
		}
		cipherSuitesMap[name] = suiteMap
	}

	// Set the data source attributes
	d.SetId(appUUIDURL) // Use app_uuid_url as the ID
	d.Set("cipher_suites", cipherSuitesMap)
	d.Set("cipher_suite_names", cipherSuiteNames)
	d.Set("default_suite_name", defaultSuiteName)

	return diags
}
