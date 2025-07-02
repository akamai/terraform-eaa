package eaaprovider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrRegistrationTokensGet = errors.New("registration tokens get failed")
)

func dataSourceRegistrationTokens() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceRegistrationTokensRead,

		Schema: map[string]*schema.Schema{
			"connector_pool": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "UUID of the connector pool to retrieve tokens for",
			},
			"tokens": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of registration tokens",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"uuid_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "UUID URL of the registration token",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Name of the registration token",
						},
						"max_use": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Maximum number of times the token can be used",
						},
						"connector_pool": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "UUID of the connector pool",
						},
						"agents": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "List of agents associated with the token",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"expires_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Expiration date and time for the token",
						},
						"image_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "URL of the generated image (if applicable)",
						},
						"token": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The generated token string",
						},
						"used_count": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Number of times the token has been used",
						},
						"token_suffix": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Suffix of the token",
						},
						"modified_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Last modification timestamp",
						},
					},
				},
			},
		},
	}
}

func dataSourceRegistrationTokensRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaClient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	connectorPool := d.Get("connector_pool").(string)
	contractID := eaaClient.ContractID

	// Get all registration tokens for the connector pool
	tokens, err := eaaClient.GetRegistrationTokens(connectorPool, contractID)
	if err != nil {
		return diag.FromErr(err)
	}

	var tokenDataList []interface{}
	for _, token := range tokens {
		tokenData := map[string]interface{}{
			"uuid_url":       token.UUIDURL,
			"name":           token.Name,
			"max_use":        token.MaxUse,
			"connector_pool": token.ConnectorPool,
			"agents":         token.Agents,
			"expires_at":     token.ExpiresAt,
			"image_url":      token.ImageURL,
			"token":          token.Token,
			"used_count":     token.UsedCount,
			"token_suffix":   token.TokenSuffix,
			"modified_at":    token.ModifiedAt,
		}
		tokenDataList = append(tokenDataList, tokenData)
	}

	if err := d.Set("tokens", tokenDataList); err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID
	d.SetId("eaa_registration_tokens_" + connectorPool)

	return nil
} 