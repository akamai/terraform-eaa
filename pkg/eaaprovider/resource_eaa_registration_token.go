package eaaprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrGetRegistrationToken    = errors.New("registration token get failed")
	ErrInvalidRegistrationTokenData = errors.New("invalid registration token data in schema")
)

func resourceEaaRegistrationToken() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaRegistrationTokenCreate,
		ReadContext:   resourceEaaRegistrationTokenRead,
		UpdateContext: resourceEaaRegistrationTokenUpdate,
		DeleteContext: resourceEaaRegistrationTokenDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the registration token (mandatory)",
			},
			"max_use": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "Maximum number of times the token can be used (mandatory)",
			},
			"expires_at": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Expiration date and time for the token in ISO 8601 format (mandatory)",
			},
			"connector_pool": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "UUID of the connector pool to associate with the token (mandatory)",
			},
			"generate_embedded_img": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to generate an embedded image for the token",
			},
			"uuid_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "UUID URL of the registration token",
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
			"image_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "URL of the generated image (if applicable)",
			},
			"modified_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last modification timestamp",
			},
			"agents": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of agents associated with the token",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"registration_token_get_api_response": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON response from registration token GET API call",
			},
		},
	}
}

// resourceEaaRegistrationTokenCreate function is responsible for creating a new EAA Registration Token.
func resourceEaaRegistrationTokenCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	createRequest := client.CreateRegistrationTokenRequest{}
	err = createRequest.CreateRegistrationTokenRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	contract_id := eaaclient.ContractID

	// Create the token - this will return an empty response but the token is created
	eaaclient.Logger.Info("=== CREATING REGISTRATION TOKEN ===")
	eaaclient.Logger.Info("Token Name:", d.Get("name").(string))
	eaaclient.Logger.Info("Connector Pool:", d.Get("connector_pool").(string))
	eaaclient.Logger.Info("Max Use:", d.Get("max_use").(int))
	eaaclient.Logger.Info("Expires At:", d.Get("expires_at").(string))
	
	_, err = createRequest.CreateRegistrationToken(ctx, eaaclient, contract_id, "")
	if err != nil {
		eaaclient.Logger.Error("Token creation failed:", err)
		return diag.FromErr(err)
	}
	eaaclient.Logger.Info("=== TOKEN CREATION SUCCESSFUL ===")
	
	// Since create response is empty, we need to get the token details via GET API
	// Add a longer delay to ensure the token is fully created and available
	eaaclient.Logger.Info("Waiting 10 seconds for token to be fully created and available...")
	time.Sleep(10 * time.Second)
	
	// Get all tokens for this connector pool and find the one we just created by name
	// Use the same connector_pool that was in the create payload
	connectorPoolID := d.Get("connector_pool").(string)
	eaaclient.Logger.Info("=== FETCHING TOKENS AFTER CREATION ===")
	eaaclient.Logger.Info("Connector Pool ID:", connectorPoolID)
	eaaclient.Logger.Info("Contract ID:", contract_id)
	
	// Try multiple times with increasing delays if needed
	var allTokens []client.RegistrationToken
	maxRetries := 6
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		eaaclient.Logger.Info(fmt.Sprintf("Attempt %d/%d: Fetching tokens...", attempt, maxRetries))
		allTokens, err = eaaclient.GetRegistrationTokens(connectorPoolID, contract_id)
		if err != nil {
			eaaclient.Logger.Error(fmt.Sprintf("Attempt %d failed to get tokens:", attempt), err)
			if attempt < maxRetries {
				eaaclient.Logger.Info(fmt.Sprintf("Waiting 10 seconds before retry %d...", attempt+1))
				time.Sleep(10 * time.Second)
				continue
			} else {
				return diag.FromErr(fmt.Errorf("failed to get tokens after creation after %d attempts: %w", maxRetries, err))
			}
		}
		eaaclient.Logger.Info(fmt.Sprintf("Attempt %d successful, found %d tokens", attempt, len(allTokens)))
		// Log the full list of tokens for debugging
		for i, token := range allTokens {
			eaaclient.Logger.Info(fmt.Sprintf("Token %d - Name: %s, UUID: %s, ConnectorPool: %s", i+1, token.Name, token.UUIDURL, token.ConnectorPool))
		}
		break
	}
	
	eaaclient.Logger.Info("=== TOKENS FETCHED SUCCESSFULLY ===")
	eaaclient.Logger.Info("Total tokens found:", len(allTokens))
	for i, token := range allTokens {
		eaaclient.Logger.Info(fmt.Sprintf("Token %d - Name: %s, UUID: %s, ConnectorPool: %s", i+1, token.Name, token.UUIDURL, token.ConnectorPool))
	}
	
	// Find the token by name (since create response is empty)
	tokenName := d.Get("name").(string)
	eaaclient.Logger.Info("=== SEARCHING FOR TOKEN BY NAME AND CONNECTOR POOL ===")
	eaaclient.Logger.Info("Looking for token with name:", tokenName)
	eaaclient.Logger.Info("Looking for connector pool:", connectorPoolID)
	
	var foundToken *client.RegistrationToken
	
	for i := range allTokens {
		eaaclient.Logger.Info(fmt.Sprintf("Checking token %d: Name=%s, ConnectorPool=%s", i+1, allTokens[i].Name, allTokens[i].ConnectorPool))
		if allTokens[i].Name == tokenName && allTokens[i].ConnectorPool == connectorPoolID {
			foundToken = &allTokens[i]
			eaaclient.Logger.Info("=== TOKEN FOUND BY NAME AND CONNECTOR POOL ===")
			eaaclient.Logger.Info("Token Name:", foundToken.Name)
			eaaclient.Logger.Info("Token UUID:", foundToken.UUIDURL)
			eaaclient.Logger.Info("Token Value:", foundToken.Token)
			break
		}
	}
	
	if foundToken == nil {
		eaaclient.Logger.Error("=== TOKEN NOT FOUND BY NAME AND CONNECTOR POOL ===")
		eaaclient.Logger.Error("Searched for name:", tokenName)
		eaaclient.Logger.Error("Searched for connector pool:", connectorPoolID)
		eaaclient.Logger.Error("Available tokens:")
		for i, token := range allTokens {
			eaaclient.Logger.Error(fmt.Sprintf("  %d. Name: %s, UUID: %s, ConnectorPool: %s", i+1, token.Name, token.UUIDURL, token.ConnectorPool))
		}
		return diag.FromErr(fmt.Errorf("created token with name %s and connector pool %s not found in GET response", tokenName, connectorPoolID))
	}
	
	// Set the ID and all fields from the GET response
	d.SetId(foundToken.UUIDURL)
	d.Set("uuid_url", foundToken.UUIDURL)
	d.Set("token", foundToken.Token)
	d.Set("used_count", foundToken.UsedCount)
	d.Set("token_suffix", foundToken.TokenSuffix)
	d.Set("image_url", foundToken.ImageURL)
	d.Set("modified_at", foundToken.ModifiedAt)
	d.Set("agents", foundToken.Agents)
	
	// Store the full GET response as JSON
	getRespJson, _ := json.Marshal(foundToken)
	d.Set("registration_token_get_api_response", string(getRespJson))
	eaaclient.Logger.Info("Set registration_token_get_api_response from GET:", string(getRespJson))

	return nil
}

// resourceEaaRegistrationTokenRead function reads an existing EAA registration token.
func resourceEaaRegistrationTokenRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	id := d.Id()
	eaaclient := m.(*client.EaaClient)

	contract_id := eaaclient.ContractID
	connector_pool := d.Get("connector_pool").(string)

	// First try to get by UUID
	regToken, err := eaaclient.GetRegistrationTokenByUUID(id, connector_pool, contract_id)
	if err != nil {
		eaaclient.Logger.Error("Failed to get token by UUID:", err)
		
		// Fallback: get all tokens and find by name
		eaaclient.Logger.Info("Trying fallback: get all tokens and find by name")
		allTokens, err2 := eaaclient.GetRegistrationTokens(connector_pool, contract_id)
		if err2 != nil {
			return diag.FromErr(fmt.Errorf("failed to get registration tokens: %w", err2))
		}
		
		// Find the token by name
		tokenName := d.Get("name").(string)
		var foundToken *client.RegistrationToken
		
		for i := range allTokens {
			if allTokens[i].Name == tokenName {
				foundToken = &allTokens[i]
				break
			}
		}
		
		if foundToken == nil {
			return diag.FromErr(fmt.Errorf("registration token with name %s not found in connector pool %s", tokenName, connector_pool))
		}
		
		regToken = foundToken
		// Update the ID with the correct UUID
		d.SetId(regToken.UUIDURL)
	}

	// Set all the fields from the GET response
	d.Set("name", regToken.Name)
	d.Set("max_use", regToken.MaxUse)
	d.Set("expires_at", regToken.ExpiresAt)
	d.Set("connector_pool", regToken.ConnectorPool)
	d.Set("generate_embedded_img", regToken.GenerateEmbeddedImg)
	d.Set("uuid_url", regToken.UUIDURL)
	d.Set("token", regToken.Token)
	d.Set("used_count", regToken.UsedCount)
	d.Set("token_suffix", regToken.TokenSuffix)
	d.Set("image_url", regToken.ImageURL)
	d.Set("modified_at", regToken.ModifiedAt)
	d.Set("agents", regToken.Agents)

	// Store the full GET response as JSON for debugging
	getRespJson, _ := json.Marshal(regToken)
	d.Set("registration_token_get_api_response", string(getRespJson))
	eaaclient.Logger.Info("Set registration_token_get_api_response:", string(getRespJson))

	return nil
}

// resourceEaaRegistrationTokenUpdate updates an existing EAA registration token.
func resourceEaaRegistrationTokenUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	// Get the current registration token
	id := d.Id()
	contract_id := eaaclient.ContractID
	connector_pool := d.Get("connector_pool").(string)
	gid := ""
	regToken, err := eaaclient.GetRegistrationTokenByUUID(id, connector_pool, contract_id)
	if err != nil {
		logger.Error("get registration token failed. err ", err)
		return diag.FromErr(err)
	}

	// Update fields if they have changed
	if d.HasChange("name") {
		regToken.Name = d.Get("name").(string)
	}
	if d.HasChange("max_use") {
		regToken.MaxUse = d.Get("max_use").(int)
	}
	if d.HasChange("expires_at") {
		regToken.ExpiresAt = d.Get("expires_at").(string)
	}
	if d.HasChange("connector_pool") {
		regToken.ConnectorPool = d.Get("connector_pool").(string)
	}
	if d.HasChange("generate_embedded_img") {
		regToken.GenerateEmbeddedImg = d.Get("generate_embedded_img").(bool)
	}

	// Update the registration token
	err = regToken.UpdateRegistrationToken(ctx, eaaclient, contract_id, gid)
	if err != nil {
		logger.Error("update registration token failed. err ", err)
		return diag.FromErr(err)
	}

	return nil
}

// resourceEaaRegistrationTokenDelete deletes an existing EAA registration token.
func resourceEaaRegistrationTokenDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	id := d.Id()
	eaaclient := m.(*client.EaaClient)

	contract_id := eaaclient.ContractID

	err := client.DeleteRegistrationToken(ctx, eaaclient, id, contract_id, "")
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
} 