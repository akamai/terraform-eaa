package eaaprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ============================================================================
// COMMON VALIDATION FUNCTIONS
// ============================================================================

// validatePackageType validates package_type using client package constants
func validatePackageType(val interface{}, key string) (warns []string, errs []error) {
	valStr, ok := val.(string)
	if !ok {
		return nil, []error{fmt.Errorf("%s must be a string", key)}
	}

	validTypes := []string{
		string(client.ConnPackageTypeVmware),
		string(client.ConnPackageTypeVbox),
		string(client.ConnPackageTypeAWS),
		string(client.ConnPackageTypeKVM),
		string(client.ConnPackageTypeHyperv),
		string(client.ConnPackageTypeDocker),
		string(client.ConnPackageTypeAWSClassic),
		string(client.ConnPackageTypeAzure),
		string(client.ConnPackageTypeGoogle),
		string(client.ConnPackageTypeSoftLayer),
		string(client.ConnPackageTypeFujitsu_k5),
	}

	return client.ValidateStringInSlice(valStr, key, validTypes)
}

// validateInfraType validates infra_type using client package constants
func validateInfraType(val interface{}, key string) (warns []string, errs []error) {
	valStr, ok := val.(string)
	if !ok {
		return nil, []error{fmt.Errorf("%s must be a string", key)}
	}

	validTypes := []string{
		string(client.InfraTypeEAA),
		string(client.InfraTypeUnified),
		string(client.InfraTypeBroker),
		string(client.InfraTypeCPAG),
	}

	return client.ValidateStringInSlice(valStr, key, validTypes)
}

// validateOperatingMode validates operating_mode using client package constants
func validateOperatingMode(val interface{}, key string) (warns []string, errs []error) {
	valStr, ok := val.(string)
	if !ok {
		return nil, []error{fmt.Errorf("%s must be a string", key)}
	}

	validModes := []string{
		string(client.OperatingModeConnector),
		string(client.OperatingModePEB),
		string(client.OperatingModeCombined),
		string(client.OperatingModeCPAGPublic),
		string(client.OperatingModeCPAGPrivate),
		string(client.OperatingModeConnectorWithChinaAccel),
	}

	return client.ValidateStringInSlice(valStr, key, validModes)
}

// ============================================================================
// HELPER FUNCTIONS FOR RESOURCE OPERATIONS
// ============================================================================

// setConnectorPoolBasicAttributes sets the basic attributes of a connector pool in the schema
func setConnectorPoolBasicAttributes(d *schema.ResourceData, connPool *client.ConnectorPool) {
	client.SetConnectorPoolBasicAttributes(d, connPool)
}

var (
	ErrGetConnectorPool    = errors.New("connector pool get failed")
	ErrInvalidConnPoolData = errors.New("invalid connector pool data in schema")
)

func resourceEaaConnectorPool() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaConnectorPoolCreate,
		ReadContext:   resourceEaaConnectorPoolRead,
		UpdateContext: resourceEaaConnectorPoolUpdate,
		DeleteContext: resourceEaaConnectorPoolDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		SchemaVersion: 1,
		StateUpgraders: []schema.StateUpgrader{
			{
				Type:    resourceEaaConnectorPoolV0().CoreConfigSchema().ImpliedType(),
				Upgrade: client.ConnectorPoolStateUpgradeV0,
				Version: 0,
			},
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the connector pool (mandatory)",
			},
			"package_type": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Package type for the connector pool. Valid values: vmware, vbox, aws, kvm, hyperv, docker, aws_classic, azure, google, softlayer, fujitsu_k5",
				ValidateFunc: validatePackageType,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Description of the connector pool",
			},
			"infra_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Infrastructure type for the connector pool. Valid values: eaa, unified, broker, cpag",
				ValidateFunc: validateInfraType,
			},
			"operating_mode": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Operating mode for the connector pool. Valid values: connector, peb, combined, cpag_public, cpag_private, connector_with_china_acceleration",
				ValidateFunc: validateOperatingMode,
			},
			"uuid_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "UUID URL of the connector pool",
			},
			// Connectors in the pool
			"connectors": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of connector names that should be in the pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			// Registration tokens for the pool
			"registration_tokens": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of registration tokens for the connector pool",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"uuid_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "UUID URL of the registration token",
						},
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the registration token",
						},
						"max_use": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     1,
							Description: "Maximum number of times the token can be used (defaults to 1)",
							ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
								v := val.(int)
								if v < 1 {
									errs = append(errs, fmt.Errorf("%s must be greater than 0, got %d", key, v))
								}
								if v > 1000 {
									errs = append(errs, fmt.Errorf("%s cannot be greater than 1000, got %d", key, v))
								}
								return
							},
						},
						"connector_pool": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Connector pool UUID",
						},
						"agents": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"expires_in_days": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     1,
							Description: "Number of days from now until the token expires (defaults to 1)",
							ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
								v := val.(int)
								if v < 1 {
									errs = append(errs, fmt.Errorf("%s must be greater than 0, got %d", key, v))
								}
								if v > 700 {
									errs = append(errs, fmt.Errorf("%s cannot be greater than 700 days, got %d", key, v))
								}
								return
							},
						},
						"expires_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Expiration date in RFC3339 format from API response",
						},
						"image_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Image URL",
						},
						"token": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Token value",
						},
						"used_count": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Number of times the token has been used",
						},
						"token_suffix": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Token suffix",
						},
						"modified_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Last modification timestamp",
						},
						"generate_embedded_img": {
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     false,
							Description: "Whether to generate an embedded image for the token",
						},
					},
				},
			},
			// Apps assigned to this connector pool
			"apps": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of app names that should be assigned to this connector pool",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			// API response fields as individual computed fields
			"cidrs": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "CIDRs from API response",
			},
		},
	}
}

// resourceEaaConnectorPoolCreate function is responsible for creating a new EAA Connector Pool.
func resourceEaaConnectorPoolCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	e := hasDuplicateTokenNames(d)
	if e != nil {
		return diag.FromErr(e)
	}

	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	// Create the connector pool
	createRequest := &client.CreateConnectorPoolRequest{}
	err = createRequest.CreateConnectorPoolRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

			connPoolResp, err := createRequest.CreateConnectorPool(ctx, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set resource ID and basic attributes
	d.SetId(connPoolResp.UUIDURL)
	d.Set("uuid_url", connPoolResp.UUIDURL)
	d.Set("cidrs", connPoolResp.CIDRs)

	// Handle additional operations using helper functions
	if err := client.AssignConnectorsToPoolFromSchema(d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return diag.FromErr(err)
	}

	if err := client.CreateRegistrationTokensFromSchema(ctx, d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return diag.FromErr(err)
	}

	if err := client.AssignAppsToPoolFromSchema(d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return diag.FromErr(err)
	}

	return resourceEaaConnectorPoolRead(ctx, d, m)
}

// resourceEaaConnectorPoolRead function reads an existing EAA connector pool.
func resourceEaaConnectorPoolRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}

	connectorPoolUUID := d.Id()

	// Read connector pool details
	connPool, err := client.GetConnectorPool(ctx, eaaclient, connectorPoolUUID)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set basic connector pool attributes using helper function
	setConnectorPoolBasicAttributes(d, connPool)

	// Read connectors in the pool
	currentConnectors, err := client.GetConnectorNamesInPool(eaaclient, connectorPoolUUID)
	if err != nil {
		eaaclient.Logger.Error("Failed to get connectors in pool:", err)
	} else {
		var connectorsInterface []interface{}
		for _, connector := range currentConnectors {
			connectorsInterface = append(connectorsInterface, connector)
		}
		d.Set("connectors", connectorsInterface)
	}

	// Read registration tokens
	tokens, err := eaaclient.GetRegistrationTokens(connectorPoolUUID)
	if err != nil {
		eaaclient.Logger.Error("Failed to get registration tokens:", err)
	} else {
		// Debug: Print the full API response for registration tokens
		if b, err := json.MarshalIndent(tokens, "", "  "); err == nil {
			eaaclient.Logger.Info("API returned registration tokens:", string(b))
		}
		// Sort tokens by name to ensure consistent ordering
		sort.Slice(tokens, func(i, j int) bool {
			return tokens[i].Name < tokens[j].Name
		})

		var tokensInterface []interface{}
		for _, token := range tokens {
			// Convert RFC3339 date back to days from now
			expiresAtTime, err := time.Parse(time.RFC3339, token.ExpiresAt)
			var expiresInDays int
			if err == nil {
				now := time.Now().UTC()
				duration := expiresAtTime.Sub(now)
				expiresInDays = int(duration.Hours() / 24)
				if expiresInDays < 0 {
					expiresInDays = 0 // Handle expired tokens
				}
			} else {
				// If parsing fails, default to 1 day
				expiresInDays = 1
			}

			tokenMap := map[string]interface{}{
				"uuid_url":              token.UUIDURL,
				"name":                  token.Name,
				"max_use":               token.MaxUse,
				"connector_pool":        token.ConnectorPool,
				"agents":                token.Agents,
				"expires_in_days":       expiresInDays,   // Converted from RFC3339 to days
				"expires_at":            token.ExpiresAt, // Store the RFC3339 date from API response
				"image_url":             token.ImageURL,
				"token":                 token.Token,
				"used_count":            token.UsedCount,
				"token_suffix":          token.TokenSuffix,
				"modified_at":           token.ModifiedAt,
				"generate_embedded_img": token.GenerateEmbeddedImg, // Use API response value
			}

			tokensInterface = append(tokensInterface, tokenMap)
		}
		d.Set("registration_tokens", tokensInterface)
	}

	// Read apps assigned to this connector pool
	currentApps, err := client.GetAppNamesAssignedToPool(eaaclient, connectorPoolUUID)
	if err != nil {
		eaaclient.Logger.Error("Failed to get apps assigned to pool:", err)
		// Set empty list if we can't get current apps
		currentApps = []string{}
	}

	var appsInterface []interface{}
	for _, app := range currentApps {
		appsInterface = append(appsInterface, app)
	}
	d.Set("apps", appsInterface)

	// Preserve api_create_response if it exists (don't overwrite it during read)
	// The api_create_response is only set during creation and should be preserved

	return nil
}

// resourceEaaConnectorPoolUpdate updates an existing EAA connector pool.
func resourceEaaConnectorPoolUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	e := hasDuplicateTokenNames(d)
	if e != nil {
		return diag.FromErr(e)
	}

	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	connectorPoolUUID := d.Id()

	// Update basic connector pool attributes
	if d.HasChanges("name", "description", "package_type", "infra_type", "operating_mode") {
		updateRequest := &client.CreateConnectorPoolRequest{}
		err = updateRequest.CreateConnectorPoolRequestFromSchema(ctx, d, eaaclient)
		if err != nil {
			return diag.FromErr(err)
		}

		// Update the connector pool using PUT
		apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.CONNECTOR_POOLS_URL, connectorPoolUUID)

		logger.Info("Updating connector pool with URL:", apiURL)

		// Log the actual JSON that will be sent
		jsonData, _ := json.Marshal(updateRequest)
		logger.Info("Update request JSON body:", string(jsonData))

		resp, err := eaaclient.SendAPIRequest(apiURL, "PUT", updateRequest, nil, false)
		if err != nil {
			logger.Error("Update API request failed:", err)
			return diag.FromErr(err)
		}

		logger.Info("Update response status:", resp.StatusCode)

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc, _ := client.FormatErrorResponse(resp)
			updateErrMsg := fmt.Errorf("connector pool update failed: %s", desc)
			logger.Error("Update failed with status:", resp.StatusCode, "error:", desc)
			return diag.FromErr(updateErrMsg)
		}
	}

	// Handle connector associations
	if d.HasChange("connectors") {
		// Get current connectors from the API
		currConnectors, err := client.GetConnectorNamesInPool(eaaclient, connectorPoolUUID)
		if err != nil {
			logger.Error("Failed to get current connectors in pool:", err)
			return diag.FromErr(fmt.Errorf("failed to get current connectors in pool: %w", err))
		}

		// Get desired connectors from configuration
		connectorsRaw := d.Get("connectors")
		connectorList := connectorsRaw.([]interface{})
		var desiredConnectors []string
		for _, connector := range connectorList {
			if str, ok := connector.(string); ok {
				desiredConnectors = append(desiredConnectors, str)
			}
		}

		// Calculate differences using the same logic as agents
		connectorsToAssign := client.DifferenceIgnoreCase(desiredConnectors, currConnectors)
		connectorsToUnassign := client.DifferenceIgnoreCase(currConnectors, desiredConnectors)

		// Assign new connectors
		if len(connectorsToAssign) > 0 {
			err = client.AssignConnectorsToPoolByName(eaaclient, connectorPoolUUID, connectorsToAssign)
			if err != nil {
				return diag.FromErr(fmt.Errorf("failed to assign new connectors to pool: %w", err))
			}
		}

		// Unassign removed connectors
		if len(connectorsToUnassign) > 0 {
			err = client.UnassignConnectorsFromPoolByName(eaaclient, connectorPoolUUID, connectorsToUnassign)
			if err != nil {
				return diag.FromErr(fmt.Errorf("failed to unassign connectors from pool: %w", err))
			}
		}
	}

	// Handle registration tokens
	if d.HasChange("registration_tokens") {
		_, newTokensInterface := d.GetChange("registration_tokens")

		// Get existing tokens from the API
		existingTokens, err := eaaclient.GetRegistrationTokens(connectorPoolUUID)
		if err != nil {
			logger.Error("Failed to get existing registration tokens:", err)
			return diag.FromErr(fmt.Errorf("failed to get existing registration tokens: %w", err))
		}

		// Create a map of existing tokens by name for easy lookup (for this pool only)
		existingTokensMap := make(map[string]*client.RegistrationToken)
		for i := range existingTokens {
			existingTokensMap[existingTokens[i].Name] = &existingTokens[i]
		}

		// Get new token names from configuration
		newTokens := newTokensInterface.([]interface{})
		newTokenNames := make(map[string]bool)

		for _, tokenInterface := range newTokens {
			tokenData := tokenInterface.(map[string]interface{})
			tokenName := tokenData["name"].(string)
			newTokenNames[tokenName] = true

			// Check if token already exists
			if _, exists := existingTokensMap[tokenName]; exists {
				logger.Info("Token already exists, skipping creation:", tokenName)
				continue
			}

			// Create new token
			logger.Info("Creating registration token:", tokenName)

			// Create token request with values - validation is handled by Terraform schema
			// and the client layer will perform additional validation if needed
			expiresInDays := tokenData["expires_in_days"].(int)
			now := time.Now().UTC()
			expiresAt := now.AddDate(0, 0, expiresInDays)

			createTokenRequest := client.CreateRegistrationTokenRequest{
				Name:                tokenData["name"].(string),
				MaxUse:              tokenData["max_use"].(int),
				ExpiresAt:           expiresAt.Format(time.RFC3339),
				ConnectorPool:       connectorPoolUUID,
				GenerateEmbeddedImg: tokenData["generate_embedded_img"].(bool),
			}
			_, err = createTokenRequest.CreateRegistrationToken(ctx, eaaclient)
			if err != nil {
				logger.Error("Failed to create registration token:", err)
				return diag.FromErr(fmt.Errorf("failed to create registration token: %w", err))
			}
		}
		// Delete tokens that are no longer in the configuration
		for tokenName, existingToken := range existingTokensMap {
			if !newTokenNames[tokenName] {
				logger.Info("Deleting registration token that is no longer in configuration:", tokenName)
				err = client.DeleteRegistrationTokenByUUID(ctx, eaaclient, existingToken.UUIDURL)
				if err != nil {
					logger.Error("Failed to delete registration token:", err)
					return diag.FromErr(fmt.Errorf("failed to delete registration token: %w", err))
				}
			}
		}
	}

	// Handle app assignments
	if appsRaw, ok := d.GetOk("apps"); ok {
		appsList := appsRaw.([]interface{})
		var desiredApps []string
		for _, app := range appsList {
			if str, ok := app.(string); ok {
				desiredApps = append(desiredApps, str)
			}
		}

		// Get current apps assigned to this pool
		currApps, err := client.GetAppNamesAssignedToPool(eaaclient, connectorPoolUUID)
		if err != nil {
			logger.Error("Failed to get current apps assigned to pool:", err)
			// Continue with empty list if we can't get current apps
			currApps = []string{}
		}

		// Calculate differences
		appsToAssign := client.DifferenceIgnoreCase(desiredApps, currApps)
		appsToUnassign := client.DifferenceIgnoreCase(currApps, desiredApps)

		// Assign new apps
		if len(appsToAssign) > 0 {
			logger.Info("Assigning apps to connector pool:", appsToAssign)
			err = client.AssignConnectorPoolToApps(eaaclient, connectorPoolUUID, appsToAssign)
			if err != nil {
				logger.Error("Failed to assign apps to connector pool:", err)
				return diag.FromErr(fmt.Errorf("failed to assign apps to connector pool: %w", err))
			}
		}

		// Unassign removed apps
		if len(appsToUnassign) > 0 {
			logger.Info("Unassigning apps from connector pool:", appsToUnassign)
			err = client.UnassignConnectorPoolFromApps(eaaclient, connectorPoolUUID, appsToUnassign)
			if err != nil {
				logger.Error("Failed to unassign apps from connector pool:", err)
				return diag.FromErr(fmt.Errorf("failed to unassign apps from connector pool: %w", err))
			}
		}
	} else {
		// If apps is not set in configuration, unassign all apps
		logger.Info("No apps specified in configuration, unassigning all apps from connector pool")

		// Get current apps assigned to this pool
		currApps, err := client.GetAppNamesAssignedToPool(eaaclient, connectorPoolUUID)
		if err != nil {
			logger.Error("Failed to get current apps assigned to pool:", err)
			// Continue with empty list if we can't get current apps
			currApps = []string{}
		}

		// Unassign all current apps
		if len(currApps) > 0 {
			logger.Info("Unassigning all apps from connector pool:", currApps)
			err = client.UnassignConnectorPoolFromApps(eaaclient, connectorPoolUUID, currApps)
			if err != nil {
				logger.Error("Failed to unassign all apps from connector pool:", err)
				return diag.FromErr(fmt.Errorf("failed to unassign all apps from connector pool: %w", err))
			}
		}
	}

	return resourceEaaConnectorPoolRead(ctx, d, m)
}

// resourceEaaConnectorPoolDelete deletes an existing EAA connector pool.
func resourceEaaConnectorPoolDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	id := d.Id()
	logger.Info(fmt.Sprintf("Destroying connector pool with ID: %s", id))
	
	// STEP 1: Disassociate APPS first (must be done before connectors)
	logger.Info("Step 1: Disassociating apps from pool before deletion")
	currentApps, err := client.GetAppNamesAssignedToPool(eaaclient, id)  // Fixed: Use names, not UUIDs
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to get current apps assigned to pool: %v", err))
		// Continue with deletion even if we can't get current apps
	} else if len(currentApps) > 0 {
		logger.Info(fmt.Sprintf("Disassociating apps from pool: %v", currentApps))
		
		// Disassociate all current apps from the pool
		err = client.UnassignConnectorPoolFromApps(eaaclient, id, currentApps)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to disassociate apps from pool: %v", err))
			// Continue with deletion even if disassociation fails
			// The API might handle this automatically
		} else {
			logger.Info("Successfully disassociated apps from pool")
		}
	} else {
		logger.Info("No apps currently assigned to pool")
	}
	
	// STEP 2: Disassociate CONNECTORS second (after apps are removed)
	logger.Info("Step 2: Disassociating connectors from pool before deletion")
	currentConnectors, err := client.GetConnectorNamesInPool(eaaclient, id)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to get current connectors in pool: %v", err))
		// Continue with deletion even if we can't get current connectors
	} else if len(currentConnectors) > 0 {
		logger.Info(fmt.Sprintf("Found %d connectors to disassociate: %v", len(currentConnectors), currentConnectors))

		// Disassociate all current connectors from the pool
		logger.Info("Calling UnassignConnectorsFromPoolByName...")
		err = client.UnassignConnectorsFromPoolByName(eaaclient, id, currentConnectors)
		if err != nil {
			logger.Error(fmt.Sprintf("FAILED to disassociate connectors from pool: %v", err))
			logger.Error("This is likely due to EAA business rules preventing connector disassociation")
			logger.Error("The pool cannot be deleted while connectors are present")
			// Don't continue - we need to stop here since connectors can't be removed
			return diag.Errorf("cannot destroy connector pool: connectors cannot be disassociated due to EAA business rules: %v", err)
		} else {
			logger.Info("Successfully disassociated connectors from pool")
		}
	} else {
		logger.Info("No connectors currently in pool")
	}

	// STEP 3: Verify that all resources are actually disassociated
	logger.Info("Step 3: Verifying all resources are disassociated before deletion")
	
	// Add a small delay to allow API state to sync
	logger.Info("Waiting 2 seconds for API state to sync...")
	time.Sleep(2 * time.Second)
	
	// Verify apps are disassociated
	currentAppsAfter, err := client.GetAppNamesAssignedToPool(eaaclient, id)  // Fixed: Use names, not UUIDs
	if err == nil && len(currentAppsAfter) > 0 {
		logger.Warn("Apps still assigned after disassociation:", currentAppsAfter)
	} else {
		logger.Info("Apps successfully disassociated")
	}
	
	// Verify connectors are disassociated
	currentConnectorsAfter, err := client.GetConnectorNamesInPool(eaaclient, id)
	if err == nil && len(currentConnectorsAfter) > 0 {
		logger.Warn(fmt.Sprintf("Connectors still in pool after disassociation: %v", currentConnectorsAfter))
	} else {
		logger.Info("Connectors successfully disassociated")
	}
	
	// STEP 4: Now delete the empty connector pool
	logger.Info("Step 4: Deleting empty connector pool")
	err = client.DeleteConnectorPool(ctx, eaaclient, id)
	if err != nil {
		logger.Error("delete connector pool failed. err ", err)
		return diag.FromErr(err)
	}

	logger.Info("Successfully deleted connector pool")
	logger.Info("Successfully deleted connector pool")
	d.SetId("")
	return nil
}

// State migration functions for schema version 1
func resourceEaaConnectorPoolV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"package_type": {
				Type:     schema.TypeInt,
				Required: true,
			},
			"infra_type": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"operating_mode": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"connectors": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"apps": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"registration_tokens": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"max_use": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"expires_in_days": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"generate_embedded_img": {
							Type:     schema.TypeBool,
							Required: true,
						},
					},
				},
			},
			"uuid_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}



// hasDuplicateTokenNames checks for duplicate registration token names
func hasDuplicateTokenNames(d *schema.ResourceData) error {
	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return nil
	}
	nameSet := make(map[string]struct{})
	for _, tokenInterface := range tokens.([]interface{}) {
		tokenData := tokenInterface.(map[string]interface{})
		name := tokenData["name"].(string)
		if _, exists := nameSet[name]; exists {
			return fmt.Errorf("duplicate registration token name found: %s. Each registration token name must be unique within the connector pool", name)
		}
		nameSet[name] = struct{}{}
	}
	return nil
}
