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

func validateRFC3339Timestamp(val interface{}, key string) (warns []string, errs []error) {
	valStr, ok := val.(string)
	if !ok {
		return nil, []error{fmt.Errorf("%s must be a string", key)}
	}

	if _, err := time.Parse(time.RFC3339Nano, valStr); err != nil {
		return nil, []error{fmt.Errorf("%s must be a valid RFC3339 timestamp (e.g. 2026-01-02T15:04:05Z): %w", key, err)}
	}

	return nil, nil
}

func suppressRFC3339Diff(_, old, newValue string, _ *schema.ResourceData) bool {
	// Normalise both sides the same way FormatExpiresAt does (bumps :00 seconds
	// to :01 and converts to UTC) so plan diffs are suppressed for equivalent timestamps.
	normOld, errOld := client.FormatExpiresAt(old)
	normNew, errNew := client.FormatExpiresAt(newValue)
	if errOld != nil || errNew != nil {
		return false
	}
	return normOld == normNew
}

func formatRFC3339Timestamp(value string) (string, error) {
	return client.FormatExpiresAt(value)
}

// ============================================================================
// HELPER FUNCTIONS FOR RESOURCE OPERATIONS
// ============================================================================

// setConnectorPoolBasicAttributes sets the basic attributes of a connector pool in the schema
func setConnectorPoolBasicAttributes(d *schema.ResourceData, connPool *client.ConnectorPool) error {
	return client.SetConnectorPoolBasicAttributes(d, connPool)
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

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the connector pool (mandatory)",
			},
			"package_type": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Package type for the connector pool. Valid values: vmware, vbox, aws, kvm, hyperv, docker, azure, google, softlayer, fujitsu_k5. Note: aws_classic is no longer supported for new resources; use aws instead.",
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
				Computed:     true,
				Description:  "Infrastructure type for the connector pool. Valid values: eaa, unified, broker, cpag",
				ValidateFunc: validateInfraType,
			},
			"operating_mode": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
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
								v, ok := val.(int)
								if !ok {
									errs = append(errs, fmt.Errorf("%s must be an integer", key))
									return
								}
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
						"expires_at": {
							Type:             schema.TypeString,
							Required:         true,
							Description:      "Expiration date in RFC3339 format (e.g. 2026-01-02T15:04:05Z)",
							ValidateFunc:     validateRFC3339Timestamp,
							DiffSuppressFunc: suppressRFC3339Diff,
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
				Type:        schema.TypeList,
				Computed:    true,
				Description: "CIDRs from API response",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

// resourceEaaConnectorPoolCreate function is responsible for creating a new EAA Connector Pool.
func resourceEaaConnectorPoolCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if v, ok := d.GetOk("package_type"); ok {
		if pkgType, isStr := v.(string); isStr && pkgType == string(client.ConnPackageTypeAWSClassic) {
			return diag.Errorf("\"aws_classic\" is no longer supported for new connector pools, please use \"aws\" instead")
		}
	}

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
		return diag.FromErr(fmt.Errorf("failed to build connector pool create request: %w", err))
	}

	connPoolResp, err := createRequest.CreateConnectorPool(ctx, eaaclient)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to create connector pool: %w", err))
	}

	// Set resource ID and basic attributes
	d.SetId(connPoolResp.UUIDURL)
	if err := d.Set("uuid_url", connPoolResp.UUIDURL); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set uuid_url: %w", err))
	}
	if err := d.Set("cidrs", connPoolResp.CIDRs); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set cidrs: %w", err))
	}

	// Handle additional operations using helper functions
	if err := client.AssignConnectorsToPoolFromSchema(d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return diag.FromErr(fmt.Errorf("failed to assign connectors to pool: %w", err))
	}

	if err := client.CreateRegistrationTokensFromSchema(ctx, d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return diag.FromErr(fmt.Errorf("failed to create registration tokens: %w", err))
	}

	if err := client.AssignAppsToPoolFromSchema(d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return diag.FromErr(fmt.Errorf("failed to assign apps to pool: %w", err))
	}

	return resourceEaaConnectorPoolRead(ctx, d, m)
}

// resourceEaaConnectorPoolRead function reads an existing EAA connector pool.
func resourceEaaConnectorPoolRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	var readDiags diag.Diagnostics

	connectorPoolUUID := d.Id()

	// Read connector pool details
	connPool, err := client.GetConnectorPool(ctx, eaaclient, connectorPoolUUID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read connector pool %s: %w", connectorPoolUUID, err))
	}

	// Set basic connector pool attributes using helper function
	setErr := setConnectorPoolBasicAttributes(d, connPool)
	if setErr != nil {
		return diag.FromErr(fmt.Errorf("failed to set connector pool attributes: %w", setErr))
	}

	// Read connectors in the pool
	currentConnectors, err := client.GetConnectorNamesInPool(eaaclient, connectorPoolUUID)
	if err != nil {
		eaaclient.Logger.Error("Failed to get connectors in pool", "error", err)
		readDiags = append(readDiags, diag.FromErr(fmt.Errorf("failed to get connectors in pool: %w", err))...)
	} else {
		var connectorsInterface []interface{}
		for _, connector := range currentConnectors {
			connectorsInterface = append(connectorsInterface, connector)
		}
		setConnectorsErr := d.Set("connectors", connectorsInterface)
		if setConnectorsErr != nil {
			readDiags = append(readDiags, diag.FromErr(fmt.Errorf("failed to set connectors: %w", setConnectorsErr))...)
		}
	}

	// Read registration tokens
	tokens, err := eaaclient.GetRegistrationTokens(connectorPoolUUID)
	if err != nil {
		eaaclient.Logger.Error("Failed to get registration tokens", "error", err)
		readDiags = append(readDiags, diag.FromErr(fmt.Errorf("failed to get registration tokens: %w", err))...)
	} else {
		// Debug: Print the full API response for registration tokens
		if b, marshalErr := json.MarshalIndent(tokens, "", "  "); marshalErr == nil {
			eaaclient.Logger.Info("API returned registration tokens:", string(b))
		}
		// Sort tokens by name to ensure consistent ordering
		sort.Slice(tokens, func(i, j int) bool {
			return tokens[i].Name < tokens[j].Name
		})

		var tokensInterface []interface{}
		for i := range tokens {
			token := &tokens[i]
			formattedExpiresAt, formatErr := formatRFC3339Timestamp(token.ExpiresAt)
			if formatErr != nil {
				return diag.FromErr(fmt.Errorf("registration token %q has invalid expires_at value %q: %w", token.Name, token.ExpiresAt, formatErr))
			}

			tokenMap := map[string]interface{}{
				"uuid_url":              token.UUIDURL,
				"name":                  token.Name,
				"max_use":               token.MaxUse,
				"connector_pool":        token.ConnectorPool,
				"agents":                token.Agents,
				"expires_at":            formattedExpiresAt,
				"image_url":             token.ImageURL,
				"token":                 token.Token,
				"used_count":            token.UsedCount,
				"token_suffix":          token.TokenSuffix,
				"modified_at":           token.ModifiedAt,
				"generate_embedded_img": token.GenerateEmbeddedImg, // Use API response value
			}

			tokensInterface = append(tokensInterface, tokenMap)
		}
		setTokensErr := d.Set("registration_tokens", tokensInterface)
		if setTokensErr != nil {
			readDiags = append(readDiags, diag.FromErr(fmt.Errorf("failed to set registration_tokens: %w", setTokensErr))...)
		}
	}

	// Read apps assigned to this connector pool
	currentApps, err := client.GetAppNamesAssignedToPool(eaaclient, connectorPoolUUID)
	if err != nil {
		eaaclient.Logger.Error("Failed to get apps assigned to pool", "error", err)
		readDiags = append(readDiags, diag.FromErr(fmt.Errorf("failed to get apps assigned to pool: %w", err))...)
	} else {
		var appsInterface []interface{}
		for _, app := range currentApps {
			appsInterface = append(appsInterface, app)
		}
		if err := d.Set("apps", appsInterface); err != nil {
			readDiags = append(readDiags, diag.FromErr(fmt.Errorf("failed to set apps: %w", err))...)
		}
	}

	return readDiags
}

// resourceEaaConnectorPoolUpdate updates an existing EAA connector pool.
func resourceEaaConnectorPoolUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChange("package_type") {
		if v, ok := d.GetOk("package_type"); ok {
			if pkgType, isStr := v.(string); isStr && pkgType == string(client.ConnPackageTypeAWSClassic) {
				return diag.Errorf("\"aws_classic\" is no longer supported, please use \"aws\" instead")
			}
		}
	}

	e := hasDuplicateTokenNames(d)
	if e != nil {
		return diag.FromErr(e)
	}

	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger
	var updateDiags diag.Diagnostics

	connectorPoolUUID := d.Id()

	// Update basic connector pool attributes
	if d.HasChanges("name", "description", "package_type", "infra_type", "operating_mode") {
		updateRequest := &client.CreateConnectorPoolRequest{}
		err = updateRequest.CreateConnectorPoolRequestFromSchema(ctx, d, eaaclient)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to build connector pool update request: %w", err))
		}

		// Update the connector pool using PUT
		apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.CONNECTOR_POOLS_URL, connectorPoolUUID)

		logger.Info("updating connector pool", "url", apiURL)

		// Log the actual JSON that will be sent
		jsonData, err := json.Marshal(updateRequest)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to marshal connector pool update request: %w", err))
		}
		logger.Info("update request JSON body", "body", string(jsonData))

		resp, err := eaaclient.SendAPIRequest(apiURL, "PUT", updateRequest, nil, false)
		if err != nil {
			logger.Error("update API request failed", "error", err)
			return diag.FromErr(fmt.Errorf("connector pool update API request failed: %w", err))
		}

		logger.Info("update response status", "status", resp.StatusCode)

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc := client.FormatErrorDescription(resp)
			updateErrMsg := fmt.Errorf("connector pool update failed: %s", desc)
			logger.Error("update failed", "status", resp.StatusCode, "error", desc)
			return diag.FromErr(updateErrMsg)
		}
	}

	// Handle connector associations
	if d.HasChange("connectors") {
		// Get current connectors from the API
		currConnectors, err := client.GetConnectorNamesInPool(eaaclient, connectorPoolUUID)
		if err != nil {
			logger.Error("failed to get current connectors in pool", "error", err)
			return diag.FromErr(fmt.Errorf("failed to get current connectors in pool: %w", err))
		}

		// Get desired connectors from configuration
		connectorsRaw := d.Get("connectors")
		connectorList, ok := connectorsRaw.([]interface{})
		if !ok {
			return diag.FromErr(fmt.Errorf("connectors: %w", ErrInvalidData))
		}
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
			logger.Error("failed to get existing registration tokens", "error", err)
			return diag.FromErr(fmt.Errorf("failed to get existing registration tokens: %w", err))
		}

		// Create a map of existing tokens by name for easy lookup (for this pool only)
		existingTokensMap := make(map[string]*client.RegistrationToken)
		for i := range existingTokens {
			existingTokensMap[existingTokens[i].Name] = &existingTokens[i]
		}

		// Get new token names from configuration
		newTokens, ok := newTokensInterface.([]interface{})
		if !ok {
			return diag.FromErr(fmt.Errorf("registration_tokens must be a list, got %T", newTokensInterface))
		}
		newTokenNames := make(map[string]bool)

		for _, tokenInterface := range newTokens {
			tokenData, ok := tokenInterface.(map[string]interface{})
			if !ok {
				return diag.FromErr(fmt.Errorf("registration token must be an object, got %T", tokenInterface))
			}
			tokenName, ok := tokenData["name"].(string)
			if !ok || tokenName == "" {
				return diag.FromErr(fmt.Errorf("registration token 'name' must be a non-empty string, got %T", tokenData["name"]))
			}
			newTokenNames[tokenName] = true

			expiresAtRaw, ok := tokenData["expires_at"].(string)
			if !ok {
				return diag.FromErr(fmt.Errorf("registration token 'expires_at' must be a string, got %T", tokenData["expires_at"]))
			}
			expiresAt, formatErr := formatRFC3339Timestamp(expiresAtRaw)
			if formatErr != nil {
				return diag.FromErr(fmt.Errorf("invalid registration token expires_at %q for token %q: %w", expiresAtRaw, tokenName, formatErr))
			}
			maxUse, ok := tokenData["max_use"].(int)
			if !ok {
				return diag.FromErr(fmt.Errorf("registration token 'max_use' must be an integer, got %T", tokenData["max_use"]))
			}
			generateEmbeddedImg, ok := tokenData["generate_embedded_img"].(bool)
			if !ok {
				return diag.FromErr(fmt.Errorf("registration token 'generate_embedded_img' must be a boolean, got %T", tokenData["generate_embedded_img"]))
			}
			if existingToken, exists := existingTokensMap[tokenName]; exists {
				logger.Info("token exists, updating", "token", tokenName)
				updateReq := &client.RegistrationTokenWriteRequest{
					Name:                tokenName,
					MaxUse:              maxUse,
					ExpiresAt:           expiresAt,
					ConnectorPool:       connectorPoolUUID,
					GenerateEmbeddedImg: generateEmbeddedImg,
				}
				err = client.UpdateRegistrationToken(ctx, eaaclient, existingToken.UUIDURL, updateReq)
				if err != nil {
					logger.Error("failed to update registration token", "error", err)
					return diag.FromErr(fmt.Errorf("failed to update registration token %q: %w", tokenName, err))
				}
				continue
			}

			logger.Info("creating registration token", "token", tokenName)
			createTokenRequest := client.RegistrationTokenWriteRequest{
				Name:                tokenName,
				MaxUse:              maxUse,
				ExpiresAt:           expiresAt,
				ConnectorPool:       connectorPoolUUID,
				GenerateEmbeddedImg: generateEmbeddedImg,
			}
			_, err = createTokenRequest.CreateRegistrationToken(ctx, eaaclient)
			if err != nil {
				logger.Error("failed to create registration token", "error", err)
				return diag.FromErr(fmt.Errorf("failed to create registration token: %w", err))
			}
		}
		// Delete tokens that are no longer in the configuration
		for tokenName, existingToken := range existingTokensMap {
			if !newTokenNames[tokenName] {
				logger.Info("deleting registration token no longer in configuration", "token", tokenName)
				err = client.DeleteRegistrationTokenByUUID(ctx, eaaclient, existingToken.UUIDURL)
				if err != nil {
					logger.Error("failed to delete registration token", "error", err)
					return diag.FromErr(fmt.Errorf("failed to delete registration token: %w", err))
				}
			}
		}
	}

	// Handle app assignments
	if appsRaw, ok := d.GetOk("apps"); ok {
		appsList, ok := appsRaw.([]interface{})
		if !ok {
			return diag.FromErr(fmt.Errorf("apps: %w", ErrInvalidData))
		}
		var desiredApps []string
		for _, app := range appsList {
			if str, ok := app.(string); ok {
				desiredApps = append(desiredApps, str)
			}
		}

		// Get current apps assigned to this pool
		currApps, err := client.GetAppNamesAssignedToPool(eaaclient, connectorPoolUUID)
		if err != nil {
			logger.Error("failed to get current apps assigned to pool", "error", err)
			updateDiags = append(updateDiags, diag.FromErr(fmt.Errorf("failed to get current apps assigned to pool: %w", err))...)
		} else {
			// Calculate differences
			appsToAssign := client.DifferenceIgnoreCase(desiredApps, currApps)
			appsToUnassign := client.DifferenceIgnoreCase(currApps, desiredApps)

			// Assign new apps
			if len(appsToAssign) > 0 {
				logger.Info("assigning apps to connector pool", "apps", appsToAssign)
				err = client.AssignConnectorPoolToApps(eaaclient, connectorPoolUUID, appsToAssign)
				if err != nil {
					logger.Error("failed to assign apps to connector pool", "error", err)
					return diag.FromErr(fmt.Errorf("failed to assign apps to connector pool: %w", err))
				}
			}

			// Unassign removed apps
			if len(appsToUnassign) > 0 {
				logger.Info("unassigning apps from connector pool", "apps", appsToUnassign)
				err = client.UnassignConnectorPoolFromApps(eaaclient, connectorPoolUUID, appsToUnassign)
				if err != nil {
					logger.Error("failed to unassign apps from connector pool", "error", err)
					return diag.FromErr(fmt.Errorf("failed to unassign apps from connector pool: %w", err))
				}
			}
		}
	} else {
		// If apps is not set in configuration, unassign all apps
		logger.Info("No apps specified in configuration, unassigning all apps from connector pool")

		// Get current apps assigned to this pool
		currApps, err := client.GetAppNamesAssignedToPool(eaaclient, connectorPoolUUID)
		if err != nil {
			logger.Error("failed to get current apps assigned to pool", "error", err)
			updateDiags = append(updateDiags, diag.FromErr(fmt.Errorf("failed to get current apps assigned to pool: %w", err))...)
		} else if len(currApps) > 0 {
			// Unassign all current apps
			logger.Info("unassigning all apps from connector pool", "apps", currApps)
			err = client.UnassignConnectorPoolFromApps(eaaclient, connectorPoolUUID, currApps)
			if err != nil {
				logger.Error("failed to unassign all apps from connector pool", "error", err)
				return diag.FromErr(fmt.Errorf("failed to unassign all apps from connector pool: %w", err))
			}
		}
	}

	return append(updateDiags, resourceEaaConnectorPoolRead(ctx, d, m)...)
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
	currentApps, err := client.GetAppNamesAssignedToPool(eaaclient, id) // Fixed: Use names, not UUIDs
	switch {
	case err != nil:
		logger.Error(fmt.Sprintf("Failed to get current apps assigned to pool: %v", err))
		// Continue with deletion even if we can't get current apps
	case len(currentApps) == 0:
		logger.Info("No apps currently assigned to pool")
	default:
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
	}

	// STEP 2: Disassociate CONNECTORS second (after apps are removed)
	logger.Info("Step 2: Disassociating connectors from pool before deletion")
	currentConnectors, err := client.GetConnectorNamesInPool(eaaclient, id)
	switch {
	case err != nil:
		logger.Error(fmt.Sprintf("Failed to get current connectors in pool: %v", err))
		// Continue with deletion even if we can't get current connectors
	case len(currentConnectors) == 0:
		logger.Info("No connectors currently in pool")
	default:
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
		}
		logger.Info("Successfully disassociated connectors from pool")
	}

	// STEP 3: Verify that all resources are actually disassociated
	logger.Info("Step 3: Verifying all resources are disassociated before deletion")

	// Add a small delay to allow API state to sync
	logger.Info("Waiting 2 seconds for API state to sync...")
	time.Sleep(2 * time.Second)

	// Verify apps are disassociated
	currentAppsAfter, err := client.GetAppNamesAssignedToPool(eaaclient, id) // Fixed: Use names, not UUIDs
	if err == nil && len(currentAppsAfter) > 0 {
		logger.Warn("apps still assigned after disassociation", "apps", currentAppsAfter)
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
		logger.Error("delete connector pool failed", "error", err)
		return diag.FromErr(fmt.Errorf("failed to delete connector pool %s: %w", id, err))
	}

	logger.Info("Successfully deleted connector pool")
	logger.Info("Successfully deleted connector pool")
	d.SetId("")
	return nil
}

// hasDuplicateTokenNames checks for duplicate registration token names
func hasDuplicateTokenNames(d *schema.ResourceData) error {
	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return nil
	}
	nameSet := make(map[string]struct{})
	tokenList, ok := tokens.([]interface{})
	if !ok {
		return fmt.Errorf("registration_tokens: %w", ErrInvalidData)
	}
	for _, tokenInterface := range tokenList {
		tokenData, ok := tokenInterface.(map[string]interface{})
		if !ok {
			return fmt.Errorf("registration_tokens entry: %w", ErrInvalidData)
		}
		name, ok := tokenData["name"].(string)
		if !ok {
			return fmt.Errorf("registration_tokens name: %w", ErrInvalidData)
		}
		if _, exists := nameSet[name]; exists {
			return fmt.Errorf("duplicate registration token name found: %s. Each registration token name must be unique within the connector pool", name)
		}
		nameSet[name] = struct{}{}
	}
	return nil
}
