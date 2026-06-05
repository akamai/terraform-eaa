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
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

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
				Description:  "Infrastructure type for the connector pool. Valid values: eaa, unified, broker, cpag. Note: the EAA API requires cpag to be paired with operating_mode cpag_public or cpag_private.",
				ValidateFunc: validateInfraType,
			},
			"operating_mode": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "Operating mode for the connector pool. Valid values: connector, peb, combined, cpag_public, cpag_private, connector_with_china_acceleration. Note: the EAA API requires cpag_public and cpag_private to be paired with infra_type cpag.",
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
	tags := []logging.Tag{logging.TagProvider, logging.TagConnPool, logging.TagCreate}
	logging.Info(ctx, "creating connector pool", tags)

	if v, ok := d.GetOk("package_type"); ok {
		if pkgType, isStr := v.(string); isStr && pkgType == string(client.ConnPackageTypeAWSClassic) {
			return logging.DiagErrorf(tags, "\"aws_classic\" is no longer supported for new connector pools, please use \"aws\" instead")
		}
	}

	e := hasDuplicateTokenNames(d)
	if e != nil {
		return logging.DiagFromErr(e, tags, "duplicate token names")
	}

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Create the connector pool
	createRequest := &client.CreateConnectorPoolRequest{}
	err = createRequest.CreateConnectorPoolRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return logging.DiagFromErrf(err, tags, "failed to build connector pool create request")
	}

	connPoolResp, err := createRequest.CreateConnectorPool(ctx, eaaclient)
	if err != nil {
		logging.Warn(ctx, "connector pool create failed", tags, map[string]any{"error": err.Error()})
		return logging.DiagFromErrf(err, tags, "connector pool create failed")
	}

	logging.Info(ctx, "connector pool created", tags, map[string]any{"uuid": connPoolResp.UUIDURL})

	// Set resource ID and basic attributes
	d.SetId(connPoolResp.UUIDURL)
	if err := d.Set("uuid_url", connPoolResp.UUIDURL); err != nil {
		return logging.DiagFromErrf(err, tags, "failed to set uuid_url")
	}
	if err := d.Set("cidrs", connPoolResp.CIDRs); err != nil {
		return logging.DiagFromErrf(err, tags, "failed to set cidrs")
	}

	// Handle additional operations using helper functions
	if err := client.AssignConnectorsToPoolFromSchema(ctx, d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return logging.DiagFromErrf(err, tags, "failed to assign connectors to pool")
	}

	if err := client.CreateRegistrationTokensFromSchema(ctx, d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return logging.DiagFromErrf(err, tags, "failed to create registration tokens")
	}

	if err := client.AssignAppsToPoolFromSchema(ctx, d, eaaclient, connPoolResp.UUIDURL); err != nil {
		return logging.DiagFromErrf(err, tags, "failed to assign apps to pool")
	}

	logging.Info(ctx, "connector pool created successfully", tags)
	return resourceEaaConnectorPoolRead(ctx, d, m)
}

// resourceEaaConnectorPoolRead function reads an existing EAA connector pool.
func resourceEaaConnectorPoolRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagConnPool, logging.TagRead}
	logging.Info(ctx, "reading connector pool", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}
	var readDiags diag.Diagnostics

	connectorPoolUUID := d.Id()

	// Read connector pool details
	connPool, err := client.GetConnectorPool(ctx, eaaclient, connectorPoolUUID)
	if err != nil {
		return logging.DiagFromErrf(err, tags, "failed to read connector pool %s", connectorPoolUUID)
	}

	// Set basic connector pool attributes using helper function
	setErr := setConnectorPoolBasicAttributes(d, connPool)
	if setErr != nil {
		return logging.DiagFromErrf(setErr, tags, "failed to set connector pool attributes")
	}

	// Read connectors in the pool
	currentConnectors, err := client.GetConnectorNamesInPool(ctx, eaaclient, connectorPoolUUID)
	if err != nil {
		logging.Warn(ctx, "failed to get connectors in pool", tags, map[string]any{"error": err.Error()})
		readDiags = append(readDiags, logging.DiagFromErrf(err, tags, "failed to get connectors in pool")...)
	} else {
		var connectorsInterface []interface{}
		for _, connector := range currentConnectors {
			connectorsInterface = append(connectorsInterface, connector)
		}
		setConnectorsErr := d.Set("connectors", connectorsInterface)
		if setConnectorsErr != nil {
			readDiags = append(readDiags, logging.DiagFromErrf(setConnectorsErr, tags, "failed to set connectors")...)
		}
	}

	// Read registration tokens
	tokens, err := eaaclient.GetRegistrationTokens(ctx, connectorPoolUUID)
	if err != nil {
		logging.Warn(ctx, "failed to get registration tokens", tags, map[string]any{"error": err.Error()})
		readDiags = append(readDiags, logging.DiagFromErrf(err, tags, "failed to get registration tokens")...)
	} else {
		if b, marshalErr := json.MarshalIndent(tokens, "", "  "); marshalErr == nil {
			logging.Trace(ctx, "API returned registration tokens", tags, map[string]any{"tokens": string(b)})
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
				return logging.DiagFromErrf(formatErr, tags, "registration token %q has invalid expires_at value %q", token.Name, token.ExpiresAt)
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
			readDiags = append(readDiags, logging.DiagFromErrf(setTokensErr, tags, "failed to set registration_tokens")...)
		}
	}

	// Read apps assigned to this connector pool
	currentApps, err := client.GetAppNamesAssignedToPool(ctx, eaaclient, connectorPoolUUID)
	if err != nil {
		logging.Warn(ctx, "failed to get apps assigned to pool", tags, map[string]any{"error": err.Error()})
		readDiags = append(readDiags, logging.DiagFromErrf(err, tags, "failed to get apps assigned to pool")...)
	} else {
		var appsInterface []interface{}
		for _, app := range currentApps {
			appsInterface = append(appsInterface, app)
		}
		if err := d.Set("apps", appsInterface); err != nil {
			readDiags = append(readDiags, logging.DiagFromErrf(err, tags, "failed to set apps")...)
		}
	}

	logging.Info(ctx, "connector pool read successfully", tags)
	return readDiags
}

// resourceEaaConnectorPoolUpdate updates an existing EAA connector pool.
func resourceEaaConnectorPoolUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagConnPool, logging.TagUpdate}
	logging.Info(ctx, "updating connector pool", tags)

	if d.HasChange("package_type") {
		if v, ok := d.GetOk("package_type"); ok {
			if pkgType, isStr := v.(string); isStr && pkgType == string(client.ConnPackageTypeAWSClassic) {
				return logging.DiagErrorf(tags, "\"aws_classic\" is no longer supported, please use \"aws\" instead")
			}
		}
	}

	e := hasDuplicateTokenNames(d)
	if e != nil {
		return logging.DiagFromErr(e, tags, "duplicate token names")
	}

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}
	var updateDiags diag.Diagnostics

	connectorPoolUUID := d.Id()

	// Update basic connector pool attributes
	if d.HasChanges("name", "description", "package_type", "infra_type", "operating_mode") {
		updateRequest := &client.CreateConnectorPoolRequest{}
		err = updateRequest.CreateConnectorPoolRequestFromSchema(ctx, d, eaaclient)
		if err != nil {
			return logging.DiagFromErr(err, tags, "failed to build connector pool update request")
		}

		// Update the connector pool using PUT
		apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.CONNECTOR_POOLS_URL, connectorPoolUUID)

		logging.Debug(ctx, "updating connector pool", tags, map[string]any{"url": apiURL})

		resp, err := eaaclient.SendAPIRequest(ctx, apiURL, "PUT", updateRequest, nil, false)
		if err != nil {
			return logging.DiagFromErr(err, tags, "connector pool update request failed")
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc := client.FormatErrorDescription(resp)
			return logging.DiagFromErrf(nil, tags, "connector pool update rejected (HTTP %d): %s", resp.StatusCode, desc)
		}
	}

	// Handle connector associations
	if d.HasChange("connectors") {
		// Get current connectors from the API
		currConnectors, err := client.GetConnectorNamesInPool(ctx, eaaclient, connectorPoolUUID)
		if err != nil {
			return logging.DiagFromErr(err, tags, "failed to get current connectors in pool")
		}

		// Get desired connectors from configuration
		connectorsRaw := d.Get("connectors")
		connectorList, ok := connectorsRaw.([]interface{})
		if !ok {
			return logging.DiagErrorf(tags, "connectors: %s", ErrInvalidData)
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
			err = client.AssignConnectorsToPoolByName(ctx, eaaclient, connectorPoolUUID, connectorsToAssign)
			if err != nil {
				return logging.DiagFromErr(err, tags, "failed to assign new connectors to pool")
			}
		}

		// Unassign removed connectors
		if len(connectorsToUnassign) > 0 {
			err = client.UnassignConnectorsFromPoolByName(ctx, eaaclient, connectorPoolUUID, connectorsToUnassign)
			if err != nil {
				return logging.DiagFromErr(err, tags, "failed to unassign connectors from pool")
			}
		}
	}

	// Handle registration tokens
	if d.HasChange("registration_tokens") {
		_, newTokensInterface := d.GetChange("registration_tokens")

		// Get existing tokens from the API
		existingTokens, err := eaaclient.GetRegistrationTokens(ctx, connectorPoolUUID)
		if err != nil {
			return logging.DiagFromErr(err, tags, "failed to get existing registration tokens")
		}

		// Create a map of existing tokens by name for easy lookup (for this pool only)
		existingTokensMap := make(map[string]*client.RegistrationToken)
		for i := range existingTokens {
			existingTokensMap[existingTokens[i].Name] = &existingTokens[i]
		}

		// Get new token names from configuration
		newTokens, ok := newTokensInterface.([]interface{})
		if !ok {
			return logging.DiagErrorf(tags, "registration_tokens must be a list, got %T", newTokensInterface)
		}
		newTokenNames := make(map[string]bool)

		for _, tokenInterface := range newTokens {
			tokenData, ok := tokenInterface.(map[string]interface{})
			if !ok {
				return logging.DiagErrorf(tags, "registration token must be an object, got %T", tokenInterface)
			}
			tokenName, ok := tokenData["name"].(string)
			if !ok || tokenName == "" {
				return logging.DiagErrorf(tags, "registration token 'name' must be a non-empty string, got %T", tokenData["name"])
			}
			newTokenNames[tokenName] = true

			expiresAtRaw, ok := tokenData["expires_at"].(string)
			if !ok {
				return logging.DiagErrorf(tags, "registration token 'expires_at' must be a string, got %T", tokenData["expires_at"])
			}
			expiresAt, formatErr := formatRFC3339Timestamp(expiresAtRaw)
			if formatErr != nil {
				return logging.DiagFromErrf(formatErr, tags, "invalid registration token expires_at %q for token %q", expiresAtRaw, tokenName)
			}
			maxUse, ok := tokenData["max_use"].(int)
			if !ok {
				return logging.DiagErrorf(tags, "registration token 'max_use' must be an integer, got %T", tokenData["max_use"])
			}
			generateEmbeddedImg, ok := tokenData["generate_embedded_img"].(bool)
			if !ok {
				return logging.DiagErrorf(tags, "registration token 'generate_embedded_img' must be a boolean, got %T", tokenData["generate_embedded_img"])
			}
			if existingToken, exists := existingTokensMap[tokenName]; exists {
				logging.Debug(ctx, "updating existing registration token", tags, map[string]any{"token": tokenName})
				updateReq := &client.RegistrationTokenWriteRequest{
					Name:                tokenName,
					MaxUse:              maxUse,
					ExpiresAt:           expiresAt,
					ConnectorPool:       connectorPoolUUID,
					GenerateEmbeddedImg: generateEmbeddedImg,
				}
				err = client.UpdateRegistrationToken(ctx, eaaclient, existingToken.UUIDURL, updateReq)
				if err != nil {
					return logging.DiagFromErrf(err, tags, "failed to update registration token %q", tokenName)
				}
				continue
			}

			logging.Debug(ctx, "creating registration token", tags, map[string]any{"token": tokenName})
			createTokenRequest := client.RegistrationTokenWriteRequest{
				Name:                tokenName,
				MaxUse:              maxUse,
				ExpiresAt:           expiresAt,
				ConnectorPool:       connectorPoolUUID,
				GenerateEmbeddedImg: generateEmbeddedImg,
			}
			_, err = createTokenRequest.CreateRegistrationToken(ctx, eaaclient)
			if err != nil {
				return logging.DiagFromErr(err, tags, "failed to create registration token")
			}
		}
		// Delete tokens that are no longer in the configuration
		for tokenName, existingToken := range existingTokensMap {
			if !newTokenNames[tokenName] {
				logging.Debug(ctx, "deleting registration token no longer in configuration", tags, map[string]any{"token": tokenName})
				err = client.DeleteRegistrationTokenByUUID(ctx, eaaclient, existingToken.UUIDURL)
				if err != nil {
					return logging.DiagFromErr(err, tags, "failed to delete registration token")
				}
			}
		}
	}

	// Handle app assignments
	if appsRaw, ok := d.GetOk("apps"); ok {
		appsList, ok := appsRaw.([]interface{})
		if !ok {
			return logging.DiagErrorf(tags, "apps: %s", ErrInvalidData)
		}
		var desiredApps []string
		for _, app := range appsList {
			if str, ok := app.(string); ok {
				desiredApps = append(desiredApps, str)
			}
		}

		// Get current apps assigned to this pool
		currApps, err := client.GetAppNamesAssignedToPool(ctx, eaaclient, connectorPoolUUID)
		if err != nil {
			updateDiags = append(updateDiags, logging.DiagFromErr(err, tags, "failed to get current apps assigned to pool")...)
		} else {
			// Calculate differences
			appsToAssign := client.DifferenceIgnoreCase(desiredApps, currApps)
			appsToUnassign := client.DifferenceIgnoreCase(currApps, desiredApps)

			// Assign new apps
			if len(appsToAssign) > 0 {
				logging.Debug(ctx, "assigning apps to connector pool", tags, map[string]any{"apps": appsToAssign})
				err = client.AssignConnectorPoolToApps(ctx, eaaclient, connectorPoolUUID, appsToAssign)
				if err != nil {
					return logging.DiagFromErr(err, tags, "failed to assign apps to connector pool")
				}
			}

			// Unassign removed apps
			if len(appsToUnassign) > 0 {
				logging.Debug(ctx, "unassigning apps from connector pool", tags, map[string]any{"apps": appsToUnassign})
				err = client.UnassignConnectorPoolFromApps(ctx, eaaclient, connectorPoolUUID, appsToUnassign)
				if err != nil {
					return logging.DiagFromErr(err, tags, "failed to unassign apps from connector pool")
				}
			}
		}
	} else {
		// If apps is not set in configuration, unassign all apps
		logging.Debug(ctx, "no apps specified in configuration, unassigning all apps from connector pool", tags)

		// Get current apps assigned to this pool
		currApps, err := client.GetAppNamesAssignedToPool(ctx, eaaclient, connectorPoolUUID)
		if err != nil {
			updateDiags = append(updateDiags, logging.DiagFromErr(err, tags, "failed to get current apps assigned to pool")...)
		} else if len(currApps) > 0 {
			// Unassign all current apps
			logging.Debug(ctx, "unassigning all apps from connector pool", tags, map[string]any{"apps": currApps})
			err = client.UnassignConnectorPoolFromApps(ctx, eaaclient, connectorPoolUUID, currApps)
			if err != nil {
				return logging.DiagFromErr(err, tags, "failed to unassign all apps from connector pool")
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
	tags := []logging.Tag{logging.TagProvider, logging.TagConnPool, logging.TagDelete}

	id := d.Id()
	logging.Info(ctx, "deleting connector pool", tags, map[string]any{"id": id})

	// STEP 1: Disassociate APPS first (must be done before connectors)
	logging.Info(ctx, "step 1: disassociating apps from pool", tags)
	currentApps, err := client.GetAppNamesAssignedToPool(ctx, eaaclient, id)
	switch {
	case err != nil:
		return diag.Errorf("cannot destroy connector pool: failed to get assigned apps: %v", err)
	case len(currentApps) == 0:
		logging.Debug(ctx, "no apps currently assigned to pool", tags)
	default:
		logging.Debug(ctx, "disassociating apps from pool", tags, map[string]any{"apps": currentApps})

		err = client.UnassignConnectorPoolFromApps(ctx, eaaclient, id, currentApps)
		if err != nil {
			return diag.Errorf("cannot destroy connector pool: failed to disassociate apps: %v", err)
		}
	}

	// STEP 2: Disassociate CONNECTORS second (after apps are removed)
	logging.Info(ctx, "step 2: disassociating connectors from pool", tags)
	currentConnectors, err := client.GetConnectorNamesInPool(ctx, eaaclient, id)
	switch {
	case err != nil:
		return diag.Errorf("cannot destroy connector pool: failed to get connectors: %v", err)
	case len(currentConnectors) == 0:
		logging.Debug(ctx, "no connectors currently in pool", tags)
	default:
		logging.Debug(ctx, fmt.Sprintf("found %d connectors to disassociate", len(currentConnectors)), tags, map[string]any{"connectors": currentConnectors})

		err = client.UnassignConnectorsFromPoolByName(ctx, eaaclient, id, currentConnectors)
		if err != nil {
			return diag.Errorf("cannot destroy connector pool: connectors cannot be disassociated due to EAA business rules: %v", err)
		}
	}

	// STEP 3: Verify that all resources are actually disassociated
	logging.Info(ctx, "step 3: verifying all resources are disassociated", tags)

	// Add a small delay to allow API state to sync
	time.Sleep(2 * time.Second)

	// Verify apps are disassociated
	currentAppsAfter, err := client.GetAppNamesAssignedToPool(ctx, eaaclient, id)
	switch {
	case err != nil:
		logging.Warn(ctx, "could not verify app disassociation", tags, map[string]any{"error": err.Error()})
	case len(currentAppsAfter) > 0:
		return diag.Errorf("cannot destroy connector pool %s: apps still assigned after disassociation: %v", id, currentAppsAfter)
	}

	// Verify connectors are disassociated
	currentConnectorsAfter, err := client.GetConnectorNamesInPool(ctx, eaaclient, id)
	switch {
	case err != nil:
		logging.Warn(ctx, "could not verify connector disassociation", tags, map[string]any{"error": err.Error()})
	case len(currentConnectorsAfter) > 0:
		return diag.Errorf("cannot destroy connector pool %s: connectors still in pool after disassociation: %v", id, currentConnectorsAfter)
	}

	// STEP 4: Now delete the empty connector pool
	logging.Info(ctx, "step 4: deleting empty connector pool", tags)
	err = client.DeleteConnectorPool(ctx, eaaclient, id)
	if err != nil {
		return logging.DiagFromErrf(err, tags, "failed to delete connector pool %s", id)
	}

	logging.Info(ctx, "successfully deleted connector pool", tags)
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
