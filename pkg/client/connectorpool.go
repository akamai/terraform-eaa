package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ============================================================================
// COMMON VALIDATION AND CONVERSION FUNCTIONS
// ============================================================================

// convertPackageType converts package_type string to integer using the type system
func convertPackageType(ctx context.Context, packageTypeStr string) (int, error) {
	tags := []logging.Tag{logging.TagConnPool, logging.TagValidate}
	if packageTypeStr == "" {
		return 0, logging.Errorf(tags, "package_type cannot be empty")
	}

	packageType := ConnPackageType(packageTypeStr)
	packageTypeInt, err := packageType.ToInt()
	if err != nil {
		return 0, logging.Wrapf(err, tags, "invalid package_type '%s'", packageTypeStr)
	}

	return packageTypeInt, nil
}

// convertInfraType converts infra_type string to integer using the type system
func convertInfraType(ctx context.Context, infraTypeStr string) (int, error) {
	tags := []logging.Tag{logging.TagConnPool, logging.TagValidate}
	if infraTypeStr == "" {
		return 0, logging.Errorf(tags, "infra_type cannot be empty if provided")
	}

	infraTypeEnum := InfraType(infraTypeStr)
	infraTypeInt, err := infraTypeEnum.ToInt()
	if err != nil {
		return 0, logging.Wrapf(err, tags, "invalid infra_type '%s'", infraTypeStr)
	}

	return infraTypeInt, nil
}

// convertOperatingMode converts operating_mode string to integer using the type system
func convertOperatingMode(ctx context.Context, operatingModeStr string) (int, error) {
	tags := []logging.Tag{logging.TagConnPool, logging.TagValidate}
	if operatingModeStr == "" {
		return 0, logging.Errorf(tags, "operating_mode cannot be empty if provided")
	}

	operatingModeEnum := OperatingMode(operatingModeStr)
	operatingModeInt, err := operatingModeEnum.ToInt()
	if err != nil {
		return 0, logging.Wrapf(err, tags, "invalid operating_mode '%s'", operatingModeStr)
	}

	return operatingModeInt, nil
}

// validateAndConvertEnumField validates and converts an enum field from string to int
func validateAndConvertEnumField(ctx context.Context, d *schema.ResourceData, fieldName string, converter func(context.Context, string) (int, error)) (*int, error) {
	tags := []logging.Tag{logging.TagConnPool, logging.TagValidate}
	if value, ok := d.GetOk(fieldName); ok {
		valueStr, ok := value.(string)
		if !ok {
			return nil, logging.Errorf(tags, "%s must be a string, got %T", fieldName, value)
		}

		valueInt, err := converter(ctx, valueStr)
		if err != nil {
			return nil, err
		}

		logging.Trace(ctx, "setting field value", tags, map[string]any{"field": fieldName, "value": valueInt})
		return &valueInt, nil
	}

	logging.Trace(ctx, "field not found in schema, leaving as nil", tags, map[string]any{"field": fieldName})
	return nil, nil
}

// ConnectorPool represents a connector pool
type ConnectorPool struct {
	Description      *string `json:"description"`
	LocationFreetext *string `json:"location_freetext,omitempty"`
	Name             string  `json:"name"`
	ResourceURI      struct {
		Href string `json:"href,omitempty"`
	} `json:"resource_uri,omitempty"`
	ModifiedAt              string          `json:"modified_at,omitempty"`
	UUIDURL                 string          `json:"uuid_url,omitempty"`
	Localization            string          `json:"localization,omitempty"`
	CreatedAt               string          `json:"created_at,omitempty"`
	Connectors              json.RawMessage `json:"connectors,omitempty"`
	EDNS                    json.RawMessage `json:"edns,omitempty"`
	ApplicationAccessGroups json.RawMessage `json:"application_access_groups,omitempty"`
	ApplicationAccessGroup  []string        `json:"application_access_group,omitempty"`
	Directories             json.RawMessage `json:"directories,omitempty"`
	DNSList                 []string        `json:"dns_list,omitempty"`
	CIDRs                   []string        `json:"cidrs,omitempty"`
	Applications            json.RawMessage `json:"applications,omitempty"`
	OperatingMode           int             `json:"operating_mode"`
	InfraType               int             `json:"infra_type"`
	PackageType             int             `json:"package_type"`
	IsEnabled               bool            `json:"is_enabled,omitempty"`
	DNSOverride             bool            `json:"dns_override,omitempty"`
	SendAlerts              bool            `json:"send_alerts,omitempty"`
}

// CreateConnectorPoolRequest represents the request to create a connector pool
type CreateConnectorPoolRequest struct {
	InfraType     *int   `json:"infra_type,omitempty"`
	OperatingMode *int   `json:"operating_mode,omitempty"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	PackageType   int    `json:"package_type"`
}

// CreateConnectorPoolResponse represents the response from creating a connector pool
type CreateConnectorPoolResponse struct {
	OperatingMode *int     `json:"operating_mode,omitempty"`
	UUIDURL       string   `json:"uuid_url"`
	CIDRs         []string `json:"cidrs"`
}

// CreateConnectorPoolRequestFromSchema creates a CreateConnectorPoolRequest from the schema
func (ccpr *CreateConnectorPoolRequest) CreateConnectorPoolRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	// Validate and set required fields
	name, err := ValidateRequiredString(ctx, d, "name")
	if err != nil {
		return err
	}
	ccpr.Name = name

	// Validate and set optional description
	description, err := ValidateOptionalString(ctx, d, "description")
	if err != nil {
		return err
	}
	ccpr.Description = description

	// Validate and convert package_type
	packageTypeStr, err := ValidateRequiredString(ctx, d, "package_type")
	if err != nil {
		return err
	}

	packageTypeInt, err := convertPackageType(ctx, packageTypeStr)
	if err != nil {
		return err
	}
	ccpr.PackageType = packageTypeInt

	// Initialize optional fields to nil
	ccpr.InfraType = nil
	ccpr.OperatingMode = nil

	// Validate and convert optional enum fields
	ccpr.InfraType, err = validateAndConvertEnumField(ctx, d, "infra_type", convertInfraType)
	if err != nil {
		return err
	}

	ccpr.OperatingMode, err = validateAndConvertEnumField(ctx, d, "operating_mode", convertOperatingMode)
	if err != nil {
		return err
	}

	return nil
}

// ============================================================================
// API HELPER FUNCTIONS
// ============================================================================

// buildConnectorPoolDetailURL builds a URL for specific connector pool operations
func buildConnectorPoolDetailURL(ec *EaaClient, uuid string) string {
	return fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_MGMT_URL, uuid)
}

// handleConnectorPoolAPIResponse handles common API response processing
func handleConnectorPoolAPIResponse(resp *http.Response, operation string, tags []logging.Tag) error {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(resp)
		return logging.Errorf(tags, "%s failed: HTTP %d: %s", operation, resp.StatusCode, desc)
	}
	return nil
}

// ============================================================================
// CONNECTOR POOL CRUD OPERATIONS
// ============================================================================

// CreateConnectorPool creates a new connector pool
func (ccpr *CreateConnectorPoolRequest) CreateConnectorPool(ctx context.Context, ec *EaaClient) (*CreateConnectorPoolResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagCreate}
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL)

	var response CreateConnectorPoolResponse
	resp, err := ec.SendAPIRequest(ctx, apiURL, "POST", ccpr, &response, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "connector pool creation API request failed")
	}

	if err := handleConnectorPoolAPIResponse(resp, "create ConnectorPool", tags); err != nil {
		return nil, err
	}

	logging.Info(ctx, "connector pool created", tags, map[string]any{"uuid": response.UUIDURL})
	return &response, nil
}

// GetConnectorPool retrieves a connector pool by UUID
func GetConnectorPool(ctx context.Context, ec *EaaClient, uuid string) (*ConnectorPool, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	apiURL := buildConnectorPoolDetailURL(ec, uuid)

	var connectorPool ConnectorPool
	resp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &connectorPool, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "get connector pool API request failed")
	}

	if err := handleConnectorPoolAPIResponse(resp, "get ConnectorPool", tags); err != nil {
		return nil, err
	}

	return &connectorPool, nil
}

// DeleteConnectorPool deletes a connector pool
func DeleteConnectorPool(ctx context.Context, ec *EaaClient, uuid string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagDelete}
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, uuid)

	resp, err := ec.SendAPIRequest(ctx, apiURL, "DELETE", nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "delete connector pool API request failed")
	}

	if err := handleConnectorPoolAPIResponse(resp, "delete ConnectorPool", tags); err != nil {
		return err
	}

	logging.Info(ctx, "connector pool deleted", tags, map[string]any{"uuid": uuid})
	return nil
}

// ============================================================================
// CONNECTOR ASSOCIATION OPERATIONS
// ============================================================================

// ConnectorPoolAssociationRequest represents the request to associate/disassociate connectors with a pool
type ConnectorPoolAssociationRequest struct {
	Agents []AgentAssociation `json:"agents"`
}

// AgentAssociation represents an agent in the association request
type AgentAssociation struct {
	CID            string `json:"cid"`
	UUIDURL        string `json:"uuid_url"`
	AgentInfraType int    `json:"agentInfraType"`
}

// buildConnectorAssociationRequest builds a request for associating connectors with a pool
func buildConnectorAssociationRequest(connectorUUIDs []string) *ConnectorPoolAssociationRequest {
	var agents []AgentAssociation
	for _, connectorUUID := range connectorUUIDs {
		agent := AgentAssociation{
			AgentInfraType: int(INFRA_TYPE_EAA),
			UUIDURL:        connectorUUID,
		}
		agents = append(agents, agent)
	}

	return &ConnectorPoolAssociationRequest{
		Agents: agents,
	}
}

// AssignConnectorsToPool assigns multiple connectors to a connector pool
func AssignConnectorsToPool(ctx context.Context, ec *EaaClient, poolUUID string, connectorUUIDs []string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagAssign}
	url := fmt.Sprintf("%s://%s/%s/%s/agents/associate",
		URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, poolUUID)

	// Use the helper function to build the request
	associationRequest := buildConnectorAssociationRequest(connectorUUIDs)

	resp, err := ec.SendAPIRequest(ctx, url, "PUT", associationRequest, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "assign connectors to pool API request failed")
	}

	if err := handleConnectorPoolAPIResponse(resp, "assign connectors to pool", tags); err != nil {
		return err
	}

	return nil
}

// UnassignConnectorsFromPool removes multiple connectors from a connector pool
func UnassignConnectorsFromPool(ctx context.Context, ec *EaaClient, connectorPoolUUID string, connectorUUIDs []string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagAssign}

	// Use existing constants for URL building
	apiURL := fmt.Sprintf("%s://%s/%s/%s/agents/disassociate",
		URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, connectorPoolUUID)

	// Create the disassociation request
	var agents []AgentAssociation
	for _, connectorUUID := range connectorUUIDs {
		agent := AgentAssociation{
			AgentInfraType: int(INFRA_TYPE_EAA),
			UUIDURL:        connectorUUID,
		}
		agents = append(agents, agent)
	}

	disassociationRequest := &ConnectorPoolAssociationRequest{
		Agents: agents,
	}

	resp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", disassociationRequest, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "unassign connectors from pool API request failed")
	}

	if err := handleConnectorPoolAPIResponse(resp, "unassign connectors from pool", tags); err != nil {
		return err
	}

	return nil
}

// GetConnectorsInPool retrieves the list of connector UUIDs currently in a connector pool
func GetConnectorsInPool(ctx context.Context, ec *EaaClient, poolUUID string) ([]string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	// Use existing constants for URL building
	url := fmt.Sprintf("%s://%s/%s/%s",
		URL_SCHEME, ec.Host, CONNECTOR_POOLS_MGMT_URL, poolUUID)

	var connectorPool ConnectorPool
	resp, err := ec.SendAPIRequest(ctx, url, "GET", nil, &connectorPool, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "get connectors in pool API request failed")
	}

	if err := handleConnectorPoolAPIResponse(resp, "get connectors in pool", tags); err != nil {
		return nil, err
	}

	// Parse the connectors from the JSON response
	var connectors []string
	if connectorPool.Connectors != nil {
		var connectorData []map[string]interface{}
		if err := json.Unmarshal(connectorPool.Connectors, &connectorData); err != nil {
			return nil, logging.Wrapf(err, tags, "failed to parse connectors JSON for pool %s", poolUUID)
		}
		for _, connector := range connectorData {
			if uuid, ok := connector["uuid_url"].(string); ok {
				connectors = append(connectors, uuid)
			} else {
				logging.Warn(ctx, "connector entry missing uuid_url field", tags, map[string]any{"connector": connector})
			}
		}
	}

	return connectors, nil
}

// GetConnectorNamesInPool retrieves the list of connector names currently in a connector pool
func GetConnectorNamesInPool(ctx context.Context, ec *EaaClient, poolUUID string) ([]string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	connectorUUIDs, err := GetConnectorsInPool(ctx, ec, poolUUID)
	if err != nil {
		return nil, err
	}

	// Get all agents to build a UUID-to-name mapping
	agents, err := GetAgents(ctx, ec)
	if err != nil {
		return nil, err
	}

	// Build UUID-to-name lookup map
	uuidToName := make(map[string]string)
	for i := range agents {
		agent := &agents[i]
		uuidToName[agent.UUIDURL] = agent.Name
	}

	// Map UUIDs back to names
	var connectorNames []string
	for _, uuid := range connectorUUIDs {
		if name, exists := uuidToName[uuid]; exists {
			connectorNames = append(connectorNames, name)
		} else {
			logging.Warn(ctx, "connector UUID could not be resolved to a name", tags, map[string]any{"uuid": uuid})
		}
	}

	return connectorNames, nil
}

// AppConnectorPoolAssignment represents the assignment of connector pools to an app
type AppConnectorPoolAssignment struct {
	Active  []string `json:"active"`
	Standby []string `json:"standby"`
}

// AppConnectorPoolAssignmentRequest represents the request to assign/disassign connector pools to an app
type AppConnectorPoolAssignmentRequest struct {
	Add    AppConnectorPoolAssignment `json:"add"`
	Delete []string                   `json:"delete"`
}

// AssignConnectorPoolsToApp assigns connector pools to an application
func AssignConnectorPoolsToApp(ctx context.Context, ec *EaaClient, appUUID string, request *AppConnectorPoolAssignmentRequest) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagAssign}
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, fmt.Sprintf(APP_CONNECTOR_POOLS_ASSOCIATE_URL, appUUID))

	resp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", request, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "assign connector pools to app API request failed")
	}

	if err := handleConnectorPoolAPIResponse(resp, "assign connector pools to app", tags); err != nil {
		return err
	}

	return nil
}

// GetConnectorUUIDs maps connector names to UUIDs by fetching all agents with pagination and building a lookup table
func GetConnectorUUIDs(ctx context.Context, ec *EaaClient, connectorNames []string) ([]string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	// Implement pagination directly here to fetch all agents
	var allAgents []Connector
	offset := 0
	var apiLimit int // Will be set from API response meta

	for {
		// Build URL with optimized parameters - using contractId, gid, expand, and dynamic limit from API
		var apiURL string
		if offset == 0 {
			// First request: let API use its default limit
			apiURL = fmt.Sprintf("%s://%s/%s?&expand=true&offset=0", URL_SCHEME, ec.Host, AGENTS_URL)
		} else {
			// Subsequent requests: use the limit we got from API response meta
			apiURL = fmt.Sprintf("%s://%s/%s?&expand=true&limit=%d&offset=%d", URL_SCHEME, ec.Host, AGENTS_URL, apiLimit, offset)
		}

		// Define the response structure inline to match the API response
		var response struct {
			Objects []struct {
				Name    string `json:"name"`
				UUIDURL string `json:"uuid_url"`
			} `json:"objects"`
			Meta struct {
				Next       *string `json:"next"`
				Previous   *string `json:"previous"`
				Limit      int     `json:"limit"`
				Offset     int     `json:"offset"`
				TotalCount int     `json:"total_count"`
			} `json:"meta"`
		}

		resp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &response, false)
		if err != nil {
			return nil, logging.Wrapf(err, tags, "get agents API request failed")
		}

		// Set the API limit from the first response (if not already set)
		if offset == 0 {
			apiLimit = response.Meta.Limit
		}

		if err := handleConnectorPoolAPIResponse(resp, "get agents", tags); err != nil {
			return nil, err
		}

		// Convert response objects to Connector and add to results
		for _, agent := range response.Objects {
			if agent.Name == "" || agent.UUIDURL == "" {
				logging.Warn(ctx, "skipping agent with empty name or UUID", tags, map[string]any{"name": agent.Name, "uuid": agent.UUIDURL})
				continue
			}
			allAgents = append(allAgents, Connector{
				Name:    agent.Name,
				UUIDURL: agent.UUIDURL,
			})
		}

		// Check if we've retrieved all agents using the total count from API
		if response.Meta.TotalCount > 0 && len(allAgents) >= response.Meta.TotalCount {
			break
		}

		// Check if we got fewer results than requested (end of data)
		if len(response.Objects) < apiLimit {
			break
		}

		// Move to next page
		offset += apiLimit
	}

	// Now search for the requested connector names
	connectorUUIDs := make([]string, 0)
	notFoundConnectors := make([]string, 0)

	for _, connectorName := range connectorNames {
		found := false
		for i := range allAgents {
			agentData := &allAgents[i]
			if connectorName == agentData.Name {
				connectorUUIDs = append(connectorUUIDs, agentData.UUIDURL)
				found = true
				break
			}
		}
		if !found {
			notFoundConnectors = append(notFoundConnectors, connectorName)
		}
	}

	if len(notFoundConnectors) > 0 {
		return nil, logging.Errorf(tags, "connectors not found: %v", notFoundConnectors)
	}

	return connectorUUIDs, nil
}

// AssignConnectorsToPoolByName assigns connectors to a pool using connector names instead of UUIDs
func AssignConnectorsToPoolByName(ctx context.Context, ec *EaaClient, poolUUID string, connectorNames []string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagAssign}
	connectorUUIDs, err := GetConnectorUUIDs(ctx, ec, connectorNames)
	if err != nil {
		return err
	}

	if len(connectorUUIDs) == 0 {
		return logging.Errorf(tags, "no valid connectors found to assign")
	}

	return AssignConnectorsToPool(ctx, ec, poolUUID, connectorUUIDs)
}

// UnassignConnectorsFromPoolByName removes connectors from a pool using connector names instead of UUIDs
func UnassignConnectorsFromPoolByName(ctx context.Context, ec *EaaClient, connectorPoolUUID string, connectorNames []string) error {
	connectorUUIDs, err := GetConnectorUUIDs(ctx, ec, connectorNames)
	if err != nil {
		return err
	}

	if len(connectorUUIDs) == 0 {
		return nil
	}

	return UnassignConnectorsFromPool(ctx, ec, connectorPoolUUID, connectorUUIDs)
}

// App represents an application
type App struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

// GetApps retrieves all applications using smart pagination that reads meta information
// Uses the API's own limit and pagination information for optimal performance
func GetApps(ctx context.Context, ec *EaaClient) ([]App, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagList}
	var allApps []App
	offset := 0
	var apiLimit int // Will be set from API response meta

	for {
		// Build URL - first request without limit/offset, subsequent requests with API's limit
		var url string
		if offset == 0 {
			// First request: use v3 API with optimized parameters
			url = fmt.Sprintf("%s://%s/crux/v3/mgmt-pop/apps?limit=10&offset=0&fields=name,uuid_url&ordering=name",
				URL_SCHEME, ec.Host)
		} else {
			// Subsequent requests: use the limit we got from API response meta
			url = fmt.Sprintf("%s://%s/crux/v3/mgmt-pop/apps?limit=%d&offset=%d&fields=name,uuid_url&ordering=name",
				URL_SCHEME, ec.Host, apiLimit, offset)
		}

		// Define the response structure to read ALL meta information from v3 API
		var response struct {
			Objects []struct {
				Name    string `json:"name"`
				UUIDURL string `json:"uuid_url"`
			} `json:"objects"`
			Meta struct {
				Next       *string `json:"next"`
				Previous   *string `json:"previous"`
				Limit      int     `json:"limit"`
				Offset     int     `json:"offset"`
				TotalCount int     `json:"total_count"`
			} `json:"meta"`
		}

		resp, err := ec.SendAPIRequest(ctx, url, "GET", nil, &response, false)
		if err != nil {
			return nil, logging.Wrapf(err, tags, "get apps API request failed")
		}

		if err := handleConnectorPoolAPIResponse(resp, "get apps", tags); err != nil {
			return nil, err
		}

		// Set the API limit from the first response (if not already set)
		if offset == 0 {
			apiLimit = response.Meta.Limit
		}

		// Convert response objects to App and add to results
		for _, app := range response.Objects {
			allApps = append(allApps, App{
				Name:    app.Name,
				UUIDURL: app.UUIDURL,
			})
		}

		// SMART PAGINATION: Use meta information to determine when to stop

		// Check 1: No more pages available (meta.next is null)
		if response.Meta.Next == nil {
			break
		}

		// Check 2: We've retrieved all apps according to API total count
		if response.Meta.TotalCount > 0 && len(allApps) >= response.Meta.TotalCount {
			break
		}

		// Check 3: API returned fewer objects than its own limit (end of data)
		if len(response.Objects) < response.Meta.Limit {
			break
		}

		// Move to next batch using the API's limit
		offset += response.Meta.Limit

		// Safety check to prevent infinite loops
		if offset > 10000 {
			break
		}

		// Add a small delay to prevent overwhelming the API
		time.Sleep(100 * time.Millisecond)
	}

	return allApps, nil
}

// GetAppUUIDs converts app names to UUIDs
func GetAppUUIDs(ctx context.Context, ec *EaaClient, appNames []string) ([]string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagRead}
	apps, err := GetApps(ctx, ec)
	if err != nil {
		return nil, err
	}

	appUUIDs := make([]string, 0)
	notFoundApps := make([]string, 0)

	for _, appName := range appNames {
		found := false
		for _, appData := range apps {
			if appName == appData.Name {
				appUUIDs = append(appUUIDs, appData.UUIDURL)
				found = true
				break
			}
		}
		if !found {
			notFoundApps = append(notFoundApps, appName)
		}
	}

	if len(notFoundApps) > 0 {
		return nil, logging.Errorf(tags, "apps not found: %v", notFoundApps)
	}

	return appUUIDs, nil
}

// AssignConnectorPoolToApps assigns a connector pool to multiple apps
func AssignConnectorPoolToApps(ctx context.Context, ec *EaaClient, poolUUID string, appNames []string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagAssign}
	appUUIDs, err := GetAppUUIDs(ctx, ec, appNames)
	if err != nil {
		return err
	}

	if len(appUUIDs) == 0 {
		return logging.Errorf(tags, "no valid apps found to assign")
	}

	var errs []error
	for _, appUUID := range appUUIDs {
		request := &AppConnectorPoolAssignmentRequest{
			Add: AppConnectorPoolAssignment{
				Active:  []string{poolUUID},
				Standby: []string{},
			},
			Delete: []string{},
		}
		err := AssignConnectorPoolsToApp(ctx, ec, appUUID, request)
		if err != nil {
			errs = append(errs, fmt.Errorf("app %s: %w", appUUID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to assign pool to %d app(s): %w", len(errs), errors.Join(errs...))
	}
	return nil
}

// UnassignConnectorPoolFromApps removes a connector pool from multiple apps
func UnassignConnectorPoolFromApps(ctx context.Context, ec *EaaClient, poolUUID string, appNames []string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagAssign}
	appUUIDs, err := GetAppUUIDs(ctx, ec, appNames)
	if err != nil {
		return err
	}

	if len(appUUIDs) == 0 {
		return logging.Errorf(tags, "no valid apps found to unassign")
	}

	logging.Info(ctx, "unassigning connector pool from apps", tags, map[string]any{"count": len(appUUIDs), "apps": appNames})

	var errs []error
	for _, appUUID := range appUUIDs {
		request := &AppConnectorPoolAssignmentRequest{
			Add: AppConnectorPoolAssignment{
				Active:  []string{},
				Standby: []string{},
			},
			Delete: []string{poolUUID},
		}

		err := AssignConnectorPoolsToApp(ctx, ec, appUUID, request)
		if err != nil {
			errs = append(errs, fmt.Errorf("app %s: %w", appUUID, err))
			continue
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to unassign pool from %d app(s): %w", len(errs), errors.Join(errs...))
	}

	logging.Info(ctx, "successfully unassigned connector pool from all apps", tags, map[string]any{"count": len(appUUIDs)})
	return nil
}

// GetAppsAssignedToPool retrieves the list of app UUIDs currently assigned to a connector pool
func GetAppsAssignedToPool(ctx context.Context, ec *EaaClient, poolUUID string) ([]string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}

	// Use the same pattern as GetConnectorsInPool - read the connector pool object directly
	url := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_MGMT_URL, poolUUID)

	var connectorPool ConnectorPool
	resp, err := ec.SendAPIRequest(ctx, url, "GET", nil, &connectorPool, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to get connector pool")
	}

	if err := handleConnectorPoolAPIResponse(resp, "get connector pool", tags); err != nil {
		return nil, err
	}

	// Parse the applications from the JSON response, similar to how we parse connectors
	var assignedAppUUIDs []string
	if connectorPool.Applications != nil {
		// Parse the applications JSON to extract UUIDs
		var appData []map[string]interface{}
		if err := json.Unmarshal(connectorPool.Applications, &appData); err != nil {
			return nil, logging.Wrapf(err, tags, "failed to parse applications JSON for pool %s", poolUUID)
		}
		for _, app := range appData {
			if uuid, ok := app["uuid_url"].(string); ok {
				assignedAppUUIDs = append(assignedAppUUIDs, uuid)
			}
		}
	}

	logging.Trace(ctx, "apps assigned to pool", tags, map[string]any{"count": len(assignedAppUUIDs), "pool_uuid": poolUUID})
	return assignedAppUUIDs, nil
}

// GetAppNamesAssignedToPool retrieves the list of app names currently assigned to a connector pool
func GetAppNamesAssignedToPool(ctx context.Context, ec *EaaClient, poolUUID string) ([]string, error) {
	appUUIDs, err := GetAppsAssignedToPool(ctx, ec, poolUUID)
	if err != nil {
		return nil, err
	}

	// Get all apps to build a UUID-to-name mapping
	apps, err := GetApps(ctx, ec)
	if err != nil {
		return nil, err
	}

	// Build UUID-to-name lookup map
	uuidToName := make(map[string]string)
	for _, app := range apps {
		uuidToName[app.UUIDURL] = app.Name
	}

	// Map UUIDs back to names
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	var appNames []string
	for _, uuid := range appUUIDs {
		if name, exists := uuidToName[uuid]; exists {
			appNames = append(appNames, name)
		} else {
			logging.Warn(ctx, "app UUID could not be resolved to a name", tags, map[string]any{"uuid": uuid})
		}
	}

	return appNames, nil
}

// GetConnectorPools retrieves all connector pools using smart pagination that reads meta information
// Uses the API's own limit and pagination information for optimal performance
func GetConnectorPools(ctx context.Context, ec *EaaClient) ([]ConnectorPool, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagList}
	var allPools []ConnectorPool
	offset := 0
	var apiLimit int // Will be set from API response meta

	for {
		// Build URL - first request without limit/offset, subsequent requests with API's limit
		var apiURL string
		if offset == 0 {
			// First request: let API use its default limit
			apiURL = fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_MGMT_URL)
		} else {
			// Subsequent requests: use the limit we got from API response meta
			apiURL = fmt.Sprintf("%s://%s/%s?limit=%d&offset=%d", URL_SCHEME, ec.Host, CONNECTOR_POOLS_MGMT_URL, apiLimit, offset)
		}

		// Define the response structure to read ALL meta information
		type connectorPoolsListResponse struct {
			Objects []ConnectorPool `json:"objects"`
			Meta    struct {
				Next       *string `json:"next"`
				Previous   *string `json:"previous"`
				Limit      int     `json:"limit"`
				Offset     int     `json:"offset"`
				TotalCount int     `json:"total_count"`
			} `json:"meta"`
		}

		var response connectorPoolsListResponse
		resp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &response, false)
		if err != nil {
			return nil, logging.Wrapf(err, tags, "get connector pools API request failed")
		}

		if err := handleConnectorPoolAPIResponse(resp, "get connector pools", tags); err != nil {
			return nil, err
		}

		// Set the API limit from the first response (if not already set)
		if offset == 0 {
			apiLimit = response.Meta.Limit
		}

		// Add pools from this batch to results
		allPools = append(allPools, response.Objects...)

		// SMART PAGINATION: Use meta information to determine when to stop

		// Check 1: No more pages available (meta.next is null)
		if response.Meta.Next == nil {
			break
		}

		// Check 2: We've retrieved all pools according to API total count
		if response.Meta.TotalCount > 0 && len(allPools) >= response.Meta.TotalCount {
			break
		}

		// Check 3: API returned fewer objects than its own limit (end of data)
		if len(response.Objects) < response.Meta.Limit {
			break
		}

		// Move to next batch using the API's limit
		offset += response.Meta.Limit

		// Safety check to prevent infinite loops
		if offset > 10000 {
			logging.Warn(ctx, "reached maximum offset limit (10000), stopping pagination", tags)
			break
		}

		// Add a small delay to prevent overwhelming the API
		time.Sleep(100 * time.Millisecond)
	}
	return allPools, nil
}

// SetConnectorPoolBasicAttributes sets the basic attributes of a connector pool in the schema
func SetConnectorPoolBasicAttributes(d *schema.ResourceData, connPool *ConnectorPool) error {
	if err := d.Set("name", connPool.Name); err != nil {
		return err
	}

	// Handle optional description field
	description := ""
	if connPool.Description != nil {
		description = *connPool.Description
	}
	if err := d.Set("description", description); err != nil {
		return err
	}

	if err := d.Set("uuid_url", connPool.UUIDURL); err != nil {
		return err
	}

	// Convert package_type from int back to string using type system
	packageTypeStr := ConvertIntToEnumString(connPool.PackageType, func(i int) (string, error) {
		return ConnPackageTypeInt(i).String()
	})
	if err := d.Set("package_type", packageTypeStr); err != nil {
		return err
	}

	// Convert infra_type from int back to string using type system
	if connPool.InfraType != 0 {
		infraTypeStr := ConvertIntToEnumString(connPool.InfraType, func(i int) (string, error) {
			return InfraTypeInt(i).String()
		})
		if err := d.Set("infra_type", infraTypeStr); err != nil {
			return err
		}
	}

	// Convert operating_mode from int back to string using type system
	if connPool.OperatingMode != 0 {
		operatingModeStr := ConvertIntToEnumString(connPool.OperatingMode, func(i int) (string, error) {
			return OperatingModeInt(i).String()
		})
		if err := d.Set("operating_mode", operatingModeStr); err != nil {
			return err
		}
	}

	return nil
}

// ============================================================================
// TERRAFORM SCHEMA HELPER FUNCTIONS
// ============================================================================

// AssignConnectorsToPoolFromSchema assigns connectors to a connector pool from Terraform schema data
func AssignConnectorsToPoolFromSchema(ctx context.Context, d *schema.ResourceData, eaaclient *EaaClient, poolUUID string) error {
	tags := []logging.Tag{logging.TagConnPool, logging.TagAssign}
	connectors, ok := d.GetOk("connectors")
	if !ok {
		return nil
	}

	connectorsList, ok := connectors.([]interface{})
	if !ok {
		return logging.Errorf(tags, "connectors must be a list, got %T", connectors)
	}
	var connectorNames []string
	for _, connector := range connectorsList {
		connectorName, ok := connector.(string)
		if !ok {
			return logging.Errorf(tags, "connector name must be a string, got %T", connector)
		}
		connectorNames = append(connectorNames, connectorName)
	}

	if len(connectorNames) > 0 {
		err := AssignConnectorsToPoolByName(ctx, eaaclient, poolUUID, connectorNames)
		if err != nil {
			return logging.Wrapf(err, tags, "failed to assign connectors to pool")
		}
	}

	return nil
}

// AssignAppsToPoolFromSchema assigns apps to a connector pool from Terraform schema data
func AssignAppsToPoolFromSchema(ctx context.Context, d *schema.ResourceData, eaaclient *EaaClient, poolUUID string) error {
	tags := []logging.Tag{logging.TagConnPool, logging.TagAssign}
	apps, ok := d.GetOk("apps")
	if !ok {
		return nil
	}

	appsList, ok := apps.([]interface{})
	if !ok {
		return logging.Errorf(tags, "apps must be a list, got %T", apps)
	}
	var appNames []string
	for _, app := range appsList {
		appName, ok := app.(string)
		if !ok {
			return logging.Errorf(tags, "app name must be a string, got %T", app)
		}
		appNames = append(appNames, appName)
	}

	if len(appNames) > 0 {
		err := AssignConnectorPoolToApps(ctx, eaaclient, poolUUID, appNames)
		if err != nil {
			return logging.Wrapf(err, tags, "failed to assign apps to connector pool")
		}
	}

	return nil
}
