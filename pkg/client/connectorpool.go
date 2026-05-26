package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ============================================================================
// COMMON VALIDATION AND CONVERSION FUNCTIONS
// ============================================================================

// convertPackageType converts package_type string to integer using the type system
func convertPackageType(packageTypeStr string, ec *EaaClient) (int, error) {
	if packageTypeStr == "" {
		ec.Logger.Error("package_type cannot be empty")
		return 0, fmt.Errorf("package_type cannot be empty")
	}

	packageType := ConnPackageType(packageTypeStr)
	packageTypeInt, err := packageType.ToInt()
	if err != nil {
		ec.Logger.Error("Invalid package_type", "value", packageTypeStr)
		return 0, fmt.Errorf("invalid package_type '%s': %w", packageTypeStr, err)
	}

	return packageTypeInt, nil
}

// convertInfraType converts infra_type string to integer using the type system
func convertInfraType(infraTypeStr string, ec *EaaClient) (int, error) {
	if infraTypeStr == "" {
		ec.Logger.Error("infra_type cannot be empty if provided")
		return 0, fmt.Errorf("infra_type cannot be empty if provided")
	}

	infraTypeEnum := InfraType(infraTypeStr)
	infraTypeInt, err := infraTypeEnum.ToInt()
	if err != nil {
		ec.Logger.Error("Invalid infra_type", "value", infraTypeStr)
		return 0, fmt.Errorf("invalid infra_type '%s': %w", infraTypeStr, err)
	}

	return infraTypeInt, nil
}

// convertOperatingMode converts operating_mode string to integer using the type system
func convertOperatingMode(operatingModeStr string, ec *EaaClient) (int, error) {
	if operatingModeStr == "" {
		ec.Logger.Error("operating_mode cannot be empty if provided")
		return 0, fmt.Errorf("operating_mode cannot be empty if provided")
	}

	operatingModeEnum := OperatingMode(operatingModeStr)
	operatingModeInt, err := operatingModeEnum.ToInt()
	if err != nil {
		ec.Logger.Error("Invalid operating_mode", "value", operatingModeStr)
		return 0, fmt.Errorf("invalid operating_mode '%s': %w", operatingModeStr, err)
	}

	return operatingModeInt, nil
}

// validateAndConvertEnumField validates and converts an enum field from string to int
func validateAndConvertEnumField(d *schema.ResourceData, fieldName string, converter func(string, *EaaClient) (int, error), ec *EaaClient) (*int, error) {
	if value, ok := d.GetOk(fieldName); ok {
		valueStr, ok := value.(string)
		if !ok {
			ec.Logger.Error("field must be a string", "field", fieldName)
			return nil, fmt.Errorf("%s must be a string, got %T", fieldName, value)
		}

		valueInt, err := converter(valueStr, ec)
		if err != nil {
			return nil, err
		}

		ec.Logger.Info("Setting field value", "field", fieldName, "value", valueInt)
		return &valueInt, nil
	}

	ec.Logger.Info("Field not found in schema, leaving as nil", "field", fieldName)
	return nil, nil
}

var (
	ErrConnectorPoolCreate = errors.New("connector pool creation failed")
	ErrConnectorPoolGet    = errors.New("connector pool get failed")
	ErrConnectorPoolUpdate = errors.New("connector pool update failed")
	ErrConnectorPoolDelete = errors.New("connector pool delete failed")
)

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
	name, err := ValidateRequiredString(d, "name", ec)
	if err != nil {
		return err
	}
	ccpr.Name = name

	// Validate and set optional description
	description, err := ValidateOptionalString(d, "description", ec)
	if err != nil {
		return err
	}
	ccpr.Description = description

	// Validate and convert package_type
	packageTypeStr, err := ValidateRequiredString(d, "package_type", ec)
	if err != nil {
		return err
	}

	packageTypeInt, err := convertPackageType(packageTypeStr, ec)
	if err != nil {
		return err
	}
	ccpr.PackageType = packageTypeInt

	// Initialize optional fields to nil
	ccpr.InfraType = nil
	ccpr.OperatingMode = nil

	// Validate and convert optional enum fields
	ccpr.InfraType, err = validateAndConvertEnumField(d, "infra_type", convertInfraType, ec)
	if err != nil {
		return err
	}

	ccpr.OperatingMode, err = validateAndConvertEnumField(d, "operating_mode", convertOperatingMode, ec)
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

// handleAPIResponse handles common API response processing
func handleConnectorPoolAPIResponse(resp *http.Response, operation string, ec *EaaClient) error {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(resp)
		errMsg := fmt.Errorf("%s failed: %s", operation, desc)
		ec.Logger.Error("Operation failed", "operation", operation, "status_code", resp.StatusCode, "error", desc)
		return errMsg
	}
	return nil
}

// ============================================================================
// CONNECTOR POOL CRUD OPERATIONS
// ============================================================================

// CreateConnectorPool creates a new connector pool
func (ccpr *CreateConnectorPoolRequest) CreateConnectorPool(ctx context.Context, ec *EaaClient) (*CreateConnectorPoolResponse, error) {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL)

	var response CreateConnectorPoolResponse
	resp, err := ec.SendAPIRequest(apiURL, "POST", ccpr, &response, false)
	if err != nil {
		ec.Logger.Error("API request failed", "error", err)
		return nil, err
	}

	if err := handleConnectorPoolAPIResponse(resp, "create ConnectorPool", ec); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectorPoolCreate, err)
	}

	return &response, nil
}

// GetConnectorPool retrieves a connector pool by UUID
func GetConnectorPool(ctx context.Context, ec *EaaClient, uuid string) (*ConnectorPool, error) {
	apiURL := buildConnectorPoolDetailURL(ec, uuid)

	var connectorPool ConnectorPool
	resp, err := ec.SendAPIRequest(apiURL, "GET", nil, &connectorPool, false)
	if err != nil {
		ec.Logger.Error("Get API request failed", "error", err)
		return nil, err
	}

	if err := handleConnectorPoolAPIResponse(resp, "get ConnectorPool", ec); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectorPoolGet, err)
	}

	return &connectorPool, nil
}

// DeleteConnectorPool deletes a connector pool
func DeleteConnectorPool(ctx context.Context, ec *EaaClient, uuid string) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, uuid)

	resp, err := ec.SendAPIRequest(apiURL, "DELETE", nil, nil, false)
	if err != nil {
		ec.Logger.Error("DELETE request failed", "error", err)
		return err
	}

	if err := handleConnectorPoolAPIResponse(resp, "delete ConnectorPool", ec); err != nil {
		return fmt.Errorf("%w: %w", ErrConnectorPoolDelete, err)
	}
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
func AssignConnectorsToPool(client *EaaClient, poolUUID string, connectorUUIDs []string) error {
	url := fmt.Sprintf("%s://%s/%s/%s/agents/associate",
		URL_SCHEME, client.Host, CONNECTOR_POOLS_URL, poolUUID)

	// Use the helper function to build the request
	associationRequest := buildConnectorAssociationRequest(connectorUUIDs)

	resp, err := client.SendAPIRequest(url, "PUT", associationRequest, nil, false)
	if err != nil {
		client.Logger.Error("Assignment API request failed", "error", err)
		return err
	}

	if err := handleConnectorPoolAPIResponse(resp, "assign connectors to pool", client); err != nil {
		return err
	}

	return nil
}

// UnassignConnectorsFromPool removes multiple connectors from a connector pool
func UnassignConnectorsFromPool(ec *EaaClient, connectorPoolUUID string, connectorUUIDs []string) error {

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

	resp, err := ec.SendAPIRequest(apiURL, "PUT", disassociationRequest, nil, false)
	if err != nil {
		ec.Logger.Error("Unassignment API request failed", "error", err)
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(resp)
		unassignmentErrMsg := fmt.Errorf("connector pool unassignment failed: %s", desc)
		ec.Logger.Error("Unassignment failed", "status_code", resp.StatusCode, "error", desc)
		return unassignmentErrMsg
	}

	return nil
}

// GetConnectorsInPool retrieves the list of connector UUIDs currently in a connector pool
func GetConnectorsInPool(client *EaaClient, poolUUID string) ([]string, error) {
	// Use existing constants for URL building
	url := fmt.Sprintf("%s://%s/%s/%s",
		URL_SCHEME, client.Host, CONNECTOR_POOLS_MGMT_URL, poolUUID)

	var connectorPool ConnectorPool
	resp, err := client.SendAPIRequest(url, "GET", nil, &connectorPool, false)
	if err != nil {
		client.Logger.Error("Get connectors API request failed", "error", err)
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(resp)
		getErrMsg := fmt.Errorf("get connectors in pool failed: %s", desc)
		client.Logger.Error("Get connectors failed", "status_code", resp.StatusCode, "error", desc)
		return nil, getErrMsg
	}

	// Parse the connectors from the JSON response
	var connectors []string
	if connectorPool.Connectors != nil {
		var connectorData []map[string]interface{}
		if err := json.Unmarshal(connectorPool.Connectors, &connectorData); err != nil {
			return nil, fmt.Errorf("failed to parse connectors JSON for pool %s: %w", poolUUID, err)
		}
		for _, connector := range connectorData {
			if uuid, ok := connector["uuid_url"].(string); ok {
				connectors = append(connectors, uuid)
			} else {
				client.Logger.Warn("Connector entry missing uuid_url field", "connector", connector)
			}
		}
	}

	return connectors, nil
}

// GetConnectorNamesInPool retrieves the list of connector names currently in a connector pool
func GetConnectorNamesInPool(client *EaaClient, poolUUID string) ([]string, error) {

	connectorUUIDs, err := GetConnectorsInPool(client, poolUUID)
	if err != nil {
		client.Logger.Error("Failed to get connectors in pool", "error", err)
		return nil, err
	}

	// Get all agents to build a UUID-to-name mapping
	agents, err := GetAgents(client)
	if err != nil {
		client.Logger.Error("Failed to get agents", "error", err)
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
			// Found connector mapping
		}
		// else No agent found for connector UUID
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
func AssignConnectorPoolsToApp(ec *EaaClient, appUUID string, request *AppConnectorPoolAssignmentRequest) error {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, fmt.Sprintf(APP_CONNECTOR_POOLS_ASSOCIATE_URL, appUUID))

	resp, err := ec.SendAPIRequest(apiURL, "PUT", request, nil, false)
	if err != nil {
		ec.Logger.Error("Assignment API request failed", "error", err)
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(resp)
		assignmentErrMsg := fmt.Errorf("app connector pool assignment failed: %s", desc)
		ec.Logger.Error("Assignment failed", "status_code", resp.StatusCode, "error", desc)
		return assignmentErrMsg
	}

	return nil
}

// GetConnectorUUIDs maps connector names to UUIDs by fetching all agents with pagination and building a lookup table
func GetConnectorUUIDs(ec *EaaClient, connectorNames []string) ([]string, error) {
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

		resp, err := ec.SendAPIRequest(apiURL, "GET", nil, &response, false)
		if err != nil {
			ec.Logger.Error("Get agents API request failed", "error", err)
			return nil, ErrAgentsGet
		}

		// Set the API limit from the first response (if not already set)
		if offset == 0 {
			apiLimit = response.Meta.Limit
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(resp)
			getErrMsg := fmt.Errorf("get agents failed: %s", desc)
			ec.Logger.Error("Get agents failed", "status_code", resp.StatusCode, "error", desc)
			return nil, getErrMsg
		}

		// Convert response objects to Connector and add to results
		for _, agent := range response.Objects {
			if agent.Name == "" || agent.UUIDURL == "" {
				ec.Logger.Warn("Skipping agent with empty name or UUID", "name", agent.Name, "uuid", agent.UUIDURL)
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
			ec.Logger.Warn("Connector not found", "name", connectorName)
			notFoundConnectors = append(notFoundConnectors, connectorName)
		}
	}

	if len(notFoundConnectors) > 0 {
		ec.Logger.Error("Connectors not found", "connectors", notFoundConnectors)
		return nil, fmt.Errorf("connectors not found: %v", notFoundConnectors)
	}

	return connectorUUIDs, nil
}

// AssignConnectorsToPoolByName assigns connectors to a pool using connector names instead of UUIDs
func AssignConnectorsToPoolByName(client *EaaClient, poolUUID string, connectorNames []string) error {
	connectorUUIDs, err := GetConnectorUUIDs(client, connectorNames)
	if err != nil {
		client.Logger.Error("unable to lookup uuids from connector names", "error", err)
		return err
	}

	if len(connectorUUIDs) == 0 {
		return fmt.Errorf("no valid connectors found to assign")
	}

	return AssignConnectorsToPool(client, poolUUID, connectorUUIDs)
}

// UnassignConnectorsFromPoolByName removes connectors from a pool using connector names instead of UUIDs
func UnassignConnectorsFromPoolByName(ec *EaaClient, connectorPoolUUID string, connectorNames []string) error {

	connectorUUIDs, err := GetConnectorUUIDs(ec, connectorNames)
	if err != nil {
		ec.Logger.Error("Unable to lookup UUIDs from connector names", "error", err)
		return err
	}

	if len(connectorUUIDs) == 0 {
		ec.Logger.Error("No connectors to unassign")
		return nil
	}

	return UnassignConnectorsFromPool(ec, connectorPoolUUID, connectorUUIDs)
}

// App represents an application
type App struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

// GetApps retrieves all applications using smart pagination that reads meta information
// Uses the API's own limit and pagination information for optimal performance
func GetApps(client *EaaClient) ([]App, error) {
	var allApps []App
	offset := 0
	var apiLimit int // Will be set from API response meta

	for {
		// Build URL - first request without limit/offset, subsequent requests with API's limit
		var url string
		if offset == 0 {
			// First request: use v3 API with optimized parameters
			url = fmt.Sprintf("%s://%s/crux/v3/mgmt-pop/apps?limit=10&offset=0&fields=name,uuid_url&ordering=name",
				URL_SCHEME, client.Host)

		} else {
			// Subsequent requests: use the limit we got from API response meta
			url = fmt.Sprintf("%s://%s/crux/v3/mgmt-pop/apps?limit=%d&offset=%d&fields=name,uuid_url&ordering=name",
				URL_SCHEME, client.Host, apiLimit, offset)

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

		resp, err := client.SendAPIRequest(url, "GET", nil, &response, false)
		if err != nil {
			client.Logger.Error("Get apps API request failed", "error", err)
			return nil, err
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(resp)
			getErrMsg := fmt.Errorf("get apps failed: %s", desc)
			client.Logger.Error("Get apps failed", "status_code", resp.StatusCode, "error", desc)
			return nil, getErrMsg
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
func GetAppUUIDs(ec *EaaClient, appNames []string) ([]string, error) {

	apps, err := GetApps(ec)
	if err != nil {

		ec.Logger.Error("Failed to get apps from API", "error", err)
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
			ec.Logger.Error("App not found", "name", appName)
			notFoundApps = append(notFoundApps, appName)
		}
	}

	if len(notFoundApps) > 0 {
		ec.Logger.Error("Apps not found", "apps", notFoundApps)
		return nil, fmt.Errorf("apps not found: %v", notFoundApps)
	}

	return appUUIDs, nil
}

// AssignConnectorPoolToApps assigns a connector pool to multiple apps
func AssignConnectorPoolToApps(ec *EaaClient, poolUUID string, appNames []string) error {
	appUUIDs, err := GetAppUUIDs(ec, appNames)
	if err != nil {
		ec.Logger.Error("unable to lookup uuids from app names")
		return err
	}

	if len(appUUIDs) == 0 {
		ec.Logger.Error("no apps to assign")
		return fmt.Errorf("no valid apps found to assign")
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
		err := AssignConnectorPoolsToApp(ec, appUUID, request)
		if err != nil {
			ec.Logger.Error("Failed to assign pool to app", "app_uuid", appUUID, "error", err)
			errs = append(errs, fmt.Errorf("app %s: %w", appUUID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to assign pool to %d app(s): %w", len(errs), errors.Join(errs...))
	}
	return nil
}

// UnassignConnectorPoolFromApps removes a connector pool from multiple apps
func UnassignConnectorPoolFromApps(ec *EaaClient, poolUUID string, appNames []string) error {
	appUUIDs, err := GetAppUUIDs(ec, appNames)
	if err != nil {
		ec.Logger.Error("unable to lookup uuids from app names")
		return err
	}

	if len(appUUIDs) == 0 {
		ec.Logger.Error("no apps to unassign")
		return fmt.Errorf("no valid apps found to unassign")
	}

	ec.Logger.Info("Unassigning connector pool from apps", "count", len(appUUIDs), "apps", appNames)

	var errs []error
	for i, appUUID := range appUUIDs {
		ec.Logger.Info("Unassigning app", "index", i+1, "total", len(appUUIDs), "app_uuid", appUUID)

		request := &AppConnectorPoolAssignmentRequest{
			Add: AppConnectorPoolAssignment{
				Active:  []string{},
				Standby: []string{},
			},
			Delete: []string{poolUUID},
		}

		err := AssignConnectorPoolsToApp(ec, appUUID, request)
		if err != nil {
			ec.Logger.Error("Failed to unassign app", "app_uuid", appUUID, "error", err)
			errs = append(errs, fmt.Errorf("app %s: %w", appUUID, err))
			continue
		}

		ec.Logger.Info("Successfully unassigned app", "index", i+1, "total", len(appUUIDs), "app_uuid", appUUID)
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to unassign pool from %d app(s): %w", len(errs), errors.Join(errs...))
	}

	ec.Logger.Info("Successfully unassigned connector pool from all apps", "count", len(appUUIDs))
	return nil
}

// GetAppsAssignedToPool retrieves the list of app UUIDs currently assigned to a connector pool
func GetAppsAssignedToPool(client *EaaClient, poolUUID string) ([]string, error) {
	client.Logger.Info("Getting apps assigned to pool", "pool_uuid", poolUUID)

	// Use the same pattern as GetConnectorsInPool - read the connector pool object directly
	url := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, client.Host, CONNECTOR_POOLS_MGMT_URL, poolUUID)

	client.Logger.Info("Calling API", "url", url)

	var connectorPool ConnectorPool
	resp, err := client.SendAPIRequest(url, "GET", nil, &connectorPool, false)
	if err != nil {
		client.Logger.Error("Failed to get connector pool", "error", err)
		return nil, fmt.Errorf("failed to get connector pool: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			client.Logger.Warn("Failed to close connector pool response body", "error", closeErr)
		}
	}()

	client.Logger.Info("API Response Status", "status_code", resp.StatusCode)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(resp)
		getErrMsg := fmt.Errorf("get connector pool failed: %s", desc)
		client.Logger.Error("Get connector pool failed", "status_code", resp.StatusCode, "error", desc)
		return nil, getErrMsg
	}

	// Parse the applications from the JSON response, similar to how we parse connectors
	var assignedAppUUIDs []string
	if connectorPool.Applications != nil {
		// Parse the applications JSON to extract UUIDs
		var appData []map[string]interface{}
		if err := json.Unmarshal(connectorPool.Applications, &appData); err == nil {
			for _, app := range appData {
				if uuid, ok := app["uuid_url"].(string); ok {
					assignedAppUUIDs = append(assignedAppUUIDs, uuid)
					client.Logger.Info("Found app assigned to pool", "uuid", uuid)
				}
			}
		} else {
			client.Logger.Warn("Failed to parse applications JSON", "error", err)
		}
	}

	client.Logger.Info("Total apps assigned to pool", "count", len(assignedAppUUIDs))
	return assignedAppUUIDs, nil
}

// GetAppNamesAssignedToPool retrieves the list of app names currently assigned to a connector pool
func GetAppNamesAssignedToPool(client *EaaClient, poolUUID string) ([]string, error) {
	appUUIDs, err := GetAppsAssignedToPool(client, poolUUID)
	if err != nil {
		return nil, err
	}

	// Get all apps to build a UUID-to-name mapping
	apps, err := GetApps(client)
	if err != nil {
		return nil, err
	}

	// Build UUID-to-name lookup map
	uuidToName := make(map[string]string)
	for _, app := range apps {
		uuidToName[app.UUIDURL] = app.Name
	}

	// Map UUIDs back to names
	var appNames []string
	for _, uuid := range appUUIDs {
		if name, exists := uuidToName[uuid]; exists {
			appNames = append(appNames, name)
		}
	}

	return appNames, nil
}

// GetConnectorPools retrieves all connector pools using smart pagination that reads meta information
// Uses the API's own limit and pagination information for optimal performance
func GetConnectorPools(ctx context.Context, ec *EaaClient) ([]ConnectorPool, error) {
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
		resp, err := ec.SendAPIRequest(apiURL, "GET", nil, &response, false)
		if err != nil {
			ec.Logger.Error("Get connector pools API request failed", "error", err)
			return nil, err
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(resp)
			getErrMsg := fmt.Errorf("%w: %s", ErrConnectorPoolGet, desc)
			ec.Logger.Error("Get connector pools failed", "status_code", resp.StatusCode, "error", desc)
			return nil, getErrMsg
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
			ec.Logger.Warn("Reached maximum offset limit (10000). Stopping pagination.")
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
func AssignConnectorsToPoolFromSchema(d *schema.ResourceData, eaaclient *EaaClient, poolUUID string) error {
	connectors, ok := d.GetOk("connectors")
	if !ok {
		return nil
	}

	connectorsList, ok := connectors.([]interface{})
	if !ok {
		return fmt.Errorf("connectors must be a list, got %T", connectors)
	}
	var connectorNames []string
	for _, connector := range connectorsList {
		connectorName, ok := connector.(string)
		if !ok {
			return fmt.Errorf("connector name must be a string, got %T", connector)
		}
		connectorNames = append(connectorNames, connectorName)
	}

	if len(connectorNames) > 0 {
		err := AssignConnectorsToPoolByName(eaaclient, poolUUID, connectorNames)
		if err != nil {
			eaaclient.Logger.Error("Failed to assign connectors to pool:", err)
			return fmt.Errorf("failed to assign connectors to pool: %w", err)
		}
	}

	return nil
}

// AssignAppsToPoolFromSchema assigns apps to a connector pool from Terraform schema data
func AssignAppsToPoolFromSchema(d *schema.ResourceData, eaaclient *EaaClient, poolUUID string) error {
	apps, ok := d.GetOk("apps")
	if !ok {
		return nil
	}

	appsList, ok := apps.([]interface{})
	if !ok {
		return fmt.Errorf("apps must be a list, got %T", apps)
	}
	var appNames []string
	for _, app := range appsList {
		appName, ok := app.(string)
		if !ok {
			return fmt.Errorf("app name must be a string, got %T", app)
		}
		appNames = append(appNames, appName)
	}

	if len(appNames) > 0 {
		err := AssignConnectorPoolToApps(eaaclient, poolUUID, appNames)
		if err != nil {
			eaaclient.Logger.Error("Failed to assign apps to connector pool:", err)
			return fmt.Errorf("failed to assign apps to connector pool: %w", err)
		}
	}

	return nil
}
