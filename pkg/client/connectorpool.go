package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
		ec.Logger.Error("Invalid package_type:", packageTypeStr)
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
		ec.Logger.Error("Invalid infra_type:", infraTypeStr)
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
		ec.Logger.Error("Invalid operating_mode:", operatingModeStr)
		return 0, fmt.Errorf("invalid operating_mode '%s': %w", operatingModeStr, err)
	}

	return operatingModeInt, nil
}

// validateAndConvertEnumField validates and converts an enum field from string to int
func validateAndConvertEnumField(d *schema.ResourceData, fieldName string, converter func(string, *EaaClient) (int, error), ec *EaaClient) (*int, error) {
	if value, ok := d.GetOk(fieldName); ok {
		valueStr, ok := value.(string)
		if !ok {
			ec.Logger.Error(fmt.Sprintf("%s must be a string", fieldName))
			return nil, fmt.Errorf("%s must be a string, got %T", fieldName, value)
		}

		valueInt, err := converter(valueStr, ec)
		if err != nil {
			return nil, err
		}

		ec.Logger.Info(fmt.Sprintf("Setting %s to: %d", fieldName, valueInt))
		return &valueInt, nil
	}

	ec.Logger.Info(fmt.Sprintf("%s not found in schema, leaving as nil", fieldName))
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
	Name                    string          `json:"name"`
	Description             *string         `json:"description"`
	PackageType             int             `json:"package_type"`
	InfraType               int             `json:"infra_type"`
	OperatingMode           int             `json:"operating_mode"`
	UUIDURL                 string          `json:"uuid_url,omitempty"`
	CIDRs                   []string        `json:"cidrs,omitempty"`
	ApplicationAccessGroup  []string        `json:"application_access_group,omitempty"`
	ApplicationAccessGroups []string        `json:"application_access_groups,omitempty"`
	Applications            json.RawMessage `json:"applications,omitempty"`
	Connectors              json.RawMessage `json:"connectors,omitempty"`
	CreatedAt               string          `json:"created_at,omitempty"`
	Directories             []string        `json:"directories,omitempty"`
	DNSList                 []string        `json:"dns_list,omitempty"`
	DNSOverride             bool            `json:"dns_override,omitempty"`
	EDNS                    []string        `json:"edns,omitempty"`
	IsEnabled               bool            `json:"is_enabled,omitempty"`
	Localization            string          `json:"localization,omitempty"`
	LocationFreetext        *string         `json:"location_freetext,omitempty"`
	ModifiedAt              string          `json:"modified_at,omitempty"`
	ResourceURI             struct {
		Href string `json:"href,omitempty"`
	} `json:"resource_uri,omitempty"`
	SendAlerts bool `json:"send_alerts,omitempty"`
}

// CreateConnectorPoolRequest represents the request to create a connector pool
type CreateConnectorPoolRequest struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	PackageType   int    `json:"package_type"`
	InfraType     *int   `json:"infra_type,omitempty"`
	OperatingMode *int   `json:"operating_mode,omitempty"`
}

// CreateConnectorPoolResponse represents the response from creating a connector pool
type CreateConnectorPoolResponse struct {
	CIDRs         []string `json:"cidrs"`
	UUIDURL       string   `json:"uuid_url"`
	OperatingMode *int     `json:"operating_mode,omitempty"`
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
		desc, _ := FormatErrorResponse(resp)
		errMsg := fmt.Errorf("%s failed: %s", operation, desc)
		ec.Logger.Error(fmt.Sprintf("%s failed. StatusCode %d %s", operation, resp.StatusCode, desc))
		return errMsg
	}
	return nil
}

// ============================================================================
// CONNECTOR POOL CRUD OPERATIONS
// ============================================================================

// CreateConnectorPool creates a new connector pool
func (ccpr *CreateConnectorPoolRequest) CreateConnectorPool(ctx context.Context, ec *EaaClient, gid string) (*CreateConnectorPoolResponse, error) {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL)
	ec.Logger.Info("Creating connector pool with URL:", apiURL)

	var response CreateConnectorPoolResponse
	resp, err := ec.SendAPIRequest(apiURL, "POST", ccpr, &response, false)
	if err != nil {
		ec.Logger.Error("API request failed:", err)
		return nil, err
	}

	if err := handleConnectorPoolAPIResponse(resp, "create ConnectorPool", ec); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectorPoolCreate, err)
	}

	return &response, nil
}

// GetConnectorPool retrieves a connector pool by UUID
func GetConnectorPool(ctx context.Context, ec *EaaClient, uuid, gid string) (*ConnectorPool, error) {
	apiURL := buildConnectorPoolDetailURL(ec, uuid)
	ec.Logger.Info("Getting connector pool with URL:", apiURL)

	var connectorPool ConnectorPool
	resp, err := ec.SendAPIRequest(apiURL, "GET", nil, &connectorPool, false)
	if err != nil {
		ec.Logger.Error("Get API request failed:", err)
		return nil, err
	}

	if err := handleConnectorPoolAPIResponse(resp, "get ConnectorPool", ec); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectorPoolGet, err)
	}

	return &connectorPool, nil
}

// DeleteConnectorPool deletes a connector pool
func DeleteConnectorPool(ctx context.Context, ec *EaaClient, uuid, gid string) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, uuid)

	resp, err := ec.SendAPIRequest(apiURL, "DELETE", nil, nil, false)
	if err != nil {
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
	AgentInfraType int    `json:"agentInfraType"`
	CID            string `json:"cid"`
	UUIDURL        string `json:"uuid_url"`
}

// buildConnectorAssociationRequest builds a request for associating connectors with a pool
func buildConnectorAssociationRequest(connectorUUIDs []string) *ConnectorPoolAssociationRequest {
	var agents []AgentAssociation
	for _, connectorUUID := range connectorUUIDs {
		agent := AgentAssociation{
			AgentInfraType: 1, // Default value, adjust as needed
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

	client.Logger.Info("Assigning connectors to pool using URL:", url)

	// Use the helper function to build the request
	associationRequest := buildConnectorAssociationRequest(connectorUUIDs)

	resp, err := client.SendAPIRequest(url, "PUT", associationRequest, nil, false)
	if err != nil {
		client.Logger.Error("Assignment API request failed:", err)
		return err
	}

	if err := handleConnectorPoolAPIResponse(resp, "assign connectors to pool", client); err != nil {
		return err
	}

	client.Logger.Info("Successfully assigned connectors to pool")
	return nil
}

// UnassignConnectorsFromPool removes multiple connectors from a connector pool
func UnassignConnectorsFromPool(ec *EaaClient, connectorPoolUUID string, connectorUUIDs []string) error {
	// Use existing constants for URL building
	apiURL := fmt.Sprintf("%s://%s/%s/%s/agents/disassociate",
		URL_SCHEME, ec.Host, CONNECTOR_POOLS_URL, connectorPoolUUID)

	ec.Logger.Info("Unassigning connectors from pool using URL:", apiURL)

	// Create the disassociation request
	var agents []AgentAssociation
	for _, connectorUUID := range connectorUUIDs {
		agent := AgentAssociation{
			AgentInfraType: 1, // Default agent infrastructure type
			UUIDURL:        connectorUUID,
		}
		agents = append(agents, agent)
	}

	disassociationRequest := &ConnectorPoolAssociationRequest{
		Agents: agents,
	}

	resp, err := ec.SendAPIRequest(apiURL, "PUT", disassociationRequest, nil, false)
	if err != nil {
		ec.Logger.Error("Unassignment API request failed:", err)
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		unassignmentErrMsg := fmt.Errorf("connector pool unassignment failed: %s", desc)
		ec.Logger.Error("Unassignment failed with status:", resp.StatusCode, "error:", desc)
		return unassignmentErrMsg
	}

	return nil
}

// GetConnectorsInPool retrieves the list of connector UUIDs currently in a connector pool
func GetConnectorsInPool(client *EaaClient, poolUUID string) ([]string, error) {
	// Use existing constants for URL building
	url := fmt.Sprintf("%s://%s/%s/%s",
		URL_SCHEME, client.Host, CONNECTOR_POOLS_MGMT_URL, poolUUID)

	client.Logger.Info("Getting connectors in pool using URL:", url)

	var connectorPool ConnectorPool
	resp, err := client.SendAPIRequest(url, "GET", nil, &connectorPool, false)
	if err != nil {
		client.Logger.Error("Get connectors API request failed:", err)
		return nil, err
	}

	client.Logger.Info("Get connectors response status:", resp.StatusCode)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		getErrMsg := fmt.Errorf("get connectors in pool failed: %s", desc)
		client.Logger.Error("Get connectors failed with status:", resp.StatusCode, "error:", desc)
		return nil, getErrMsg
	}

	// Parse the connectors from the JSON response
	var connectors []string
	if connectorPool.Connectors != nil {
		// Parse the connectors JSON to extract UUIDs
		// This is a simplified approach - you might need to adjust based on the actual API response structure
		var connectorData []map[string]interface{}
		if err := json.Unmarshal(connectorPool.Connectors, &connectorData); err == nil {
			for _, connector := range connectorData {
				if uuid, ok := connector["uuid_url"].(string); ok {
					connectors = append(connectors, uuid)
				}
			}
		}
	}

	return connectors, nil
}

// GetConnectorNamesInPool retrieves the list of connector names currently in a connector pool
func GetConnectorNamesInPool(client *EaaClient, poolUUID string) ([]string, error) {
	connectorUUIDs, err := GetConnectorsInPool(client, poolUUID)
	if err != nil {
		return nil, err
	}

	// Get all agents to build a UUID-to-name mapping
	agents, err := GetAgents(client)
	if err != nil {
		return nil, err
	}

	// Build UUID-to-name lookup map
	uuidToName := make(map[string]string)
	for _, agent := range agents {
		uuidToName[agent.UUIDURL] = agent.Name
	}

	// Map UUIDs back to names
	var connectorNames []string
	for _, uuid := range connectorUUIDs {
		if name, exists := uuidToName[uuid]; exists {
			connectorNames = append(connectorNames, name)
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
func AssignConnectorPoolsToApp(ec *EaaClient, appUUID string, request *AppConnectorPoolAssignmentRequest) error {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, fmt.Sprintf(APP_CONNECTOR_POOLS_ASSOCIATE_URL, appUUID))

	ec.Logger.Info("Assigning connector pools to app using URL:", apiURL)

	resp, err := ec.SendAPIRequest(apiURL, "PUT", request, nil, false)
	if err != nil {
		ec.Logger.Error("Assignment API request failed:", err)
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		assignmentErrMsg := fmt.Errorf("app connector pool assignment failed: %s", desc)
		ec.Logger.Error("Assignment failed with status:", resp.StatusCode, "error:", desc)
		return assignmentErrMsg
	}

	return nil
}

// ============================================================================
// REGISTRATION TOKEN STRUCTURES AND FUNCTIONS








// GetConnectorUUIDs maps connector names to UUIDs by fetching all agents and building a lookup table
func GetConnectorUUIDs(ec *EaaClient, connectorNames []string) ([]string, error) {
	agents, err := GetAgents(ec)
	if err != nil {
		return nil, ErrAgentsGet
	}

	connectorUUIDs := make([]string, 0)
	notFoundConnectors := make([]string, 0)

	for _, connectorName := range connectorNames {
		found := false
		for _, agentData := range agents {
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
		return nil, fmt.Errorf("connectors not found: %v", notFoundConnectors)
	}

	return connectorUUIDs, nil
}

// AssignConnectorsToPoolByName assigns connectors to a pool using connector names instead of UUIDs
func AssignConnectorsToPoolByName(client *EaaClient, poolUUID string, connectorNames []string) error {
	connectorUUIDs, err := GetConnectorUUIDs(client, connectorNames)
	if err != nil {
		client.Logger.Error("unable to lookup uuids from connector names:", err)
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
		ec.Logger.Error("unable to lookup uuids from connector names")
		return err
	}

	if len(connectorUUIDs) == 0 {
		ec.Logger.Error("no connectors to unassign")
		return nil
	}

	return UnassignConnectorsFromPool(ec, connectorPoolUUID, connectorUUIDs)
}

// App represents an application
type App struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

// GetApps retrieves all applications using v3 API with field selection for efficiency
// Uses proper pagination to handle large numbers of applications efficiently
func GetApps(client *EaaClient) ([]App, error) {
	var allApps []App
	offset := 0
	limit := 100 // Use a reasonable batch size for efficient pagination
	
	for {
		// Build URL with v3 API, pagination, and field selection for efficiency
		// Only request the fields we need: name and uuid_url to minimize response size
		url := fmt.Sprintf("%s://%s/%s?limit=%d&offset=%d&fields=name,uuid_url", URL_SCHEME, client.Host, APPS_V3_URL, limit, offset)
		
		client.Logger.Info("Getting apps batch - offset:", offset, "limit:", limit, "total so far:", len(allApps))

		// Define the response structure inline to match the v3 API response
		var response struct {
			Meta struct {
				TotalCount int `json:"total_count"`
			} `json:"meta"`
			Objects []struct {
				Name    string `json:"name"`
				UUIDURL string `json:"uuid_url"`
			} `json:"objects"`
		}
		
		resp, err := client.SendAPIRequest(url, "GET", nil, &response, false)
		if err != nil {
			client.Logger.Error("Get apps API request failed:", err)
			return nil, err
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc, _ := FormatErrorResponse(resp)
			getErrMsg := fmt.Errorf("get apps failed: %s", desc)
			client.Logger.Error("Get apps failed with status:", resp.StatusCode, "error:", desc)
			return nil, getErrMsg
		}

		// Convert response objects to App and add to results
		for _, app := range response.Objects {
			allApps = append(allApps, App{
				Name:    app.Name,
				UUIDURL: app.UUIDURL,
			})
		}

		client.Logger.Info("Retrieved", len(response.Objects), "apps in this batch. Total so far:", len(allApps))

		// Check if we've retrieved all apps
		// If we got fewer apps than requested, we've reached the end
		if len(response.Objects) < limit {
			client.Logger.Info("Reached end of apps list. Final total:", len(allApps))
			break
		}

		// Move to next batch
		offset += limit
		
		// Safety check to prevent infinite loops
		if offset > 10000 {
			client.Logger.Warn("Reached maximum offset limit (10000). Stopping pagination.")
			break
		}
	}

	client.Logger.Info("Successfully retrieved all apps. Total count:", len(allApps))
	return allApps, nil
}

// GetAppUUIDs converts app names to UUIDs
func GetAppUUIDs(ec *EaaClient, appNames []string) ([]string, error) {
	apps, err := GetApps(ec)
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

	var lastErr error
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
			ec.Logger.Error("Failed to assign pool to app:", appUUID, err)
			lastErr = err
		}
	}
	return lastErr
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
		return nil
	}

	// Create unassignment request
	request := &AppConnectorPoolAssignmentRequest{
		Add: AppConnectorPoolAssignment{
			Active:  []string{},
			Standby: []string{},
		},
		Delete: []string{poolUUID},
	}

	return AssignConnectorPoolsToApp(ec, appUUIDs[0], request)
}

// GetAppsAssignedToPool retrieves the list of app UUIDs currently assigned to a connector pool
func GetAppsAssignedToPool(client *EaaClient, poolUUID string) ([]string, error) {
	client.Logger.Info("Getting apps assigned to pool:", poolUUID)

	// Use the apps API to get all apps and filter by connector_pools
	apiURL := fmt.Sprintf("%s://%s/%s?limit=100&offset=0&app_type__notin=5&fields=name,uuid_url,connector_pools&ordering=name",
		URL_SCHEME, client.Host, APPS_V3_URL)

	client.Logger.Info("Calling API:", apiURL)

	var appsResponse struct {
		Objects []struct {
			UUIDURL        string `json:"uuid_url"`
			Name           string `json:"name"`
			ConnectorPools []struct {
				UUIDURL string `json:"uuid_url"`
				Name    string `json:"name"`
			} `json:"connector_pools"`
		} `json:"objects"`
	}

	resp, err := client.SendAPIRequest(apiURL, "GET", nil, &appsResponse, false)
	if err != nil {
		client.Logger.Error("Failed to get apps:", err)
		return nil, fmt.Errorf("failed to get apps: %w", err)
	}
	defer resp.Body.Close()

	var assignedAppUUIDs []string
	for _, app := range appsResponse.Objects {
		for _, pool := range app.ConnectorPools {
			if pool.UUIDURL == poolUUID {
				assignedAppUUIDs = append(assignedAppUUIDs, app.UUIDURL)
				client.Logger.Info("Found app assigned to pool:", app.Name, "(", app.UUIDURL, ")")
				break
			}
		}
	}

	client.Logger.Info("Total apps assigned to pool:", len(assignedAppUUIDs))
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

// GetConnectorPools retrieves all connector pools with pagination support
func GetConnectorPools(ctx context.Context, ec *EaaClient) ([]ConnectorPool, error) {
	var allPools []ConnectorPool
	offset := 0
	limit := 100 // Use a reasonable batch size
	
	for {
		// Build URL with pagination parameters
		apiURL := fmt.Sprintf("%s://%s/%s?limit=%d&offset=%d", URL_SCHEME, ec.Host, CONNECTOR_POOLS_MGMT_URL, limit, offset)
		
		ec.Logger.Info("Getting connector pools list with URL:", apiURL)

		type connectorPoolsListResponse struct {
			Objects []ConnectorPool `json:"objects"`
		}

		var response connectorPoolsListResponse
		resp, err := ec.SendAPIRequest(apiURL, "GET", nil, &response, false)
		if err != nil {
			ec.Logger.Error("Get connector pools API request failed:", err)
			return nil, err
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			desc, _ := FormatErrorResponse(resp)
			getErrMsg := fmt.Errorf("%w: %s", ErrConnectorPoolGet, desc)
			ec.Logger.Error("Get connector pools failed with status:", resp.StatusCode, "error:", desc)
			return nil, getErrMsg
		}

		// Add pools from this batch to results
		allPools = append(allPools, response.Objects...)

		ec.Logger.Info("Retrieved", len(response.Objects), "connector pools in this batch. Total so far:", len(allPools))

		// Check if we've retrieved all pools
		if len(response.Objects) < limit {
			// This was the last batch
			break
		}

		// Move to next batch
		offset += limit
	}

	ec.Logger.Info("Total connector pools retrieved:", len(allPools))
	return allPools, nil
}

// CallConnectorPoolGetAPI calls the connector pool GET API using mgmt-pop endpoint and returns the response as structured object
func CallConnectorPoolGetAPI(eaaclient *EaaClient, uuidURL string) (map[string]interface{}, error) {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, eaaclient.Host, CONNECTOR_POOLS_MGMT_URL, uuidURL)

	eaaclient.Logger.Info("Calling GET API with URL:", apiURL)

	// Parse JSON response into a map to preserve exact structure
	var responseMap map[string]interface{}
	resp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &responseMap, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	eaaclient.Logger.Info("GET API response status:", resp.StatusCode)
	eaaclient.Logger.Info("GET API response body:", fmt.Sprintf("%+v", responseMap))

	return responseMap, nil
}

// GetAppsForPool retrieves apps associated with a connector pool
func GetAppsForPool(eaaclient *EaaClient, poolUUID string) []interface{} {
	if poolUUID == "" {
		return []interface{}{}
	}

	// Get app UUIDs assigned to this pool
	appUUIDs, err := GetAppsAssignedToPool(eaaclient, poolUUID)
	if err != nil {
		eaaclient.Logger.Warn("Failed to get apps for pool %s: %v", poolUUID, err)
		return []interface{}{}
	}

	// Get all apps to lookup names
	allApps, err := GetApps(eaaclient)
	if err != nil {
		eaaclient.Logger.Warn("Failed to get all apps for name lookup: %v", err)
		// Continue without names if we can't get the full list
	}

	// Create a map for quick lookup
	uuidToNameMap := make(map[string]string)
	for _, app := range allApps {
		uuidToNameMap[app.UUIDURL] = app.Name
	}

	var appsList []interface{}
	for _, appUUID := range appUUIDs {
		appName := uuidToNameMap[appUUID] // Will be empty string if not found
		appData := map[string]interface{}{
			"name":     appName,
			"uuid_url": appUUID,
		}
		appsList = append(appsList, appData)
	}

	return appsList
}

// ConvertConnectorPoolToMap converts a ConnectorPool to a map for Terraform schema
func ConvertConnectorPoolToMap(pool *ConnectorPool, eaaclient *EaaClient) map[string]interface{} {
	// Convert enum fields using type system with error checking
	packageTypeStr := ConvertIntToEnumStringForDataSource(pool.PackageType, func(i int) (string, error) {
		return ConnPackageTypeInt(i).String()
	})
	// Check if conversion failed (returned integer string instead of enum string)
	if packageTypeStr == fmt.Sprintf("%d", pool.PackageType) {
		eaaclient.Logger.Warn("Unknown package type value: %d for connector pool: %s", pool.PackageType, pool.Name)
	}

	infraTypeStr := ConvertIntToEnumStringForDataSource(pool.InfraType, func(i int) (string, error) {
		return InfraTypeInt(i).String()
	})
	// Check if conversion failed (returned integer string instead of enum string)
	if infraTypeStr == fmt.Sprintf("%d", pool.InfraType) {
		eaaclient.Logger.Warn("Unknown infra type value: %d for connector pool: %s", pool.InfraType, pool.Name)
	}

	operatingModeStr := ConvertIntToEnumStringForDataSource(pool.OperatingMode, func(i int) (string, error) {
		return OperatingModeInt(i).String()
	})
	// Check if conversion failed (returned integer string instead of enum string)
	if operatingModeStr == fmt.Sprintf("%d", pool.OperatingMode) {
		eaaclient.Logger.Warn("Unknown operating mode value: %d for connector pool: %s", pool.OperatingMode, pool.Name)
	}

	// Handle optional description field
	description := ""
	if pool.Description != nil {
		description = *pool.Description
	}

	// Get registration tokens for this pool
	var registrationTokens []interface{}
	tokens, err := eaaclient.GetRegistrationTokens(pool.UUIDURL)
	if err != nil {
		eaaclient.Logger.Warn("Failed to get registration tokens for pool %s: %v", pool.UUIDURL, err)
	} else {
		// Sort tokens by name to ensure consistent ordering
		sort.Slice(tokens, func(i, j int) bool {
			return tokens[i].Name < tokens[j].Name
		})

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
			registrationTokens = append(registrationTokens, tokenMap)
		}
	}

	return map[string]interface{}{
		"name":                pool.Name,
		"description":         description,
		"connectors":          ConvertConnectorsToMap(pool.Connectors),
		"apps":                GetAppsForPool(eaaclient, pool.UUIDURL),
		"uuid_url":            pool.UUIDURL,
		"package_type":        packageTypeStr,
		"infra_type":          infraTypeStr,
		"operating_mode":      operatingModeStr,
		"created_at":          pool.CreatedAt,
		"modified_at":         pool.ModifiedAt,
		"is_enabled":          pool.IsEnabled,
		"send_alerts":         pool.SendAlerts,
		"registration_tokens": registrationTokens,
	}
}

// SetConnectorPoolBasicAttributes sets the basic attributes of a connector pool in the schema
func SetConnectorPoolBasicAttributes(d *schema.ResourceData, connPool *ConnectorPool) {
	d.Set("name", connPool.Name)
	
	// Handle optional description field
	description := ""
	if connPool.Description != nil {
		description = *connPool.Description
	}
	d.Set("description", description)
	
	d.Set("uuid_url", connPool.UUIDURL)

	// Convert package_type from int back to string using type system
	packageTypeStr := ConvertIntToEnumString(connPool.PackageType, func(i int) (string, error) {
		return ConnPackageTypeInt(i).String()
	})
	d.Set("package_type", packageTypeStr)

	// Convert infra_type from int back to string using type system
	if connPool.InfraType != 0 {
		infraTypeStr := ConvertIntToEnumString(connPool.InfraType, func(i int) (string, error) {
			return InfraTypeInt(i).String()
		})
		d.Set("infra_type", infraTypeStr)
	}

	// Convert operating_mode from int back to string using type system
	if connPool.OperatingMode != 0 {
		operatingModeStr := ConvertIntToEnumString(connPool.OperatingMode, func(i int) (string, error) {
			return OperatingModeInt(i).String()
		})
		d.Set("operating_mode", operatingModeStr)
	}
}

// ============================================================================
// STATE MIGRATION FUNCTIONS
// ============================================================================

// ConnectorPoolStateUpgradeV0 upgrades connector pool state from version 0 to version 1
// This function removes API response fields from state that are no longer needed
func ConnectorPoolStateUpgradeV0(ctx context.Context, rawState map[string]interface{}, meta interface{}) (map[string]interface{}, error) {
	// Remove API response fields from state if they exist
	delete(rawState, "connector_pool_create_api_response")
	delete(rawState, "connector_pool_get_api_response")
	delete(rawState, "app_access_groups_api_response")

	return rawState, nil
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

	connectorsList := connectors.([]interface{})
	var connectorNames []string
	for _, connector := range connectorsList {
		connectorNames = append(connectorNames, connector.(string))
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

	appsList := apps.([]interface{})
	var appNames []string
	for _, app := range appsList {
		appNames = append(appNames, app.(string))
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
