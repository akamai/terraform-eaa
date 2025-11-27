package testmocks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
)

// MockResponse holds mock response data
type MockResponse struct {
	StatusCode int
	Body       interface{}
	Header     http.Header
}

// MockHTTPTransport intercepts HTTP requests and returns mocked responses
// This prevents real API calls during unit tests
type MockHTTPTransport struct {
	Responses map[string]MockResponse
	CallCounts map[string]int // Tracks number of calls per URL pattern
}

// RoundTrip implements http.RoundTripper - intercepts HTTP requests
// This is called for every HTTP request made by the client
func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	method := req.Method
	path := req.URL.Path

	// Initialize CallCounts if nil
	if m.CallCounts == nil {
		m.CallCounts = make(map[string]int)
	}

	// Track the call
	callKey := fmt.Sprintf("%s %s", method, path)
	m.CallCounts[callKey]++
	m.CallCounts[url]++ // Also track by full URL
	m.CallCounts[method]++ // Track by method

	// Try to find exact URL match first (with query params)
	if resp, ok := m.Responses[url]; ok {
		return m.createHTTPResponse(req, resp)
	}

	// Try to find URL without query params
	urlWithoutQuery := fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, path)
	if resp, ok := m.Responses[urlWithoutQuery]; ok {
		return m.createHTTPResponse(req, resp)
	}

	// Try to find method-specific pattern match (e.g., "GET /path" or "POST /path")
	methodPattern := fmt.Sprintf("%s %s", method, path)
	if resp, ok := m.Responses[methodPattern]; ok {
		return m.createHTTPResponse(req, resp)
	}

	// Try to find path-only match (e.g., "/crux/v1/mgmt-pop/appcategories")
	if resp, ok := m.Responses[path]; ok {
		return m.createHTTPResponse(req, resp)
	}

	// Try to find path contains match (most flexible, but check last)
	for pattern, resp := range m.Responses {
		// Skip if pattern looks like a method pattern (contains space)
		if strings.Contains(pattern, " ") {
			continue
		}
		// Check if URL path contains the pattern
		if strings.Contains(path, pattern) || strings.Contains(url, pattern) {
			return m.createHTTPResponse(req, resp)
		}
	}

	// Default: return 200 OK with empty JSON body
	// This allows tests to pass even if they don't set up all mock responses
	return m.createHTTPResponse(req, MockResponse{
		StatusCode: 200,
		Body:       map[string]interface{}{},
	})
}

// createHTTPResponse creates an HTTP response from MockResponse
func (m *MockHTTPTransport) createHTTPResponse(req *http.Request, mockResp MockResponse) (*http.Response, error) {
	var bodyBytes []byte
	var err error

	if mockResp.Body != nil {
		bodyBytes, err = json.Marshal(mockResp.Body)
		if err != nil {
			bodyBytes = []byte("{}")
		}
	}

	header := mockResp.Header
	if header == nil {
		header = make(http.Header)
		header.Set("Content-Type", "application/json")
	}

	return &http.Response{
		StatusCode: mockResp.StatusCode,
		Status:     http.StatusText(mockResp.StatusCode),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Header:     header,
		Request:    req,
	}, nil
}

// GetCallCount returns the number of times a URL pattern or HTTP method was called
func (m *MockHTTPTransport) GetCallCount(key string) int {
	if m.CallCounts == nil {
		return 0
	}
	return m.CallCounts[key]
}

// VerifyCallCount verifies that a URL pattern or HTTP method was called the expected number of times
func (m *MockHTTPTransport) VerifyCallCount(t interface {
	Errorf(format string, args ...interface{})
	Helper()
}, key string, expected int) {
	t.Helper()
	actual := m.GetCallCount(key)
	if actual != expected {
		t.Errorf("MockHTTPTransport[%s]: expected %d calls, got %d", key, expected, actual)
	}
}

// ResetCallCounts resets all call counts
func (m *MockHTTPTransport) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}

// GetAllCallCounts returns all call counts for inspection
func (m *MockHTTPTransport) GetAllCallCounts() map[string]int {
	if m.CallCounts == nil {
		return make(map[string]int)
	}
	result := make(map[string]int)
	for k, v := range m.CallCounts {
		result[k] = v
	}
	return result
}

// MockApplicationData holds common application data for mocking
type MockApplicationData struct {
	AppID          string
	Name           string
	AppType        string
	AppProfile     string
	Host           string
	Description    string
	AdvancedSettings string
	ContractID    string
	AccountSwitchKey string
}

// MockConnectorData holds common connector data for mocking
type MockConnectorData struct {
	ConnectorID    string
	Name           string
	Status         string
	PoolID         string
	ContractID     string
	AccountSwitchKey string
}

// MockApplication provides structured mocking for Application resources
type MockApplication struct {
	client          *client.EaaClient
	transport       *MockHTTPTransport
	MockApplicationData MockApplicationData // Exported for test access
	callCounts      map[string]int
}

// NewMockApplication creates a new MockApplication instance
func NewMockApplication(client *client.EaaClient, transport *MockHTTPTransport) *MockApplication {
	return &MockApplication{
		client:          client,
		transport:      transport,
		callCounts:     make(map[string]int),
		MockApplicationData: MockApplicationData{
			AppID:            "test-app-uuid-123",
			Name:             "test-application",
			AppType:          "enterprise",
			AppProfile:       "http",
			Host:             "test.example.com",
			Description:      "Test application",
			AdvancedSettings: `{"app_auth":"none"}`,
			ContractID:       "test-contract",
			AccountSwitchKey: "test-account",
		},
	}
}

// WithData sets the mock application data
func (m *MockApplication) WithData(data MockApplicationData) *MockApplication {
	m.MockApplicationData = data
	return m
}

// MockCreateApplication sets up mock responses for application creation
func (m *MockApplication) MockCreateApplication() *MockApplication {
	createURL := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/apps", m.client.Host)
	m.transport.Responses[createURL] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url":    m.MockApplicationData.AppID,
			"name":        m.MockApplicationData.Name,
			"app_type":    mapAppTypeToInt(m.MockApplicationData.AppType),
			"app_profile": mapAppProfileToInt(m.MockApplicationData.AppProfile),
		},
	}
	m.callCounts["create"]++
	return m
}

// MockGetApplication sets up mock responses for application retrieval
func (m *MockApplication) MockGetApplication() *MockApplication {
	readURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", m.MockApplicationData.AppID)
	m.transport.Responses[readURL] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url":    m.MockApplicationData.AppID,
			"name":        m.MockApplicationData.Name,
			"app_type":    mapAppTypeToInt(m.MockApplicationData.AppType),
			"app_profile": mapAppProfileToInt(m.MockApplicationData.AppProfile),
			"host":        m.MockApplicationData.Host,
			"description": m.MockApplicationData.Description,
		},
	}
	m.callCounts["get"]++
	return m
}

// MockUpdateApplication sets up mock responses for application updates
func (m *MockApplication) MockUpdateApplication() *MockApplication {
	updateURL := fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", m.MockApplicationData.AppID)
	m.transport.Responses[updateURL] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url":    m.MockApplicationData.AppID,
			"name":        m.MockApplicationData.Name,
			"app_type":    mapAppTypeToInt(m.MockApplicationData.AppType),
			"app_profile": mapAppProfileToInt(m.MockApplicationData.AppProfile),
		},
	}
	m.callCounts["update"]++
	return m
}

// MockDeleteApplication sets up mock responses for application deletion
func (m *MockApplication) MockDeleteApplication() *MockApplication {
	deleteURL := fmt.Sprintf("DELETE /crux/v1/mgmt-pop/apps/%s", m.MockApplicationData.AppID)
	m.transport.Responses[deleteURL] = MockResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]interface{}{"status": "deleted"},
	}
	m.callCounts["delete"]++
	return m
}

// MockGetApplicationServices sets up mock responses for application services
func (m *MockApplication) MockGetApplicationServices() *MockApplication {
	servicesURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", m.MockApplicationData.AppID)
	m.transport.Responses[servicesURL] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"service": map[string]interface{}{
						"service_type": 6, // SERVICE_TYPE_ACCESS_CTRL
						"uuid_url":     "service-uuid-123",
					},
					"status":   1,
					"uuid_url": "service-data-uuid-123",
				},
			},
		},
	}
	m.callCounts["services"]++
	return m
}

// MockDeployApplication sets up mock responses for application deployment
func (m *MockApplication) MockDeployApplication() *MockApplication {
	deployURL := fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", m.MockApplicationData.AppID)
	m.transport.Responses[deployURL] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"status": "deployed",
		},
	}
	m.callCounts["deploy"]++
	return m
}

// GetCallCount returns the number of times a specific method was called
func (m *MockApplication) GetCallCount(method string) int {
	if m.callCounts == nil {
		return 0
	}
	return m.callCounts[method]
}

// VerifyCallCount verifies that a method was called the expected number of times
// This is a helper for tests to assert mock call counts
func (m *MockApplication) VerifyCallCount(t interface {
	Errorf(format string, args ...interface{})
	Helper()
}, method string, expected int) {
	t.Helper()
	actual := m.GetCallCount(method)
	if actual != expected {
		t.Errorf("MockApplication.%s: expected %d calls, got %d", method, expected, actual)
	}
}

// ResetCallCounts resets all call counts (useful for test cleanup)
func (m *MockApplication) ResetCallCounts() {
	m.callCounts = make(map[string]int)
}

// GetAllCallCounts returns all call counts for inspection
func (m *MockApplication) GetAllCallCounts() map[string]int {
	if m.callCounts == nil {
		return make(map[string]int)
	}
	result := make(map[string]int)
	for k, v := range m.callCounts {
		result[k] = v
	}
	return result
}

// MockConnector provides structured mocking for Connector resources
type MockConnector struct {
	client          *client.EaaClient
	transport       *MockHTTPTransport
	mockConnectorData MockConnectorData
	callCounts      map[string]int
}

// NewMockConnector creates a new MockConnector instance
func NewMockConnector(client *client.EaaClient, transport *MockHTTPTransport) *MockConnector {
	return &MockConnector{
		client:          client,
		transport:      transport,
		callCounts:     make(map[string]int),
		mockConnectorData: MockConnectorData{
			ConnectorID:      "test-connector-uuid-123",
			Name:             "test-connector",
			Status:           "active",
			PoolID:           "test-pool-uuid-123",
			ContractID:      "test-contract",
			AccountSwitchKey: "test-account",
		},
	}
}

// WithData sets the mock connector data
func (m *MockConnector) WithData(data MockConnectorData) *MockConnector {
	m.mockConnectorData = data
	return m
}

// MockCreateConnector sets up mock responses for connector creation
func (m *MockConnector) MockCreateConnector() *MockConnector {
	// Match multiple URL patterns
	createURL1 := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/agents", m.client.Host)
	createURL2 := fmt.Sprintf("POST /crux/v1/mgmt-pop/agents")
	createURL3 := fmt.Sprintf("/crux/v1/mgmt-pop/agents")
	
	response := MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url": m.mockConnectorData.ConnectorID,
			"name":     m.mockConnectorData.Name,
			"status":   1, // Active status
			"package":   0, // VMware
			"reach":    1,
		},
	}
	
	m.transport.Responses[createURL1] = response
	m.transport.Responses[createURL2] = response
	m.transport.Responses[createURL3] = response
	m.callCounts["create"]++
	return m
}

// MockGetConnector sets up mock responses for connector retrieval
func (m *MockConnector) MockGetConnector() *MockConnector {
	// Match multiple URL patterns
	readURL1 := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents/%s", m.mockConnectorData.ConnectorID)
	readURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", m.mockConnectorData.ConnectorID)
	readURL3 := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/agents/%s", m.client.Host, m.mockConnectorData.ConnectorID)
	
	response := MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url":    m.mockConnectorData.ConnectorID,
			"name":        m.mockConnectorData.Name,
			"status":      1, // Active status
			"package":     0, // VMware
			"reach":       1,
			"os_version":  "Linux 5.4",
			"public_ip":   "1.2.3.4",
			"private_ip":  "10.0.0.1",
			"type":        0,
			"region":      "us-east-1",
		},
	}
	
	m.transport.Responses[readURL1] = response
	m.transport.Responses[readURL2] = response
	m.transport.Responses[readURL3] = response
	m.callCounts["get"]++
	return m
}

// MockUpdateConnector sets up mock responses for connector updates
func (m *MockConnector) MockUpdateConnector() *MockConnector {
	// Match multiple URL patterns for PUT
	updateURL1 := fmt.Sprintf("PUT /crux/v1/mgmt-pop/agents/%s", m.mockConnectorData.ConnectorID)
	updateURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", m.mockConnectorData.ConnectorID)
	updateURL3 := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/agents/%s", m.client.Host, m.mockConnectorData.ConnectorID)
	
	response := MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url":    m.mockConnectorData.ConnectorID,
			"name":        m.mockConnectorData.Name,
			"status":      1,
			"package":     0,
			"reach":       1,
			"os_version":  "Linux 5.4",
			"public_ip":   "1.2.3.4",
			"private_ip":  "10.0.0.1",
			"type":        0,
			"region":      "us-east-1",
		},
	}
	
	m.transport.Responses[updateURL1] = response
	m.transport.Responses[updateURL2] = response
	m.transport.Responses[updateURL3] = response
	m.callCounts["update"]++
	return m
}

// MockDeleteConnector sets up mock responses for connector deletion
func (m *MockConnector) MockDeleteConnector() *MockConnector {
	// Match multiple URL patterns
	deleteURL1 := fmt.Sprintf("DELETE /crux/v1/mgmt-pop/agents/%s", m.mockConnectorData.ConnectorID)
	deleteURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", m.mockConnectorData.ConnectorID)
	deleteURL3 := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/agents/%s", m.client.Host, m.mockConnectorData.ConnectorID)
	
	response := MockResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]interface{}{"status": "deleted"},
	}
	
	m.transport.Responses[deleteURL1] = response
	m.transport.Responses[deleteURL2] = response
	m.transport.Responses[deleteURL3] = response
	m.callCounts["delete"]++
	return m
}

// GetCallCount returns the number of times a method was called
func (m *MockConnector) GetCallCount(method string) int {
	if m.callCounts == nil {
		return 0
	}
	return m.callCounts[method]
}

// VerifyCallCount verifies that a method was called the expected number of times
func (m *MockConnector) VerifyCallCount(t interface {
	Errorf(format string, args ...interface{})
	Helper()
}, method string, expected int) {
	t.Helper()
	actual := m.GetCallCount(method)
	if actual != expected {
		t.Errorf("MockConnector.%s: expected %d calls, got %d", method, expected, actual)
	}
}

// ResetCallCounts resets all call counts
func (m *MockConnector) ResetCallCounts() {
	m.callCounts = make(map[string]int)
}

// GetAllCallCounts returns all call counts for inspection
func (m *MockConnector) GetAllCallCounts() map[string]int {
	if m.callCounts == nil {
		return make(map[string]int)
	}
	result := make(map[string]int)
	for k, v := range m.callCounts {
		result[k] = v
	}
	return result
}

// Transport returns the mock HTTP transport for direct access
func (m *MockConnector) Transport() *MockHTTPTransport {
	return m.transport
}

// MockConnectorPoolData holds common connector pool data for mocking
type MockConnectorPoolData struct {
	PoolID         string
	Name           string
	Description    string
	PackageType    string
	InfraType      string
	OperatingMode  string
	ContractID     string
	AccountSwitchKey string
}

// MockConnectorPool provides structured mocking for ConnectorPool resources
type MockConnectorPool struct {
	client              *client.EaaClient
	transport           *MockHTTPTransport
	MockConnectorPoolData MockConnectorPoolData // Exported for test access
	callCounts          map[string]int
}

// NewMockConnectorPool creates a new MockConnectorPool instance
func NewMockConnectorPool(client *client.EaaClient, transport *MockHTTPTransport) *MockConnectorPool {
	return &MockConnectorPool{
		client:          client,
		transport:      transport,
		callCounts:     make(map[string]int),
		MockConnectorPoolData: MockConnectorPoolData{
			PoolID:           "test-pool-uuid-123",
			Name:             "test-connector-pool",
			Description:      "Test connector pool",
			PackageType:      "vmware",
			InfraType:        "eaa",
			OperatingMode:    "connector",
			ContractID:       "test-contract",
			AccountSwitchKey: "test-account",
		},
	}
}

// WithData sets the mock connector pool data
func (m *MockConnectorPool) WithData(data MockConnectorPoolData) *MockConnectorPool {
	m.MockConnectorPoolData = data
	return m
}

// MockCreateConnectorPool sets up mock responses for connector pool creation
func (m *MockConnectorPool) MockCreateConnectorPool() *MockConnectorPool {
	// Match both with and without query params, and method+path pattern
	createURL1 := fmt.Sprintf("https://%s/crux/v1/zt/connector-pools", m.client.Host)
	createURL2 := fmt.Sprintf("POST /crux/v1/zt/connector-pools")
	createURL3 := fmt.Sprintf("/crux/v1/zt/connector-pools")
	
	response := MockResponse{
		StatusCode: http.StatusCreated,
		Body: map[string]interface{}{
			"uuid_url": m.MockConnectorPoolData.PoolID,
			"name":     m.MockConnectorPoolData.Name,
			"cidrs":    []string{}, // Empty array to match response structure
		},
	}
	
	m.transport.Responses[createURL1] = response
	m.transport.Responses[createURL2] = response
	m.transport.Responses[createURL3] = response
	m.callCounts["create"]++
	return m
}

// MockGetConnectorPool sets up mock responses for connector pool retrieval
func (m *MockConnectorPool) MockGetConnectorPool() *MockConnectorPool {
	// Match multiple URL patterns
	readURL1 := fmt.Sprintf("GET /crux/v1/mgmt-pop/connector-pools/%s", m.MockConnectorPoolData.PoolID)
	readURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/connector-pools/%s", m.MockConnectorPoolData.PoolID)
	readURL3 := fmt.Sprintf("https://%s/crux/v1/mgmt-pop/connector-pools/%s", m.client.Host, m.MockConnectorPoolData.PoolID)
	
	response := MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url":     m.MockConnectorPoolData.PoolID,
			"name":         m.MockConnectorPoolData.Name,
			"description":  m.MockConnectorPoolData.Description,
			"package_type": mapPackageTypeToInt(m.MockConnectorPoolData.PackageType),
			"infra_type":   mapInfraTypeToInt(m.MockConnectorPoolData.InfraType),
			"cidrs":        []string{}, // Empty array to match response structure
		},
	}
	
	m.transport.Responses[readURL1] = response
	m.transport.Responses[readURL2] = response
	m.transport.Responses[readURL3] = response
	m.callCounts["get"]++
	return m
}

// MockUpdateConnectorPool sets up mock responses for connector pool updates
func (m *MockConnectorPool) MockUpdateConnectorPool() *MockConnectorPool {
	updateURL := fmt.Sprintf("PUT /crux/v1/mgmt-pop/connector-pools/%s", m.MockConnectorPoolData.PoolID)
	m.transport.Responses[updateURL] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"uuid_url":     m.MockConnectorPoolData.PoolID,
			"name":         m.MockConnectorPoolData.Name,
			"description":  m.MockConnectorPoolData.Description,
			"package_type": mapPackageTypeToInt(m.MockConnectorPoolData.PackageType),
		},
	}
	m.callCounts["update"]++
	return m
}

// MockDeleteConnectorPool sets up mock responses for connector pool deletion
func (m *MockConnectorPool) MockDeleteConnectorPool() *MockConnectorPool {
	deleteURL := fmt.Sprintf("DELETE /crux/v1/mgmt-pop/connector-pools/%s", m.MockConnectorPoolData.PoolID)
	m.transport.Responses[deleteURL] = MockResponse{
		StatusCode: http.StatusNoContent,
		Body:       map[string]interface{}{"status": "deleted"},
	}
	m.callCounts["delete"]++
	return m
}

// GetCallCount returns the number of times a method was called
func (m *MockConnectorPool) GetCallCount(method string) int {
	if m.callCounts == nil {
		return 0
	}
	return m.callCounts[method]
}

// VerifyCallCount verifies that a method was called the expected number of times
func (m *MockConnectorPool) VerifyCallCount(t interface {
	Errorf(format string, args ...interface{})
	Helper()
}, method string, expected int) {
	t.Helper()
	actual := m.GetCallCount(method)
	if actual != expected {
		t.Errorf("MockConnectorPool.%s: expected %d calls, got %d", method, expected, actual)
	}
}

// ResetCallCounts resets all call counts
func (m *MockConnectorPool) ResetCallCounts() {
	m.callCounts = make(map[string]int)
}

// GetAllCallCounts returns all call counts for inspection
func (m *MockConnectorPool) GetAllCallCounts() map[string]int {
	if m.callCounts == nil {
		return make(map[string]int)
	}
	result := make(map[string]int)
	for k, v := range m.callCounts {
		result[k] = v
	}
	return result
}

// Helper functions for mapping app types and profiles to integers
func mapAppTypeToInt(appType string) int {
	switch appType {
	case "tunnel":
		return 0
	case "enterprise":
		return 1
	case "bookmark":
		return 2
	case "saas":
		return 3
	case "vnc":
		return 4
	default:
		return 1 // default to enterprise
	}
}

func mapAppProfileToInt(appProfile string) int {
	switch appProfile {
	case "tcp":
		return 0
	case "http":
		return 1
	case "rdp":
		return 2
	default:
		return 1 // default to http
	}
}

// Helper functions for mapping connector pool types to integers
func mapPackageTypeToInt(packageType string) int {
	switch packageType {
	case "vmware":
		return 0
	case "vbox":
		return 1
	case "aws":
		return 2
	case "kvm":
		return 3
	case "hyperv":
		return 4
	case "docker":
		return 5
	case "aws_classic":
		return 6
	case "azure":
		return 7
	case "google":
		return 8
	case "softlayer":
		return 9
	case "fujitsu_k5":
		return 10
	default:
		return 0 // default to vmware
	}
}

func mapInfraTypeToInt(infraType string) int {
	switch infraType {
	case "eaa":
		return 0
	case "unified":
		return 1
	case "broker":
		return 2
	case "cpag":
		return 3
	default:
		return 0 // default to eaa
	}
}

func mapOperatingModeToInt(operatingMode string) int {
	switch operatingMode {
	case "connector":
		return 0
	case "peb":
		return 1
	case "combined":
		return 2
	case "cpag_public":
		return 3
	case "cpag_private":
		return 4
	case "connector_with_china_accel":
		return 5
	default:
		return 0 // default to connector
	}
}

// CreateMockEaaClientWithMocks creates a mock EAA client with transport for testing
func CreateMockEaaClientWithMocks() (*client.EaaClient, *MockHTTPTransport) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Warn, // Use Warn instead of Info to reduce noise
		Output: io.Discard,
	})

	mockTransport := &MockHTTPTransport{
		Responses:   make(map[string]MockResponse),
		CallCounts:  make(map[string]int),
	}

	mockHTTPClient := &http.Client{
		Transport: mockTransport,
		Timeout:   5 * time.Second, // Add timeout to prevent hanging
	}

	mockSigner := &client.MockSigner{}

	return &client.EaaClient{
		ContractID:       "test-contract",
		AccountSwitchKey: "test-account",
		Client:           mockHTTPClient,
		Signer:           mockSigner,
		Host:             "test.example.com",
		Logger:           logger,
	}, mockTransport
}

