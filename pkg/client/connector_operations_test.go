package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

// TestGetConnectorUUIDs tests the GetConnectorUUIDs function with various scenarios
func TestGetConnectorUUIDs(t *testing.T) {
	tests := []struct {
		name           string
		connectorNames []string
		responseCode   int
		responseBody   string
		expectedError  bool
		expectedUUIDs  []string
	}{
		{
			name:           "successful connector UUID retrieval",
			connectorNames: []string{"connector1", "connector2"},
			responseCode:   200,
			responseBody:   `{"meta": {"limit": 20, "offset": 0, "total_count": 2}, "objects": [{"uuid_url": "uuid1", "name": "connector1"}, {"uuid_url": "uuid2", "name": "connector2"}]}`,
			expectedError:  false,
			expectedUUIDs:  []string{"uuid1", "uuid2"},
		},
		{
			name:           "empty connector names",
			connectorNames: []string{},
			responseCode:   200,
			responseBody:   `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`,
			expectedError:  false,
			expectedUUIDs:  []string{},
		},
		{
			name:           "server error",
			connectorNames: []string{"connector1"},
			responseCode:   500,
			responseBody:   `{"error": "internal server error"}`,
			expectedError:  true,
		},
		{
			name:           "invalid JSON response",
			connectorNames: []string{"connector1"},
			responseCode:   200,
			responseBody:   `invalid json`,
			expectedError:  true,
		},
		{
			name:           "bad request",
			connectorNames: []string{"connector1"},
			responseCode:   400,
			responseBody:   `{"error": "bad request"}`,
			expectedError:  true,
		},
		{
			name:           "unauthorized",
			connectorNames: []string{"connector1"},
			responseCode:   401,
			responseBody:   `{"error": "unauthorized"}`,
			expectedError:  true,
		},
		{
			name:           "forbidden",
			connectorNames: []string{"connector1"},
			responseCode:   403,
			responseBody:   `{"error": "forbidden"}`,
			expectedError:  true,
		},
		{
			name:           "not found",
			connectorNames: []string{"connector1"},
			responseCode:   404,
			responseBody:   `{"error": "not found"}`,
			expectedError:  true,
		},
		{
			name:           "connector name not found in response",
			connectorNames: []string{"connector1", "nonexistent-connector"},
			responseCode:   200,
			responseBody:   `{"meta": {"limit": 20, "offset": 0, "total_count": 1}, "objects": [{"uuid_url": "uuid1", "name": "connector1"}]}`,
			expectedError:  true, // Function returns error when any connector is not found
		},
		{
			name:           "no connectors found",
			connectorNames: []string{"nonexistent-connector"},
			responseCode:   200,
			responseBody:   `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`,
			expectedError:  true, // Function returns error when connector is not found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/agents")

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Test GetConnectorUUIDs
			uuids, err := GetConnectorUUIDs(ec, tt.connectorNames)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUUIDs, uuids)
			}
		})
	}
}

// Removed problematic tests that use undefined types

// TestAssignConnectorsToPool tests the AssignConnectorsToPool function
func TestAssignConnectorsToPool(t *testing.T) {
	tests := []struct {
		name           string
		poolUUID       string
		connectorUUIDs []string
		responseCode   int
		responseBody   string
		expectedError  bool
	}{
		{
			name:           "successful connector assignment",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1", "conn-2"},
			responseCode:   200,
			responseBody:   `{"success": true}`,
			expectedError:  false,
		},
		{
			name:           "assignment with invalid pool ID",
			poolUUID:       "invalid-pool",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   404,
			responseBody:   `{"error": "pool not found"}`,
			expectedError:  true,
		},
		{
			name:           "assignment with server error",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   500,
			responseBody:   `{"error": "internal server error"}`,
			expectedError:  true,
		},
		{
			name:           "assignment with empty connector list",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{},
			responseCode:   200,
			responseBody:   `{"success": true}`,
			expectedError:  false,
		},
		{
			name:           "assignment with bad request",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   400,
			responseBody:   `{"error": "bad request"}`,
			expectedError:  true,
		},
		{
			name:           "assignment with unauthorized",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   401,
			responseBody:   `{"error": "unauthorized"}`,
			expectedError:  true,
		},
		{
			name:           "assignment with forbidden",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   403,
			responseBody:   `{"error": "forbidden"}`,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/zt/connector-pools/")
				assert.Contains(t, r.URL.Path, "/agents/associate")

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Test AssignConnectorsToPool
			err := AssignConnectorsToPool(ec, tt.poolUUID, tt.connectorUUIDs)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestUnassignConnectorsFromPool tests the UnassignConnectorsFromPool function
func TestUnassignConnectorsFromPool(t *testing.T) {
	tests := []struct {
		name           string
		poolUUID       string
		connectorUUIDs []string
		responseCode   int
		responseBody   string
		expectedError  bool
	}{
		{
			name:           "successful connector unassignment",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1", "conn-2"},
			responseCode:   200,
			responseBody:   `{"success": true}`,
			expectedError:  false,
		},
		{
			name:           "unassignment with invalid pool ID",
			poolUUID:       "invalid-pool",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   404,
			responseBody:   `{"error": "pool not found"}`,
			expectedError:  true,
		},
		{
			name:           "unassignment with server error",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   500,
			responseBody:   `{"error": "internal server error"}`,
			expectedError:  true,
		},
		{
			name:           "unassignment with bad request",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   400,
			responseBody:   `{"error": "bad request"}`,
			expectedError:  true,
		},
		{
			name:           "unassignment with unauthorized",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   401,
			responseBody:   `{"error": "unauthorized"}`,
			expectedError:  true,
		},
		{
			name:           "unassignment with forbidden",
			poolUUID:       "pool-123",
			connectorUUIDs: []string{"conn-1"},
			responseCode:   403,
			responseBody:   `{"error": "forbidden"}`,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/zt/connector-pools/")
				assert.Contains(t, r.URL.Path, "/agents/disassociate")

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Test UnassignConnectorsFromPool
			err := UnassignConnectorsFromPool(ec, tt.poolUUID, tt.connectorUUIDs)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAppIdpAssignIDP tests the AssignIDP method on AppIdp struct
func TestAppIdpAssignIDP(t *testing.T) {
	tests := []struct {
		name          string
		appID         string
		idpID         string
		responseCode  int
		responseBody  string
		expectedError bool
	}{
		{
			name:          "successful IDP assignment",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  200,
			responseBody:  `{"success": true}`,
			expectedError: false,
		},
		{
			name:          "assignment with empty app ID",
			appID:         "",
			idpID:         "idp-456",
			responseCode:  400,
			responseBody:  `{"error": "app ID required"}`,
			expectedError: true,
		},
		{
			name:          "assignment with empty IDP ID",
			appID:         "app-123",
			idpID:         "",
			responseCode:  400,
			responseBody:  `{"error": "IDP ID required"}`,
			expectedError: true,
		},
		{
			name:          "assignment with server error",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  500,
			responseBody:  `{"error": "internal server error"}`,
			expectedError: true,
		},
		{
			name:          "assignment with unauthorized",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  401,
			responseBody:  `{"error": "unauthorized"}`,
			expectedError: true,
		},
		{
			name:          "assignment with forbidden",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  403,
			responseBody:  `{"error": "forbidden"}`,
			expectedError: true,
		},
		{
			name:          "assignment with not found",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  404,
			responseBody:  `{"error": "not found"}`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/appidp")

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Create AppIdp instance
			appIdp := &AppIdp{
				App: tt.appID,
				IDP: tt.idpID,
			}

			// Test AssignIDP
			err := appIdp.AssignIDP(ec)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAppIdpUnAssignIDP tests the UnAssignIDP method on AppIdp struct
func TestAppIdpUnAssignIDP(t *testing.T) {
	tests := []struct {
		name          string
		appID         string
		idpID         string
		responseCode  int
		responseBody  string
		expectedError bool
	}{
		{
			name:          "successful IDP unassignment",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  200,
			responseBody:  `{"success": true}`,
			expectedError: false,
		},
		{
			name:          "unassignment with empty app ID",
			appID:         "",
			idpID:         "idp-456",
			responseCode:  400,
			responseBody:  `{"error": "app ID required"}`,
			expectedError: true,
		},
		{
			name:          "unassignment with empty IDP ID",
			appID:         "app-123",
			idpID:         "",
			responseCode:  400,
			responseBody:  `{"error": "IDP ID required"}`,
			expectedError: true,
		},
		{
			name:          "unassignment with server error",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  500,
			responseBody:  `{"error": "internal server error"}`,
			expectedError: true,
		},
		{
			name:          "unassignment with unauthorized",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  401,
			responseBody:  `{"error": "unauthorized"}`,
			expectedError: true,
		},
		{
			name:          "unassignment with forbidden",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  403,
			responseBody:  `{"error": "forbidden"}`,
			expectedError: true,
		},
		{
			name:          "unassignment with not found",
			appID:         "app-123",
			idpID:         "idp-456",
			responseCode:  404,
			responseBody:  `{"error": "not found"}`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method) // UnAssignIDP uses POST, not PUT
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/appidp")
				assert.Contains(t, r.URL.RawQuery, "method=DELETE")

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Create AppIdp instance
			appIdp := &AppIdp{
				App: tt.appID,
				IDP: tt.idpID,
			}

			// Test UnAssignIDP
			err := appIdp.UnAssignIDP(ec)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetConnectorsInPool tests the GetConnectorsInPool function
func TestGetConnectorsInPool(t *testing.T) {
	tests := []struct {
		name          string
		poolUUID      string
		responseCode  int
		responseBody  string
		expectedError bool
		expectedUUIDs []string
	}{
		{
			name:          "successful connectors retrieval",
			poolUUID:      "pool-123",
			responseCode:  200,
			responseBody:  `{"connectors": [{"uuid_url": "conn-1", "name": "connector1"}, {"uuid_url": "conn-2", "name": "connector2"}]}`,
			expectedError: false,
			expectedUUIDs: []string{"conn-1", "conn-2"},
		},
		{
			name:          "empty connectors list",
			poolUUID:      "pool-123",
			responseCode:  200,
			responseBody:  `{"connectors": []}`,
			expectedError: false,
			expectedUUIDs: nil, // Function returns nil for empty list, not empty slice
		},
		{
			name:          "pool not found",
			poolUUID:      "pool-nonexistent",
			responseCode:  404,
			responseBody:  `{"error": "connector pool not found"}`,
			expectedError: true,
		},
		{
			name:          "server error",
			poolUUID:      "pool-123",
			responseCode:  500,
			responseBody:  `{"error": "internal server error"}`,
			expectedError: true,
		},
		{
			name:          "bad request",
			poolUUID:      "pool-123",
			responseCode:  400,
			responseBody:  `{"error": "bad request"}`,
			expectedError: true,
		},
		{
			name:          "unauthorized",
			poolUUID:      "pool-123",
			responseCode:  401,
			responseBody:  `{"error": "unauthorized"}`,
			expectedError: true,
		},
		{
			name:          "forbidden",
			poolUUID:      "pool-123",
			responseCode:  403,
			responseBody:  `{"error": "forbidden"}`,
			expectedError: true,
		},
		{
			name:          "invalid JSON response",
			poolUUID:      "pool-123",
			responseCode:  200,
			responseBody:  `invalid json`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := fmt.Sprintf("/crux/v1/mgmt-pop/connector-pools/%s", tt.poolUUID)
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Test GetConnectorsInPool
			result, err := GetConnectorsInPool(ec, tt.poolUUID)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUUIDs, result)
			}
		})
	}
}

// TestGetConnectorNamesInPool tests the GetConnectorNamesInPool function
func TestGetConnectorNamesInPool(t *testing.T) {
	tests := []struct {
		name          string
		poolUUID      string
		responseCode  int
		responseBody  string
		agentsResponse string
		expectedError bool
		expectedNames []string
	}{
		{
			name:          "successful connector names retrieval",
			poolUUID:      "pool-123",
			responseCode:  200,
			responseBody:  `{"connectors": [{"uuid_url": "conn-1", "name": "connector1"}, {"uuid_url": "conn-2", "name": "connector2"}]}`,
			agentsResponse: `{"meta": {"limit": 20, "offset": 0, "total_count": 2}, "objects": [{"uuid_url": "conn-1", "name": "connector1"}, {"uuid_url": "conn-2", "name": "connector2"}]}`,
			expectedError: false,
			expectedNames: []string{"connector1", "connector2"},
		},
		{
			name:          "pool not found",
			poolUUID:      "pool-nonexistent",
			responseCode:  404,
			responseBody:  `{"error": "connector pool not found"}`,
			agentsResponse: `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`,
			expectedError: true,
		},
		{
			name:          "server error",
			poolUUID:      "pool-123",
			responseCode:  500,
			responseBody:  `{"error": "internal server error"}`,
			agentsResponse: `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`,
			expectedError: true,
		},
		{
			name:          "bad request",
			poolUUID:      "pool-123",
			responseCode:  400,
			responseBody:  `{"error": "bad request"}`,
			agentsResponse: `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`,
			expectedError: true,
		},
		{
			name:          "unauthorized",
			poolUUID:      "pool-123",
			responseCode:  401,
			responseBody:  `{"error": "unauthorized"}`,
			agentsResponse: `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`,
			expectedError: true,
		},
		{
			name:          "forbidden",
			poolUUID:      "pool-123",
			responseCode:  403,
			responseBody:  `{"error": "forbidden"}`,
			agentsResponse: `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server that handles both connector pool and agents endpoints
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/crux/v1/mgmt-pop/agents" {
					// Mock agents response
					w.WriteHeader(200)
					agentsResp := tt.agentsResponse
					if agentsResp == "" {
						agentsResp = `{"meta": {"limit": 20, "offset": 0, "total_count": 0}, "objects": []}`
					}
					w.Write([]byte(agentsResp))
					return
				}

				// For connector pool requests
				assert.Equal(t, "GET", r.Method)
				expectedPath := fmt.Sprintf("/crux/v1/mgmt-pop/connector-pools/%s", tt.poolUUID)
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Test GetConnectorNamesInPool
			result, err := GetConnectorNamesInPool(ec, tt.poolUUID)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedNames == nil {
					assert.Nil(t, result)
				} else {
					assert.Equal(t, tt.expectedNames, result)
				}
			}
		})
	}
}

// TestAssignConnectorPoolsToApp tests the AssignConnectorPoolsToApp function
func TestAssignConnectorPoolsToApp(t *testing.T) {
	tests := []struct {
		name          string
		appUUID       string
		poolUUIDs     []string
		responseCode  int
		responseBody  string
		expectedError bool
	}{
		{
			name:          "successful pool assignment",
			appUUID:       "app-123",
			poolUUIDs:     []string{"pool-1", "pool-2"},
			responseCode:  200,
			responseBody:  `{"success": true}`,
			expectedError: false,
		},
		{
			name:          "assignment with invalid app UUID",
			appUUID:       "invalid-app",
			poolUUIDs:     []string{"pool-1"},
			responseCode:  404,
			responseBody:  `{"error": "application not found"}`,
			expectedError: true,
		},
		{
			name:          "assignment with empty pool list",
			appUUID:       "app-123",
			poolUUIDs:     []string{},
			responseCode:  200,
			responseBody:  `{"success": true}`,
			expectedError: false,
		},
		{
			name:          "assignment with server error",
			appUUID:       "app-123",
			poolUUIDs:     []string{"pool-1"},
			responseCode:  500,
			responseBody:  `{"error": "internal server error"}`,
			expectedError: true,
		},
		{
			name:          "assignment with bad request",
			appUUID:       "app-123",
			poolUUIDs:     []string{"pool-1"},
			responseCode:  400,
			responseBody:  `{"error": "bad request"}`,
			expectedError: true,
		},
		{
			name:          "assignment with unauthorized",
			appUUID:       "app-123",
			poolUUIDs:     []string{"pool-1"},
			responseCode:  401,
			responseBody:  `{"error": "unauthorized"}`,
			expectedError: true,
		},
		{
			name:          "assignment with forbidden",
			appUUID:       "app-123",
			poolUUIDs:     []string{"pool-1"},
			responseCode:  403,
			responseBody:  `{"error": "forbidden"}`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/apps/")
				assert.Contains(t, r.URL.Path, "/connector-pools/associate") // Correct path format

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create EaaClient
			ec := &EaaClient{
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
				Host:   server.URL[8:], // Remove https://
				Logger: hclog.NewNullLogger(),
				Signer: &MockSigner{},
			}

			// Create assignment request
			request := &AppConnectorPoolAssignmentRequest{
				Add: AppConnectorPoolAssignment{
					Active: tt.poolUUIDs,
				},
			}

			// Test AssignConnectorPoolsToApp
			err := AssignConnectorPoolsToApp(ec, tt.appUUID, request)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
