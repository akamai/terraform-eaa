package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateConnectorPool tests connector pool creation functionality
func TestCreateConnectorPool(t *testing.T) {
	tests := map[string]struct {
		request        *CreateConnectorPoolRequest
		mockResponse   string
		mockStatusCode int
		expectError    bool
		expectedUUID   string
		errorContains  string
	}{
		"successful connector pool creation": {
			request: &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "Test connector pool",
				PackageType: 1, // vmware
			},
			mockResponse:   `{"uuid_url": "pool-uuid-123", "cidrs": ["10.0.0.0/8"]}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedUUID:   "pool-uuid-123",
		},
		"successful creation with all fields": {
			request: &CreateConnectorPoolRequest{
				Name:          "full-pool",
				Description:   "Full connector pool",
				PackageType:   1,
				InfraType:     intPtr(1),
				OperatingMode: intPtr(1),
			},
			mockResponse:   `{"uuid_url": "pool-uuid-456", "cidrs": ["10.0.0.0/8"]}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedUUID:   "pool-uuid-456",
		},
		"creation conflict": {
			request: &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "Test connector pool",
				PackageType: 1,
			},
			mockResponse:   `{"type": "error", "title": "Conflict", "detail": "Pool with this name already exists"}`,
			mockStatusCode: http.StatusConflict,
			expectError:    true,
			errorContains:  "create ConnectorPool failed",
		},
		"validation error": {
			request: &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "Test connector pool",
				PackageType: 1,
			},
			mockResponse:   `{"type": "validation_error", "title": "Bad Request", "detail": "Invalid pool configuration"}`,
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "create ConnectorPool failed",
		},
		"server error": {
			request: &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "Test connector pool",
				PackageType: 1,
			},
			mockResponse:   `{"type": "error", "title": "Internal Server Error", "detail": "Internal server error"}`,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "create ConnectorPool failed",
		},
		"unauthorized error": {
			request: &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "Test connector pool",
				PackageType: 1,
			},
			mockResponse:   `{"type": "error", "title": "Unauthorized", "detail": "Authentication failed"}`,
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "create ConnectorPool failed",
		},
		"forbidden error": {
			request: &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "Test connector pool",
				PackageType: 1,
			},
			mockResponse:   `{"type": "error", "title": "Forbidden", "detail": "Access denied"}`,
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "create ConnectorPool failed",
		},
		"network error": {
			request: &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "Test connector pool",
				PackageType: 1,
			},
			mockResponse:   "",
			mockStatusCode: 0, // Will cause network error
			expectError:    true,
		},
	}

		for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var server *httptest.Server
			
			// Only create server if not testing network error
			if tt.mockStatusCode != 0 {
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, http.MethodPost, r.Method)
					assert.Contains(t, r.URL.Path, "connector-pools")
					
					// Verify request body
					var reqBody CreateConnectorPoolRequest
					err := json.NewDecoder(r.Body).Decode(&reqBody)
					require.NoError(t, err)
					assert.Equal(t, tt.request.Name, reqBody.Name)
					
					w.WriteHeader(tt.mockStatusCode)
					if tt.mockResponse != "" {
						w.Write([]byte(tt.mockResponse))
					}
				}))
				defer server.Close()
			}

			// Create client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           &http.Client{},
				Signer:           &MockSigner{},
				Host:             "invalid-host-that-will-fail",
				Logger:           hclog.NewNullLogger(),
			}
			
			// Use server URL if server was created
			if server != nil {
				// Create HTTP client that skips TLS verification for test server
				httpClient := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}
				client.Client = httpClient
				// Extract host from server URL (remove https:// prefix)
				client.Host = server.URL[8:]
			}

			// Test CreateConnectorPool
			result, err := tt.request.CreateConnectorPool(context.Background(), client)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.expectedUUID != "" {
					assert.Equal(t, tt.expectedUUID, result.UUIDURL)
				}
			}
		})
	}
}

// Helper function to create int pointers
func intPtr(i int) *int {
	return &i
}

// TestGetConnectorPool tests connector pool retrieval functionality
func TestGetConnectorPool(t *testing.T) {
	tests := []struct {
		name           string
		poolUUID       string
		mockResponse   string
		mockStatusCode int
		expectError    bool
	}{
		{
			name:     "successful connector pool retrieval",
			poolUUID: "pool-uuid-123",
			mockResponse: `{
				"uuid_url": "pool-uuid-123",
				"name": "test-pool",
				"description": "Test connector pool",
				"status": 1,
				"package_type": 1,
				"infra_type": 1
			}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "connector pool not found",
			poolUUID:       "non-existent-uuid",
			mockResponse:   `{"error": "Connector pool not found"}`,
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
		},
		{
			name:           "invalid UUID format",
			poolUUID:       "invalid-uuid",
			mockResponse:   `{"error": "Invalid UUID format"}`,
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "unauthorized",
			poolUUID:       "pool-uuid-123",
			mockResponse:   `{"error": "Unauthorized"}`,
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name:           "forbidden",
			poolUUID:       "pool-uuid-123",
			mockResponse:   `{"error": "Forbidden"}`,
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
		},
		{
			name:           "server error",
			poolUUID:       "pool-uuid-123",
			mockResponse:   `{"error": "Internal server error"}`,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
		{
			name:           "invalid JSON response",
			poolUUID:       "pool-uuid-123",
			mockResponse:   `invalid json`,
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
	}

		for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Contains(t, r.URL.Path, tt.poolUUID)

				w.WriteHeader(tt.mockStatusCode)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			// Create HTTP client that skips TLS verification for test server
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			// Create client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           httpClient,
				Signer:           &MockSigner{},
				Host:             server.URL[8:], // Remove https:// prefix
				Logger:           hclog.NewNullLogger(),
			}

			// Test GetConnectorPool
			result, err := GetConnectorPool(context.Background(), client, tt.poolUUID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// TestDeleteConnectorPool tests connector pool deletion functionality
func TestDeleteConnectorPool(t *testing.T) {
	tests := map[string]struct {
		poolUUID       string
		mockStatusCode int
		mockResponse   string
		expectError    bool
		errorContains  string
	}{
		"successful connector pool deletion": {
			poolUUID:       "pool-uuid-123",
			mockStatusCode: http.StatusOK,
			mockResponse:   "",
			expectError:    false,
		},
		"successful deletion with no content": {
			poolUUID:       "pool-uuid-456",
			mockStatusCode: http.StatusNoContent,
			mockResponse:   "",
			expectError:    false,
		},
		"connector pool not found": {
			poolUUID:       "non-existent-uuid",
			mockStatusCode: http.StatusNotFound,
			mockResponse:   `{"type": "error", "title": "Not Found", "detail": "Connector pool not found"}`,
			expectError:    true,
			errorContains:  "delete ConnectorPool failed",
		},
		"deletion forbidden - pool in use": {
			poolUUID:       "active-pool-uuid",
			mockStatusCode: http.StatusConflict,
			mockResponse:   `{"type": "error", "title": "Conflict", "detail": "Pool is in use"}`,
			expectError:    true,
			errorContains:  "delete ConnectorPool failed",
		},
		"server error": {
			poolUUID:       "pool-uuid-789",
			mockStatusCode: http.StatusInternalServerError,
			mockResponse:   `{"type": "error", "title": "Internal Server Error", "detail": "Internal server error"}`,
			expectError:    true,
			errorContains:  "delete ConnectorPool failed",
		},
		"unauthorized error": {
			poolUUID:       "pool-uuid-999",
			mockStatusCode: http.StatusUnauthorized,
			mockResponse:   `{"type": "error", "title": "Unauthorized", "detail": "Authentication failed"}`,
			expectError:    true,
			errorContains:  "delete ConnectorPool failed",
		},
		"forbidden error": {
			poolUUID:       "pool-uuid-888",
			mockStatusCode: http.StatusForbidden,
			mockResponse:   `{"type": "error", "title": "Forbidden", "detail": "Access denied"}`,
			expectError:    true,
			errorContains:  "delete ConnectorPool failed",
		},
		"bad request": {
			poolUUID:       "pool-uuid-777",
			mockStatusCode: http.StatusBadRequest,
			mockResponse:   `{"type": "error", "title": "Bad Request", "detail": "Invalid request"}`,
			expectError:    true,
			errorContains:  "delete ConnectorPool failed",
		},
		"network error": {
			poolUUID:       "pool-uuid-000",
			mockStatusCode: 0, // Will cause network error
			mockResponse:   "",
			expectError:    true,
		},
	}

		for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var server *httptest.Server
			
			// Only create server if not testing network error
			if tt.mockStatusCode != 0 {
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, http.MethodDelete, r.Method)
					assert.Contains(t, r.URL.Path, tt.poolUUID)

					w.WriteHeader(tt.mockStatusCode)
					if tt.mockResponse != "" {
						w.Write([]byte(tt.mockResponse))
					}
				}))
				defer server.Close()
			}

			// Create client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           &http.Client{},
				Signer:           &MockSigner{},
				Host:             "invalid-host-that-will-fail",
				Logger:           hclog.NewNullLogger(),
			}
			
			// Use server URL if server was created
			if server != nil {
				// Create HTTP client that skips TLS verification for test server
				httpClient := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}
				client.Client = httpClient
				// Extract host from server URL (remove https:// prefix)
				client.Host = server.URL[8:]
			}

			// Test DeleteConnectorPool
			err := DeleteConnectorPool(context.Background(), client, tt.poolUUID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetConnectorPools tests connector pools listing functionality
func TestGetConnectorPools(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   string
		mockStatusCode int
		expectError    bool
		expectedCount  int
	}{
		{
			name: "successful connector pools retrieval",
			mockResponse: `{
				"meta": {
					"limit": 100,
					"offset": 0,
					"total_count": 2
				},
				"objects": [
					{
						"uuid_url": "pool-uuid-1",
						"name": "pool-1",
						"status": 1
					},
					{
						"uuid_url": "pool-uuid-2", 
						"name": "pool-2",
						"status": 1
					}
				]
			}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  2,
		},
		{
			name: "empty connector pools list",
			mockResponse: `{
				"meta": {
					"limit": 100,
					"offset": 0,
					"total_count": 0
				},
				"objects": []
			}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
		{
			name:           "server error",
			mockResponse:   `{"error": "Internal server error"}`,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedCount:  0,
		},
		{
			name:           "bad request",
			mockResponse:   `{"error": "Bad request"}`,
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedCount:  0,
		},
		{
			name:           "unauthorized",
			mockResponse:   `{"error": "Unauthorized"}`,
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			expectedCount:  0,
		},
		{
			name:           "forbidden",
			mockResponse:   `{"error": "Forbidden"}`,
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			expectedCount:  0,
		},
		{
			name:           "not found",
			mockResponse:   `{"error": "Not found"}`,
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedCount:  0,
		},
		{
			name:           "invalid JSON response",
			mockResponse:   `invalid json`,
			mockStatusCode: http.StatusOK,
			expectError:    true,
			expectedCount:  0,
		},
	}

		for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Contains(t, r.URL.Path, "connector-pools")

				w.WriteHeader(tt.mockStatusCode)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			// Create HTTP client that skips TLS verification for test server
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			// Extract host from server URL properly
			parsedURL, err := url.Parse(server.URL)
			var host string
			if err == nil {
				host = parsedURL.Host
			} else {
				host = server.URL[8:] // Fallback: remove https:// prefix
			}

			// Create client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           httpClient,
				Signer:           &MockSigner{},
				Host:             host,
				Logger:           hclog.NewNullLogger(),
			}

			// Test GetConnectorPools
			result, err := GetConnectorPools(context.Background(), client)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedCount > 0 {
					assert.NotNil(t, result)
					assert.Equal(t, tt.expectedCount, len(result))
				} else {
					// Empty list can be nil or empty slice
					if result != nil {
						assert.Equal(t, 0, len(result))
					}
				}
			}
		})
	}
}

