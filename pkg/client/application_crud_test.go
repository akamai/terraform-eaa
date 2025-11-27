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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create string pointers
func strPtr(s string) *string {
	return &s
}

// Helper function to extract host from server URL for testing
func getHostFromServerURL(serverURL string) string {
	parsed, _ := url.Parse(serverURL)
	return parsed.Host
}

// TestApplicationCreate tests the core application creation functionality
func TestApplicationCreate(t *testing.T) {
	tests := map[string]struct {
		request        *CreateAppRequest
		mockResponse   string
		mockStatusCode int
		expectError    bool
		expectedUUID   string
		errorContains  string
	}{
		"successful application creation": {
			request: &CreateAppRequest{
				Name:          "test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"uuid_url": "test-app-uuid-123", "name": "test-app", "app_status": 1}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedUUID:   "test-app-uuid-123",
		},
		"successful creation with all fields": {
			request: &CreateAppRequest{
				Name:          "full-app",
				Description:   strPtr("Full application"),
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
				SAML:          true,
			},
			mockResponse:   `{"uuid_url": "full-app-uuid-456", "name": "full-app", "app_status": 1}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedUUID:   "full-app-uuid-456",
		},
		"server error response": {
			request: &CreateAppRequest{
				Name:          "test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"type": "error", "title": "Internal Server Error", "detail": "Internal server error"}`,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "app creation failed",
		},
		"validation error response": {
			request: &CreateAppRequest{
				Name:          "test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"type": "validation_error", "title": "Bad Request", "detail": "Name is required"}`,
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "app creation failed",
		},
		"unauthorized error": {
			request: &CreateAppRequest{
				Name:          "test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"type": "error", "title": "Unauthorized", "detail": "Authentication failed"}`,
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "app creation failed",
		},
		"not found error": {
			request: &CreateAppRequest{
				Name:          "test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"type": "error", "title": "Not Found", "detail": "Resource not found"}`,
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "app creation failed",
		},
		"network error": {
			request: &CreateAppRequest{
				Name:          "test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
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
					assert.Contains(t, r.URL.Path, "apps")
					
					// Verify request body
					var reqBody CreateAppRequest
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
				// Extract host from server URL properly
				parsedURL, err := url.Parse(server.URL)
				if err == nil {
					client.Host = parsedURL.Host
				} else {
					// Fallback: remove https:// prefix (8 characters)
					client.Host = server.URL[8:]
				}
			}

			// Test CreateApplication
			result, err := tt.request.CreateApplication(context.Background(), client)

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

// TestApplicationUpdate tests application update functionality
func TestApplicationUpdate(t *testing.T) {
	tests := map[string]struct {
		appUUID        string
		mockResponse   string
		mockStatusCode int
		expectError    bool
	}{
		"successful application update": {
			appUUID:        "test-app-uuid-123",
			mockResponse:   `{"uuid_url": "test-app-uuid-123", "name": "updated-app", "app_status": 1}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		"application not found": {
			appUUID:        "non-existent-uuid",
			mockResponse:   `{"error": "Application not found"}`,
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
		},
		"bad request error": {
			appUUID:        "invalid-app-uuid",
			mockResponse:   `{"type": "validation_error", "title": "Bad Request", "detail": "Invalid update data"}`,
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
		},
		"server error": {
			appUUID:        "server-error-uuid",
			mockResponse:   `{"type": "error", "title": "Internal Server Error", "detail": "Internal server error"}`,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
		"unauthorized error": {
			appUUID:        "unauthorized-uuid",
			mockResponse:   `{"type": "error", "title": "Unauthorized", "detail": "Authentication failed"}`,
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
		},
		"forbidden error": {
			appUUID:        "forbidden-uuid",
			mockResponse:   `{"type": "error", "title": "Forbidden", "detail": "Access denied"}`,
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPut, r.Method)
				assert.Contains(t, r.URL.Path, tt.appUUID)

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

			// Create client with just the host part of the server URL
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           httpClient,
				Signer:           &MockSigner{},
				Host:             host,
				Logger:           hclog.NewNullLogger(),
			}

			// Create update request
			updateReq := &ApplicationUpdateRequest{}
			updateReq.Name = "updated-app"
			updateReq.UUIDURL = tt.appUUID

			// Test UpdateApplication
			updateErr := updateReq.UpdateApplication(context.Background(), client)

			if tt.expectError {
				assert.Error(t, updateErr)
			} else {
				assert.NoError(t, updateErr)
			}
		})
	}
}

// Note: TestApplicationDelete is in application_lifecycle_test.go as TestApplicationDeleteApplication
// which has more comprehensive test coverage (6 test cases vs 3)

// TestCreateMinimalApplication tests minimal application creation
func TestCreateMinimalApplication(t *testing.T) {
	tests := map[string]struct {
		request        *MinimalCreateAppRequest
		mockResponse   string
		mockStatusCode int
		expectError    bool
		expectedUUID   string
		errorContains  string
	}{
		"successful minimal application creation": {
			request: &MinimalCreateAppRequest{
				Name:          "minimal-test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"uuid_url": "minimal-app-uuid", "name": "minimal-test-app"}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedUUID:   "minimal-app-uuid",
		},
		"server error response": {
			request: &MinimalCreateAppRequest{
				Name:          "minimal-test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"type": "error", "title": "Internal Server Error", "detail": "Internal server error"}`,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "app creation failed",
		},
		"validation error response": {
			request: &MinimalCreateAppRequest{
				Name:          "minimal-test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"type": "validation_error", "title": "Bad Request", "detail": "Name is required"}`,
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "app creation failed",
		},
		"unauthorized error": {
			request: &MinimalCreateAppRequest{
				Name:          "minimal-test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			mockResponse:   `{"type": "error", "title": "Unauthorized", "detail": "Authentication failed"}`,
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "app creation failed",
		},
		"network error": {
			request: &MinimalCreateAppRequest{
				Name:          "minimal-test-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
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
					assert.Contains(t, r.URL.Path, "apps")

					// Verify request body contains minimal required fields
					var reqBody MinimalCreateAppRequest
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
				// Extract host from server URL properly
				parsedURL, err := url.Parse(server.URL)
				if err == nil {
					client.Host = parsedURL.Host
				} else {
					// Fallback: remove https:// prefix (8 characters)
					client.Host = server.URL[8:]
				}
			}

			// Test CreateMinimalApplication
			result, err := tt.request.CreateMinimalApplication(context.Background(), client)

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

// Note: TestDeployApplication is in application_lifecycle_test.go as TestApplicationDeployApplication
// which has more comprehensive test coverage (7 test cases vs 6, includes StatusCreated and Unauthorized)

// TestCreateAppRequestFromSchema tests the CreateAppRequest schema mapping functionality
func TestCreateAppRequestFromSchema(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		wantErr  bool
	}{
		{
			name: "basic application request",
			data: map[string]interface{}{
				"name":        "test-app",
				"description": "Test application",
			},
			wantErr: false,
		},
		{
			name: "minimal request",
			data: map[string]interface{}{
				"name": "minimal-app",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create basic resource schema
			resourceSchema := map[string]*schema.Schema{
				"name":        {Type: schema.TypeString, Required: true},
				"description": {Type: schema.TypeString, Optional: true},
			}

			// Create resource data
			resourceData := schema.TestResourceDataRaw(t, resourceSchema, tt.data)
			ctx := context.Background()

			// Create mock client
			client := &EaaClient{
				Host:   "test-host.com",
				Logger: hclog.NewNullLogger(),
			}

			// Create request object
			req := &CreateAppRequest{}

			// Call function under test
			err := req.CreateAppRequestFromSchema(ctx, resourceData, client)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.data["name"], req.Name)
			}
		})
	}
}

// TestMinimalCreateAppRequestFromSchema tests minimal app creation
func TestMinimalCreateAppRequestFromSchema(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"name": {Type: schema.TypeString, Required: true},
	}

	data := map[string]interface{}{
		"name": "minimal-test-app",
	}

	resourceData := schema.TestResourceDataRaw(t, resourceSchema, data)
	ctx := context.Background()
	client := &EaaClient{
		Host:   "test-host.com",
		Logger: hclog.NewNullLogger(),
	}

	req := &MinimalCreateAppRequest{}
	err := req.CreateMinimalAppRequestFromSchema(ctx, resourceData, client)

	require.NoError(t, err)
	assert.Equal(t, "minimal-test-app", req.Name)
}

// TestApplicationUpdateRequestFromSchema tests update request functionality
func TestApplicationUpdateRequestFromSchema(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"name":        {Type: schema.TypeString, Optional: true},
		"description": {Type: schema.TypeString, Optional: true},
	}

	data := map[string]interface{}{
		"name":        "updated-app",
		"description": "Updated description",
	}

	resourceData := schema.TestResourceDataRaw(t, resourceSchema, data)
	ctx := context.Background()
	client := &EaaClient{
		Host:   "test-host.com",
		Logger: hclog.NewNullLogger(),
	}

	req := &ApplicationUpdateRequest{}
	err := req.UpdateAppRequestFromSchema(ctx, resourceData, client)

	require.NoError(t, err)
	assert.Equal(t, "updated-app", req.Name)
}

// TestApplicationStructBasics tests basic structure operations
func TestApplicationStructBasics(t *testing.T) {
	t.Run("CreateAppRequest", func(t *testing.T) {
		req := &CreateAppRequest{
			Name:       "test-app",
			AppProfile: 1,
			AppType:    1,
		}
		assert.Equal(t, "test-app", req.Name)
		assert.Equal(t, 1, req.AppProfile)
	})

	t.Run("Application", func(t *testing.T) {
		app := &Application{
			Name:    "test-application",
			UUIDURL: "test-uuid-123",
		}
		assert.Equal(t, "test-application", app.Name)
		assert.Equal(t, "test-uuid-123", app.UUIDURL)
	})
}
