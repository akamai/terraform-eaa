package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplicationDeployApplication tests the DeployApplication method
func TestApplicationDeployApplication(t *testing.T) {
	testCases := []struct {
		name           string
		appUUID        string
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name:           "successful deployment",
			appUUID:        "test-app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "successful deployment with created status",
			appUUID:        "test-app-uuid-456",
			mockStatusCode: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "deployment with accepted status",
			appUUID:        "test-app-uuid-789",
			mockStatusCode: http.StatusAccepted,
			expectError:    false,
		},
		{
			name:           "deployment fails with bad request",
			appUUID:        "invalid-app-uuid",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrDeploy,
		},
		{
			name:           "deployment fails with server error",
			appUUID:        "server-error-uuid",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrDeploy,
		},
		{
			name:           "deployment fails with not found",
			appUUID:        "not-found-uuid",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrDeploy,
		},
		{
			name:           "deployment fails with unauthorized",
			appUUID:        "unauthorized-uuid",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			expectedError:  ErrDeploy,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.appUUID + "/deploy"
				assert.Equal(t, expectedPath, r.URL.Path)

				// Verify the deploy note is sent in request body
				// Note: We could parse the body to verify the deploy_note, but for unit test
				// we focus on the method behavior

				w.WriteHeader(tc.mockStatusCode)
			}))
			defer server.Close()

			// Create test client
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:], // Remove https://
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			// Create application instance
			app := &Application{
				UUIDURL: tc.appUUID,
			}

			// Call method under test
			err := app.DeployApplication(client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != nil {
					assert.Equal(t, tc.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestApplicationDeleteApplication tests the DeleteApplication method
func TestApplicationDeleteApplication(t *testing.T) {
	testCases := []struct {
		name           string
		appUUID        string
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name:           "successful deletion",
			appUUID:        "test-app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "successful deletion with no content",
			appUUID:        "test-app-uuid-456",
			mockStatusCode: http.StatusNoContent,
			expectError:    false,
		},
		{
			name:           "deletion fails with bad request",
			appUUID:        "invalid-app-uuid",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrAppDelete,
		},
		{
			name:           "deletion fails with not found",
			appUUID:        "not-found-uuid",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrAppDelete,
		},
		{
			name:           "deletion fails with server error",
			appUUID:        "server-error-uuid",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrAppDelete,
		},
		{
			name:           "deletion fails with forbidden",
			appUUID:        "forbidden-uuid",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			expectedError:  ErrAppDelete,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.appUUID
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)
			}))
			defer server.Close()

			// Create test client
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:], // Remove https://
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			// Create application instance
			app := &Application{
				UUIDURL: tc.appUUID,
			}

			// Call method under test
			err := app.DeleteApplication(client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != nil {
					assert.Equal(t, tc.expectedError, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestApplicationFromResponse tests the FromResponse method
func TestApplicationFromResponse(t *testing.T) {
	testCases := []struct {
		name     string
		response *ApplicationResponse
		expected *Application
	}{
		{
			name: "complete application response",
			response: &ApplicationResponse{
				Name:           "test-app",
				Description:    strPtr("Test application description"),
				AppProfile:     1,
				AppType:        2,
				ClientAppMode:  3,
				Host:           strPtr("app.example.com"),
				BookmarkURL:    "https://bookmark.example.com",
				AppLogo:        strPtr("logo.png"),
				OrigTLS:        "true",
				OriginHost:     strPtr("origin.example.com"),
				OriginPort:     443,
				UUIDURL:        "app-uuid-123",
				POP:            "pop-1",
				POPName:        "POP Name",
				POPRegion:      "us-east-1",
				AuthType:       1,
				AuthEnabled:    "true",
				AppDeployed:    true,
				AppOperational: 1,
				AppStatus:      1,
				Status:         1,
			},
			expected: &Application{
				Name:           "test-app",
				Description:    strPtr("Test application description"),
				AppProfile:     1,
				AppType:        2,
				ClientAppMode:  3,
				Host:           strPtr("app.example.com"),
				BookmarkURL:    "https://bookmark.example.com",
				AppLogo:        strPtr("logo.png"),
				OrigTLS:        "true",
				OriginHost:     strPtr("origin.example.com"),
				OriginPort:     443,
				UUIDURL:        "app-uuid-123",
				POP:            "pop-1",
				POPName:        "POP Name",
				POPRegion:      "us-east-1",
				AuthType:       1,
				AuthEnabled:    "true",
				AppDeployed:    true,
				AppOperational: 1,
				AppStatus:      1,
				Status:         1,
			},
		},
		{
			name: "minimal application response",
			response: &ApplicationResponse{
				Name:       "minimal-app",
				AppProfile: 1,
				AppType:    1,
				UUIDURL:    "minimal-uuid",
			},
			expected: &Application{
				Name:       "minimal-app",
				AppProfile: 1,
				AppType:    1,
				UUIDURL:    "minimal-uuid",
				OrigTLS:    "",
				OriginPort: 0,
			},
		},
		{
			name: "application with nil pointer fields",
			response: &ApplicationResponse{
				Name:        "nil-fields-app",
				Description: nil,
				Host:        nil,
				AppLogo:     nil,
				OriginHost:  nil,
				AuthEnabled: "",
				AppProfile:  1,
				AppType:     1,
				UUIDURL:     "nil-fields-uuid",
			},
			expected: &Application{
				Name:        "nil-fields-app",
				Description: nil,
				Host:        nil,
				AppLogo:     nil,
				OriginHost:  nil,
				AppProfile:  1,
				AppType:     1,
				UUIDURL:     "nil-fields-uuid",
				AuthEnabled: "",
				OrigTLS:     "",
				OriginPort:  0,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create application instance
			app := &Application{}

			// Call method under test
			app.FromResponse(tc.response)

			// Verify results
			assert.Equal(t, tc.expected.Name, app.Name)
			assert.Equal(t, tc.expected.AppProfile, app.AppProfile)
			assert.Equal(t, tc.expected.AppType, app.AppType)
			assert.Equal(t, tc.expected.ClientAppMode, app.ClientAppMode)
			assert.Equal(t, tc.expected.UUIDURL, app.UUIDURL)
			assert.Equal(t, tc.expected.BookmarkURL, app.BookmarkURL)
			assert.Equal(t, tc.expected.OrigTLS, app.OrigTLS)
			assert.Equal(t, tc.expected.OriginPort, app.OriginPort)
			assert.Equal(t, tc.expected.POP, app.POP)
			assert.Equal(t, tc.expected.POPName, app.POPName)
			assert.Equal(t, tc.expected.POPRegion, app.POPRegion)
			assert.Equal(t, tc.expected.AuthType, app.AuthType)
			assert.Equal(t, tc.expected.AuthEnabled, app.AuthEnabled)
			assert.Equal(t, tc.expected.AppDeployed, app.AppDeployed)
			assert.Equal(t, tc.expected.AppOperational, app.AppOperational)
			assert.Equal(t, tc.expected.AppStatus, app.AppStatus)
			assert.Equal(t, tc.expected.Status, app.Status)

			// Test pointer fields
			if tc.expected.Description != nil {
				require.NotNil(t, app.Description)
				assert.Equal(t, *tc.expected.Description, *app.Description)
			} else {
				assert.Nil(t, app.Description)
			}

			if tc.expected.Host != nil {
				require.NotNil(t, app.Host)
				assert.Equal(t, *tc.expected.Host, *app.Host)
			} else {
				assert.Nil(t, app.Host)
			}

			if tc.expected.AppLogo != nil {
				require.NotNil(t, app.AppLogo)
				assert.Equal(t, *tc.expected.AppLogo, *app.AppLogo)
			} else {
				assert.Nil(t, app.AppLogo)
			}

			if tc.expected.OriginHost != nil {
				require.NotNil(t, app.OriginHost)
				assert.Equal(t, *tc.expected.OriginHost, *app.OriginHost)
			} else {
				assert.Nil(t, app.OriginHost)
			}
		})
	}
}

// TestApplicationUpdateRequestUpdateApplication tests the UpdateApplication method
func TestApplicationUpdateRequestUpdateApplication(t *testing.T) {
	testCases := []struct {
		name           string
		updateRequest  *ApplicationUpdateRequest
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name: "successful update",
			updateRequest: &ApplicationUpdateRequest{
				Application: Application{
					UUIDURL:    "test-app-uuid-123",
					Name:       "Updated Test App",
					AppProfile: 1,
					AppType:    1,
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "successful update with accepted status",
			updateRequest: &ApplicationUpdateRequest{
				Application: Application{
					UUIDURL:    "test-app-uuid-456",
					Name:       "Another Updated App",
					AppProfile: 2,
					AppType:    2,
				},
			},
			mockStatusCode: http.StatusAccepted,
			expectError:    false,
		},
		{
			name: "update fails with bad request",
			updateRequest: &ApplicationUpdateRequest{
				Application: Application{
					UUIDURL: "invalid-app-uuid",
					Name:    "Invalid App",
				},
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
		{
			name: "update fails with not found",
			updateRequest: &ApplicationUpdateRequest{
				Application: Application{
					UUIDURL: "not-found-uuid",
					Name:    "Not Found App",
				},
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
		{
			name: "update fails with server error",
			updateRequest: &ApplicationUpdateRequest{
				Application: Application{
					UUIDURL: "server-error-uuid",
					Name:    "Server Error App",
				},
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.updateRequest.UUIDURL
				assert.Equal(t, expectedPath, r.URL.Path)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.mockStatusCode)

				// For successful responses, return a mock application response
				if tc.mockStatusCode >= 200 && tc.mockStatusCode < 300 {
					mockResponse := map[string]interface{}{
						"uuid_url":    tc.updateRequest.UUIDURL,
						"name":        tc.updateRequest.Name,
						"app_profile": tc.updateRequest.AppProfile,
						"app_type":    tc.updateRequest.AppType,
						"advanced_settings": map[string]interface{}{
							"app_auth_domain": "example.com",
						},
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(mockResponse)
				}
			}))
			defer server.Close()

			// Create test client
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:], // Remove https://
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			// Call method under test
			ctx := context.Background()
			err := tc.updateRequest.UpdateApplication(ctx, client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != nil {
					assert.ErrorIs(t, err, tc.expectedError)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfigureAgents tests the ConfigureAgents function
func TestConfigureAgents(t *testing.T) {
	testCases := []struct {
		name        string
		appID       string
		agentsData  interface{}
		expectError bool
		expectCall  bool
	}{
		{
			name:  "successful agent configuration",
			appID: "test-app-123",
			agentsData: []interface{}{
				"agent-1",
				"agent-2",
				"agent-3",
			},
			expectError: false,
			expectCall:  true,
		},
		{
			name:        "no agents configured",
			appID:       "test-app-456",
			agentsData:  nil,
			expectError: false,
			expectCall:  false,
		},
		{
			name:        "empty agents list",
			appID:       "test-app-789",
			agentsData:  []interface{}{},
			expectError: false,
			expectCall:  false, // No call should be made for empty list
		},
		{
			name:  "single agent configuration",
			appID: "test-app-single",
			agentsData: []interface{}{
				"single-agent",
			},
			expectError: false,
			expectCall:  true,
		},
		{
			name:  "agent assignment fails with server error",
			appID: "test-app-server-error",
			agentsData: []interface{}{
				"agent-1",
			},
			expectError: true,
			expectCall:  true,
		},
		{
			name:  "agent assignment fails with bad request",
			appID: "test-app-bad-request",
			agentsData: []interface{}{
				"agent-1",
			},
			expectError: true,
			expectCall:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server for agent operations
			assignCalled := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle GET agents request for GetAgents function
				if r.Method == "GET" && r.URL.Path == "/crux/v1/mgmt-pop/agents" {
					w.WriteHeader(http.StatusOK)
					// Mock response with agents that match our test data
					mockAgentsResponse := map[string]interface{}{
						"objects": []map[string]interface{}{
							{
								"name":     "agent-1",
								"uuid_url": "agent-uuid-1",
							},
							{
								"name":     "agent-2",
								"uuid_url": "agent-uuid-2",
							},
							{
								"name":     "agent-3",
								"uuid_url": "agent-uuid-3",
							},
							{
								"name":     "single-agent",
								"uuid_url": "single-agent-uuid",
							},
						},
					}
					json.NewEncoder(w).Encode(mockAgentsResponse)
					return
				}

				// Handle POST agent assignment request
				if r.Method == "POST" && r.URL.Path == "/crux/v1/mgmt-pop/apps/"+tc.appID+"/agents" {
					assignCalled = true
					// Return error status codes for error test cases
					if tc.appID == "test-app-server-error" {
						w.WriteHeader(http.StatusInternalServerError)
					} else if tc.appID == "test-app-bad-request" {
						w.WriteHeader(http.StatusBadRequest)
					} else {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"success": true}`))
					}
					return
				}
			}))
			defer server.Close()

			// Create test client
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:], // Remove https://
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			// Create mock ResourceData using schema.TestResourceDataRaw
			var d *schema.ResourceData
			if tc.agentsData != nil {
				rawData := map[string]interface{}{
					"agents": tc.agentsData,
				}
				d = schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"agents": {
						Type: schema.TypeList,
						Elem: &schema.Schema{Type: schema.TypeString},
					},
				}, rawData)
			} else {
				d = schema.TestResourceDataRaw(t, map[string]*schema.Schema{
					"agents": {
						Type: schema.TypeList,
						Elem: &schema.Schema{Type: schema.TypeString},
					},
				}, map[string]interface{}{})
			}

			// Call method under test
			ctx := context.Background()
			err := ConfigureAgents(ctx, tc.appID, d, client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify if agent assignment was called when expected
			assert.Equal(t, tc.expectCall, assignCalled, "Agent assignment call expectation mismatch")
		})
	}
}

// TestDeployExistingApplication tests the DeployExistingApplication function
func TestDeployExistingApplication(t *testing.T) {
	testCases := []struct {
		name             string
		appID            string
		getStatusCode    int
		deployStatusCode int
		expectError      bool
	}{
		{
			name:             "successful get and deploy",
			appID:            "test-app-123",
			getStatusCode:    http.StatusOK,
			deployStatusCode: http.StatusOK,
			expectError:      false,
		},
		{
			name:             "successful get and deploy with accepted",
			appID:            "test-app-456",
			getStatusCode:    http.StatusOK,
			deployStatusCode: http.StatusAccepted,
			expectError:      false,
		},
		{
			name:          "get fails with not found",
			appID:         "not-found-app",
			getStatusCode: http.StatusNotFound,
			expectError:   true,
		},
		{
			name:             "get succeeds but deploy fails",
			appID:            "deploy-fail-app",
			getStatusCode:    http.StatusOK,
			deployStatusCode: http.StatusBadRequest,
			expectError:      true,
		},
		{
			name:          "get fails with server error",
			appID:         "server-error-app",
			getStatusCode: http.StatusInternalServerError,
			expectError:   true,
		},
		{
			name:          "get fails with unauthorized",
			appID:         "unauthorized-app",
			getStatusCode: http.StatusUnauthorized,
			expectError:   true,
		},
		{
			name:          "get fails with forbidden",
			appID:         "forbidden-app",
			getStatusCode: http.StatusForbidden,
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/crux/v1/mgmt-pop/apps/"+tc.appID {
					// Mock GET application response
					w.WriteHeader(tc.getStatusCode)
					if tc.getStatusCode == http.StatusOK {
						mockApp := map[string]interface{}{
							"uuid_url":    tc.appID,
							"name":        "Test App",
							"app_profile": 1,
							"app_type":    1,
						}
						json.NewEncoder(w).Encode(mockApp)
					}
				} else if r.Method == "POST" && r.URL.Path == "/crux/v1/mgmt-pop/apps/"+tc.appID+"/deploy" {
					// Mock deploy response
					w.WriteHeader(tc.deployStatusCode)
				}
			}))
			defer server.Close()

			// Create test client
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:], // Remove https://
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			// Call method under test
			ctx := context.Background()
			err := DeployExistingApplication(ctx, tc.appID, client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Note: strPtr helper function is defined in application_crud_test.go
