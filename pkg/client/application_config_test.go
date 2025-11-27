package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigureAuthentication tests the ConfigureAuthentication function
func TestConfigureAuthentication(t *testing.T) {
	testCases := []struct {
		name           string
		appID          string
		authEnabled    string
		appAuth        interface{}
		idpName        string
		appDirs        interface{}
		mockIDP        *IDPData
		mockIDPError   bool
		assignIDPError bool
		expectError    bool
	}{
		{
			name:        "successful authentication configuration with IDP and directories",
			appID:       "test-app-123",
			authEnabled: "true",
			appAuth: []interface{}{
				map[string]interface{}{
					"app_idp": "test-idp",
					"app_directories": []interface{}{
						map[string]interface{}{"name": "dir1"},
						map[string]interface{}{"name": "dir2"},
					},
				},
			},
			idpName: "test-idp",
			appDirs: []interface{}{
				map[string]interface{}{"name": "dir1"},
				map[string]interface{}{"name": "dir2"},
			},
			mockIDP:     &IDPData{UUIDURL: "idp-uuid-123", Name: "test-idp"},
			expectError: false,
		},
		{
			name:        "auth disabled - no configuration",
			appID:       "test-app-456",
			authEnabled: "false",
			expectError: false,
		},
		{
			name:        "auth enabled but no app_authentication block",
			appID:       "test-app-789",
			authEnabled: "true",
			expectError: false,
		},
		{
			name:        "auth enabled with IDP but no directories",
			appID:       "test-app-no-dirs",
			authEnabled: "true",
			appAuth: []interface{}{
				map[string]interface{}{
					"app_idp": "test-idp",
				},
			},
			idpName:     "test-idp",
			mockIDP:     &IDPData{UUIDURL: "idp-uuid-123", Name: "test-idp"},
			expectError: false,
		},
		{
			name:        "IDP not found error",
			appID:       "test-app-idp-error",
			authEnabled: "true",
			appAuth: []interface{}{
				map[string]interface{}{
					"app_idp": "non-existent-idp",
				},
			},
			idpName:      "non-existent-idp",
			mockIDPError: true,
			expectError:  true,
		},
		{
			name:        "IDP assignment error",
			appID:       "test-app-assign-error",
			authEnabled: "true",
			appAuth: []interface{}{
				map[string]interface{}{
					"app_idp": "test-idp",
				},
			},
			idpName:        "test-idp",
			mockIDP:        &IDPData{UUIDURL: "idp-uuid-123", Name: "test-idp"},
			assignIDPError: true,
			expectError:    true,
		},
		{
			name:        "empty app_authentication list - no error",
			appID:       "test-app-empty",
			authEnabled: "true",
			appAuth:     []interface{}{},
			expectError: false, // Empty list is valid, just skips configuration
		},
		{
			name:        "directory assignment error",
			appID:       "test-app-dir-error",
			authEnabled: "true",
			appAuth: []interface{}{
				map[string]interface{}{
					"app_idp": "test-idp",
					"app_directories": []interface{}{
						map[string]interface{}{"name": "dir1"},
					},
				},
			},
			idpName:     "test-idp",
			appDirs:     []interface{}{map[string]interface{}{"name": "dir1"}},
			mockIDP:     &IDPData{UUIDURL: "idp-uuid-123", Name: "test-idp"},
			expectError: true, // Directory assignment will fail
		},
		// Note: appAuthenticationMap == nil case (line 610) is unreachable because
		// the type assertion on line 609 will panic if the value is nil.
		// This would require a code fix to handle gracefully.
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle IDP lookup
				if r.Method == "GET" && r.URL.Path == "/crux/v1/mgmt-pop/idp" {
					if tc.mockIDPError {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if tc.mockIDP != nil {
						w.WriteHeader(http.StatusOK)
						json.NewEncoder(w).Encode(IDPResponse{
							IDPS: []IDPResponseData{
								{
									UUIDURL: tc.mockIDP.UUIDURL,
									Name:    tc.mockIDP.Name,
								},
							},
						})
						return
					}
				}

				// Handle IDP directories lookup (path is /crux/v1/mgmt-pop/idp/{uuid}/directories - singular "idp")
				if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/crux/v1/mgmt-pop/idp/") && strings.HasSuffix(r.URL.Path, "/directories") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					// Always return a valid response, even if empty
					dirResponse := DirectoryResponse{
						DirectoryList: []DirectoryData{},
					}
					// Add directories if this test case has them
					if tc.appDirs != nil {
						if appDirsList, ok := tc.appDirs.([]interface{}); ok && len(appDirsList) > 0 {
							dirResponse.DirectoryList = []DirectoryData{
								{Name: "dir1", UUID: "dir-uuid-1"},
								{Name: "dir2", UUID: "dir-uuid-2"},
							}
						}
					}
					if err := json.NewEncoder(w).Encode(dirResponse); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
					return
				}

				// Handle IDP assignment (correct path is /crux/v1/mgmt-pop/appidp)
				if r.Method == "POST" && r.URL.Path == "/crux/v1/mgmt-pop/appidp" {
					if tc.assignIDPError {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"success": true}`))
					return
				}

				// Handle directory assignment (if needed)
				if r.Method == "POST" && r.URL.Path == "/crux/v1/mgmt-pop/appdirectories" {
					// Check if this is the directory assignment error test case
					if tc.name == "directory assignment error" {
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte(`{"error": "directory assignment failed"}`))
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"success": true}`))
					return
				}

				// Log unmatched requests for debugging
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "unmatched request: ` + r.Method + " " + r.URL.Path + `"}`))
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

			// Create mock ResourceData
			rawData := map[string]interface{}{
				"auth_enabled": tc.authEnabled,
			}
			if tc.appAuth != nil {
				rawData["app_authentication"] = tc.appAuth
			}

			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"auth_enabled": {
					Type: schema.TypeString,
				},
				"app_authentication": {
					Type: schema.TypeList,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"app_idp": {
								Type: schema.TypeString,
							},
							"app_directories": {
								Type: schema.TypeList,
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"name": {
											Type: schema.TypeString,
										},
									},
								},
							},
						},
					},
				},
			}, rawData)

			// Call method under test
			ctx := context.Background()
			err := ConfigureAuthentication(ctx, tc.appID, d, client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfigureAdvancedSettings tests the ConfigureAdvancedSettings function
func TestConfigureAdvancedSettings(t *testing.T) {
	testCases := []struct {
		name             string
		appID            string
		getStatusCode    int
		updateStatusCode int
		advancedSettings interface{}
		expectError      bool
	}{
		{
			name:             "successful advanced settings configuration",
			appID:            "test-app-123",
			getStatusCode:    http.StatusOK,
			updateStatusCode: http.StatusOK,
			advancedSettings: map[string]interface{}{
				"app_auth": "none",
			},
			expectError: false,
		},
		{
			name:          "get app fails",
			appID:         "not-found-app",
			getStatusCode: http.StatusNotFound,
			expectError:   true,
		},
		{
			name:             "get succeeds but update fails",
			appID:            "update-fail-app",
			getStatusCode:    http.StatusOK,
			updateStatusCode: http.StatusBadRequest,
			expectError:      true,
		},
		{
			name:             "get succeeds but UpdateAppRequestFromSchema fails with invalid JSON",
			appID:            "invalid-json-app",
			getStatusCode:    http.StatusOK,
			updateStatusCode: http.StatusOK,
			advancedSettings: "invalid json {", // Invalid JSON string
			expectError:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle GET application
				if r.Method == "GET" && r.URL.Path == "/crux/v1/mgmt-pop/apps/"+tc.appID {
					w.WriteHeader(tc.getStatusCode)
					if tc.getStatusCode == http.StatusOK {
						mockApp := map[string]interface{}{
							"uuid_url":    tc.appID,
							"name":        "Test App",
							"app_profile": 1,
							"app_type":    1,
							"advanced_settings": map[string]interface{}{
								"app_auth": "none",
							},
						}
						json.NewEncoder(w).Encode(mockApp)
					}
				}

				// Handle PUT update
				if r.Method == "PUT" && r.URL.Path == "/crux/v1/mgmt-pop/apps/"+tc.appID {
					w.WriteHeader(tc.updateStatusCode)
					if tc.updateStatusCode == http.StatusOK {
						mockApp := map[string]interface{}{
							"uuid_url":    tc.appID,
							"name":        "Test App",
							"app_profile": 1,
							"app_type":    1,
						}
						json.NewEncoder(w).Encode(mockApp)
					}
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

			// Create mock ResourceData
			rawData := map[string]interface{}{}
			if tc.advancedSettings != nil {
				// Handle both map[string]interface{} and string types
				if settingsMap, ok := tc.advancedSettings.(map[string]interface{}); ok {
					// Convert map to JSON string
					settingsJSON, err := json.Marshal(settingsMap)
					require.NoError(t, err)
					rawData["advanced_settings"] = string(settingsJSON)
				} else if settingsStr, ok := tc.advancedSettings.(string); ok {
					// Already a string, use directly
					rawData["advanced_settings"] = settingsStr
				}
			}

			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"advanced_settings": {
					Type: schema.TypeString,
				},
			}, rawData)

			// Call method under test
			ctx := context.Background()
			err := ConfigureAdvancedSettings(ctx, tc.appID, d, client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestApplicationUpdateG2O tests the UpdateG2O method
func TestApplicationUpdateG2O(t *testing.T) {
	testCases := []struct {
		name           string
		appUUID        string
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name:           "successful G2O update",
			appUUID:        "test-app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "successful G2O update with created status",
			appUUID:        "test-app-uuid-456",
			mockStatusCode: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "G2O update fails with bad request",
			appUUID:        "invalid-app-uuid",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
		{
			name:           "G2O update fails with server error",
			appUUID:        "server-error-uuid",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
		{
			name:           "G2O update fails with not found",
			appUUID:        "not-found-uuid",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.appUUID + "/g2o"
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockStatusCode >= http.StatusOK && tc.mockStatusCode < http.StatusMultipleChoices {
					json.NewEncoder(w).Encode(map[string]interface{}{
						"edge_cookie_key": "test-cookie-key",
						"sla_object_url":  "test-sla-url",
					})
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

			// Create application instance
			app := &Application{
				UUIDURL: tc.appUUID,
			}

			// Call method under test
			result, err := app.UpdateG2O(client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != nil {
					assert.ErrorIs(t, err, tc.expectedError)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}

// TestApplicationUpdateEdgeAuthentication tests the UpdateEdgeAuthentication method
func TestApplicationUpdateEdgeAuthentication(t *testing.T) {
	testCases := []struct {
		name           string
		appUUID        string
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name:           "successful edge authentication update",
			appUUID:        "test-app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "successful edge authentication update with accepted status",
			appUUID:        "test-app-uuid-456",
			mockStatusCode: http.StatusAccepted,
			expectError:    false,
		},
		{
			name:           "edge authentication update fails with bad request",
			appUUID:        "invalid-app-uuid",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
		{
			name:           "edge authentication update fails with server error",
			appUUID:        "server-error-uuid",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
		{
			name:           "edge authentication update fails with not found",
			appUUID:        "not-found-uuid",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrAppUpdate,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.appUUID + "/edgekey"
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockStatusCode >= http.StatusOK && tc.mockStatusCode < http.StatusMultipleChoices {
					json.NewEncoder(w).Encode(map[string]interface{}{
						"edge_cookie_key": "test-cookie-key",
						"sla_object_url":  "test-sla-url",
					})
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

			// Create application instance
			app := &Application{
				UUIDURL: tc.appUUID,
			}

			// Call method under test
			result, err := app.UpdateEdgeAuthentication(client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != nil {
					assert.ErrorIs(t, err, tc.expectedError)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}
