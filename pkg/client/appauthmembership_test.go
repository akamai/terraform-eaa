package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAppIdpMembership(t *testing.T) {
	testCases := []struct {
		name           string
		app            *Application
		mockResponse   *AppIdpMembershipResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectNil      bool
	}{
		{
			name: "successful get app idp membership",
			app: &Application{
				UUIDURL: "app-uuid-123",
				Name:    "Test App",
			},
			mockResponse: &AppIdpMembershipResponse{
				Meta: Meta{
					TotalCount: 1,
					Limit:      20,
					Offset:     0,
				},
				AppIdpMemberships: []AppIdpMembership{
					{
						UUIDURL:   "membership-uuid-1",
						EnableMFA: "true",
						App: AppMembership{
							AppUUIDURL: "app-uuid-123",
							Name:       "Test App",
						},
						IDP: IDPMembership{
							IDPUUIDURL: "idp-uuid-1",
							Name:       "Azure AD",
						},
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectNil:      false,
		},
		{
			name: "empty app idp membership response",
			app: &Application{
				UUIDURL: "app-uuid-empty",
				Name:    "Empty App",
			},
			mockResponse: &AppIdpMembershipResponse{
				Meta: Meta{
					TotalCount: 0,
					Limit:      20,
					Offset:     0,
				},
				AppIdpMemberships: []AppIdpMembership{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectNil:      true,
		},
		{
			name: "server error response",
			app: &Application{
				UUIDURL: "app-uuid-error",
				Name:    "Error App",
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "unable to get app idp membership",
		},
		{
			name: "not found response",
			app: &Application{
				UUIDURL: "app-uuid-notfound",
				Name:    "NotFound App",
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "unable to get app idp membership",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.app.UUIDURL + "/idp_membership"
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(), // Use the TLS client from the test server
			}

			// Execute function
			result, err := tc.app.GetAppIdpMembership(client)

			// Assertions
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if tc.expectNil {
					assert.Nil(t, result)
				} else {
					assert.NotNil(t, result)
					if tc.mockResponse != nil && len(tc.mockResponse.AppIdpMemberships) > 0 {
						expected := &tc.mockResponse.AppIdpMemberships[0]
						assert.Equal(t, expected.UUIDURL, result.UUIDURL)
						assert.Equal(t, expected.EnableMFA, result.EnableMFA)
						assert.Equal(t, expected.IDP.Name, result.IDP.Name)
					}
				}
			}
		})
	}
}

func TestGetAppDirectoryMembership(t *testing.T) {
	testCases := []struct {
		name           string
		app            *Application
		mockResponse   *AppDirectoryMembershipResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedCount  int
	}{
		{
			name: "successful get app directory membership",
			app: &Application{
				UUIDURL: "app-uuid-123",
				Name:    "Test App",
			},
			mockResponse: &AppDirectoryMembershipResponse{
				Meta: Meta{
					TotalCount: 2,
					Limit:      20,
					Offset:     0,
				},
				AppDirectoryMemberships: []AppDirectoryMembership{
					{
						UUIDURL:   "dir-membership-1",
						EnableMFA: "true",
						App: AppMembership{
							AppUUIDURL: "app-uuid-123",
							Name:       "Test App",
						},
						Directory: DirectoryMembership{
							DirectoryUUIDURL: "dir-uuid-1",
							Name:             "Active Directory",
						},
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  1,
		},
		{
			name: "empty directory membership response",
			app: &Application{
				UUIDURL: "app-uuid-empty",
				Name:    "Empty App",
			},
			mockResponse: &AppDirectoryMembershipResponse{
				Meta: Meta{
					TotalCount: 0,
					Limit:      20,
					Offset:     0,
				},
				AppDirectoryMemberships: []AppDirectoryMembership{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
		{
			name: "server error response",
			app: &Application{
				UUIDURL: "app-uuid-error",
				Name:    "Error App",
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "unable to get app directory membership",
		},
		{
			name: "not found response",
			app: &Application{
				UUIDURL: "app-uuid-notfound",
				Name:    "NotFound App",
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "unable to get app directory membership",
		},
		{
			name: "bad request response",
			app: &Application{
				UUIDURL: "app-uuid-badrequest",
				Name:    "BadRequest App",
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "unable to get app directory membership",
		},
		{
			name: "unauthorized response",
			app: &Application{
				UUIDURL: "app-uuid-unauthorized",
				Name:    "Unauthorized App",
			},
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "unable to get app directory membership",
		},
		{
			name: "forbidden response",
			app: &Application{
				UUIDURL: "app-uuid-forbidden",
				Name:    "Forbidden App",
			},
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "unable to get app directory membership",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.app.UUIDURL + "/directories_membership"
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(), // Use the TLS client from the test server
			}

			// Execute function
			result, err := tc.app.GetAppDirectoryMembership(client)

			// Assertions
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result, tc.expectedCount)
				if tc.expectedCount > 0 && tc.mockResponse != nil {
					assert.Equal(t, tc.mockResponse.AppDirectoryMemberships[0].Directory.Name, result[0].Directory.Name)
				}
			}
		})
	}
}

func TestGetAppGroupMembership(t *testing.T) {
	testCases := []struct {
		name           string
		app            *Application
		mockResponse   *AppGroupMembershipResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedCount  int
	}{
		{
			name: "successful get app group membership",
			app: &Application{
				UUIDURL: "app-uuid-123",
				Name:    "Test App",
			},
			mockResponse: &AppGroupMembershipResponse{
				Meta: Meta{
					TotalCount: 2,
					Limit:      20,
					Offset:     0,
				},
				AppGroupMemberships: []AppGroupMembership{
					{
						UUIDURL:   "group-membership-1",
						EnableMFA: "true",
						App: AppMembership{
							AppUUIDURL: "app-uuid-123",
							Name:       "Test App",
						},
						Group: GroupMembership{
							GroupUUIDURL: "group-uuid-1",
							GroupName:    "Admin Group",
							DirName:      "Active Directory",
							DirUUIDURL:   "dir-uuid-1",
						},
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  1,
		},
		{
			name: "empty group membership response",
			app: &Application{
				UUIDURL: "app-uuid-empty",
				Name:    "Empty App",
			},
			mockResponse: &AppGroupMembershipResponse{
				Meta: Meta{
					TotalCount: 0,
					Limit:      20,
					Offset:     0,
				},
				AppGroupMemberships: []AppGroupMembership{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
		{
			name: "server error response",
			app: &Application{
				UUIDURL: "app-uuid-error",
				Name:    "Error App",
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "unable to get app group membership",
		},
		{
			name: "not found response",
			app: &Application{
				UUIDURL: "app-uuid-notfound",
				Name:    "NotFound App",
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "unable to get app group membership",
		},
		{
			name: "bad request response",
			app: &Application{
				UUIDURL: "app-uuid-badrequest",
				Name:    "BadRequest App",
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "unable to get app group membership",
		},
		{
			name: "unauthorized response",
			app: &Application{
				UUIDURL: "app-uuid-unauthorized",
				Name:    "Unauthorized App",
			},
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "unable to get app group membership",
		},
		{
			name: "forbidden response",
			app: &Application{
				UUIDURL: "app-uuid-forbidden",
				Name:    "Forbidden App",
			},
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "unable to get app group membership",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.app.UUIDURL + "/groups"
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(), // Use the TLS client from the test server
			}

			// Execute function
			result, err := tc.app.GetAppGroupMembership(client)

			// Assertions
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result, tc.expectedCount)
				if tc.expectedCount > 0 && tc.mockResponse != nil {
					assert.Equal(t, tc.mockResponse.AppGroupMemberships[0].Group.GroupName, result[0].Group.GroupName)
				}
			}
		})
	}
}

func TestCreateAppAuthenticationStruct(t *testing.T) {
	testCases := []struct {
		name                string
		app                 *Application
		mockIdpResponse     *AppIdpMembershipResponse
		mockDirResponse     *AppDirectoryMembershipResponse
		mockGroupResponse   *AppGroupMembershipResponse
		mockStatusCode      int
		expectError         bool
		errorContains       string
		expectedStructCount int
		checkContent        func(*testing.T, []interface{})
	}{
		{
			name: "successful create app authentication struct with full data",
			app: &Application{
				UUIDURL: "app-uuid-123",
				Name:    "Test App",
			},
			mockIdpResponse: &AppIdpMembershipResponse{
				Meta: Meta{TotalCount: 1},
				AppIdpMemberships: []AppIdpMembership{
					{
						UUIDURL: "idp-membership-1",
						IDP: IDPMembership{
							IDPUUIDURL: "idp-uuid-1",
							Name:       "Azure AD",
						},
					},
				},
			},
			mockDirResponse: &AppDirectoryMembershipResponse{
				Meta: Meta{TotalCount: 1},
				AppDirectoryMemberships: []AppDirectoryMembership{
					{
						UUIDURL: "dir-membership-1",
						Directory: DirectoryMembership{
							DirectoryUUIDURL: "dir-uuid-1",
							Name:             "Active Directory",
						},
					},
				},
			},
			mockGroupResponse: &AppGroupMembershipResponse{
				Meta: Meta{TotalCount: 1},
				AppGroupMemberships: []AppGroupMembership{
					{
						UUIDURL: "group-membership-1",
						Group: GroupMembership{
							GroupName:  "Admin Group",
							DirName:    "Active Directory",
							DirUUIDURL: "dir-uuid-1",
						},
					},
				},
			},
			mockStatusCode:      http.StatusOK,
			expectError:         false,
			expectedStructCount: 1,
			checkContent: func(t *testing.T, result []interface{}) {
				require.Len(t, result, 1)
				authStruct, ok := result[0].(map[string]interface{})
				require.True(t, ok)

				// Check app_idp
				assert.Equal(t, "Azure AD", authStruct["app_idp"])

				// Check app_directories
				dirs, exists := authStruct["app_directories"]
				assert.True(t, exists)
				dirsList, ok := dirs.([]map[string]interface{})
				require.True(t, ok)
				require.Len(t, dirsList, 1)
				assert.Equal(t, "Active Directory", dirsList[0]["name"])

				// Check app_groups
				groups, exists := dirsList[0]["app_groups"]
				assert.True(t, exists)
				groupsList, ok := groups.([]map[string]interface{})
				require.True(t, ok)
				require.Len(t, groupsList, 1)
				assert.Equal(t, "Admin Group", groupsList[0]["name"])
			},
		},
		{
			name: "create app authentication struct with no idp membership",
			app: &Application{
				UUIDURL: "app-uuid-no-idp",
				Name:    "No IDP App",
			},
			mockIdpResponse: &AppIdpMembershipResponse{
				Meta:              Meta{TotalCount: 0},
				AppIdpMemberships: []AppIdpMembership{},
			},
			mockStatusCode:      http.StatusOK,
			expectError:         false,
			expectedStructCount: 1,
			checkContent: func(t *testing.T, result []interface{}) {
				require.Len(t, result, 1)
				authStruct, ok := result[0].(map[string]interface{})
				require.True(t, ok)

				// Should not have app_idp
				_, exists := authStruct["app_idp"]
				assert.False(t, exists)
			},
		},
		{
			name: "idp membership fetch fails",
			app: &Application{
				UUIDURL: "app-uuid-idp-error",
				Name:    "IDP Error App",
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "unable to get app idp membership",
		},
		{
			name: "directory membership fetch fails",
			app: &Application{
				UUIDURL: "app-uuid-dir-error",
				Name:    "Directory Error App",
			},
			mockIdpResponse: &AppIdpMembershipResponse{
				Meta: Meta{TotalCount: 1},
				AppIdpMemberships: []AppIdpMembership{
					{
						UUIDURL: "idp-membership-1",
						IDP: IDPMembership{
							IDPUUIDURL: "idp-uuid-1",
							Name:       "Azure AD",
						},
					},
				},
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "unable to get app directory membership",
		},
		{
			name: "group membership fetch fails",
			app: &Application{
				UUIDURL: "app-uuid-group-error",
				Name:    "Group Error App",
			},
			mockIdpResponse: &AppIdpMembershipResponse{
				Meta: Meta{TotalCount: 1},
				AppIdpMemberships: []AppIdpMembership{
					{
						UUIDURL: "idp-membership-1",
						IDP: IDPMembership{
							IDPUUIDURL: "idp-uuid-1",
							Name:       "Azure AD",
						},
					},
				},
			},
			mockDirResponse: &AppDirectoryMembershipResponse{
				Meta: Meta{TotalCount: 1},
				AppDirectoryMemberships: []AppDirectoryMembership{
					{
						UUIDURL: "dir-membership-1",
						Directory: DirectoryMembership{
							DirectoryUUIDURL: "dir-uuid-1",
							Name:             "Active Directory",
						},
					},
				},
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "unable to get app group membership",
		},
		{
			name: "idp membership not found",
			app: &Application{
				UUIDURL: "app-uuid-idp-notfound",
				Name:    "IDP NotFound App",
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "unable to get app idp membership",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestCount := 0

			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				requestCount++

				// Determine status code based on endpoint and test case
				statusCode := tc.mockStatusCode
				idpPath := "/crux/v1/mgmt-pop/apps/" + tc.app.UUIDURL + "/idp_membership"
				dirPath := "/crux/v1/mgmt-pop/apps/" + tc.app.UUIDURL + "/directories_membership"
				groupPath := "/crux/v1/mgmt-pop/apps/" + tc.app.UUIDURL + "/groups"

				// Route different responses based on URL path
				if r.URL.Path == idpPath {
					// Check if this endpoint should fail
					if tc.errorContains != "" && (tc.errorContains == "unable to get app idp membership" || tc.name == "idp membership fetch fails" || tc.name == "idp membership not found") {
						w.WriteHeader(statusCode)
						return
					}
					w.WriteHeader(http.StatusOK)
					if tc.mockIdpResponse != nil {
						responseJSON, _ := json.Marshal(tc.mockIdpResponse)
						w.Write(responseJSON)
					}
				} else if r.URL.Path == dirPath {
					// Check if this endpoint should fail
					if tc.errorContains != "" && tc.errorContains == "unable to get app directory membership" {
						w.WriteHeader(statusCode)
						return
					}
					w.WriteHeader(http.StatusOK)
					if tc.mockDirResponse != nil {
						responseJSON, _ := json.Marshal(tc.mockDirResponse)
						w.Write(responseJSON)
					} else {
						// Default empty response
						emptyResponse := AppDirectoryMembershipResponse{
							Meta:                    Meta{TotalCount: 0},
							AppDirectoryMemberships: []AppDirectoryMembership{},
						}
						responseJSON, _ := json.Marshal(emptyResponse)
						w.Write(responseJSON)
					}
				} else if r.URL.Path == groupPath {
					// Check if this endpoint should fail
					if tc.errorContains != "" && tc.errorContains == "unable to get app group membership" {
						w.WriteHeader(statusCode)
						return
					}
					w.WriteHeader(http.StatusOK)
					if tc.mockGroupResponse != nil {
						responseJSON, _ := json.Marshal(tc.mockGroupResponse)
						w.Write(responseJSON)
					} else {
						// Default empty response
						emptyResponse := AppGroupMembershipResponse{
							Meta:                Meta{TotalCount: 0},
							AppGroupMemberships: []AppGroupMembership{},
						}
						responseJSON, _ := json.Marshal(emptyResponse)
						w.Write(responseJSON)
					}
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(), // Use the TLS client from the test server
			}

			// Execute function
			result, err := tc.app.CreateAppAuthenticationStruct(client)

			// Assertions
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result, tc.expectedStructCount)
				if tc.checkContent != nil {
					tc.checkContent(t, result)
				}
			}
		})
	}
}
