package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetIDPS(t *testing.T) {
	testCases := []struct {
		name           string
		mockResponse   *IDPResponse
		mockDirResp    *DirectoryResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedCount  int
	}{
		{
			name: "successful get IDPs",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 2,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{
					{
						Name:    "Corporate AD",
						UUIDURL: "idp-uuid-1",
					},
					{
						Name:    "External LDAP",
						UUIDURL: "idp-uuid-2",
					},
				},
			},
			mockDirResp: &DirectoryResponse{
				Meta: Meta{TotalCount: 1},
				DirectoryList: []DirectoryData{
					{
						Name: "Default Directory",
						UUID: "dir-uuid-1",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  2,
		},
		{
			name: "empty IDPs list",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 0,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{},
			},
			mockDirResp: &DirectoryResponse{
				Meta:          Meta{TotalCount: 0},
				DirectoryList: []DirectoryData{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
		{
			name:           "server error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:           "bad request",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:           "unauthorized",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:           "forbidden",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:           "not found",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name: "IDPs with empty name or UUID are skipped",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 3,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{
					{
						Name:    "Valid IDP",
						UUIDURL: "idp-uuid-1",
					},
					{
						Name:    "", // Empty name - should be skipped
						UUIDURL: "idp-uuid-2",
					},
					{
						Name:    "Another Valid IDP",
						UUIDURL: "", // Empty UUID - should be skipped
					},
				},
			},
			mockDirResp: &DirectoryResponse{
				Meta: Meta{TotalCount: 0},
				DirectoryList: []DirectoryData{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  1, // Only one valid IDP should be returned
		},
		{
			name: "GetIDPDirectories fails for one IDP",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 2,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{
					{
						Name:    "IDP 1",
						UUIDURL: "idp-uuid-1",
					},
					{
						Name:    "IDP 2",
						UUIDURL: "idp-uuid-2",
					},
				},
			},
			mockDirResp:    nil, // Will cause GetIDPDirectories to fail
			mockStatusCode: http.StatusInternalServerError, // This will be used for directory requests
			expectError:    true,
			errorContains:  "idps get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)

				if r.URL.Path == "/crux/v1/mgmt-pop/idp" {
					// Main IDP request
					w.WriteHeader(tc.mockStatusCode)

					if tc.mockResponse != nil {
						jsonResp, err := json.Marshal(tc.mockResponse)
						require.NoError(t, err)
						w.Write(jsonResp)
					} else if tc.expectError && tc.mockStatusCode >= http.StatusBadRequest {
						// Send ErrorResponse for error cases
						errorResp := ErrorResponse{
							Title:  "Internal Server Error",
							Detail: tc.errorContains,
						}
						json.NewEncoder(w).Encode(errorResp)
					}
				} else if strings.HasPrefix(r.URL.Path, "/crux/v1/mgmt-pop/idp/") && strings.HasSuffix(r.URL.Path, "/directories") {
					// Directory request for specific IDP
					// Check if we should return error for directory requests
					if tc.mockStatusCode >= http.StatusBadRequest && tc.mockDirResp == nil {
						w.WriteHeader(tc.mockStatusCode)
						errorResp := ErrorResponse{
							Title:  "Internal Server Error",
							Detail: "idp directories get failed",
						}
						json.NewEncoder(w).Encode(errorResp)
					} else {
						w.WriteHeader(http.StatusOK)
						if tc.mockDirResp != nil {
							jsonResp, err := json.Marshal(tc.mockDirResp)
							require.NoError(t, err)
							w.Write(jsonResp)
						}
					}
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create test client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           server.Client(), // Use TLS client from server
				Signer:           &MockSigner{},
				Host:             serverURL.Host,
				Logger:           hclog.NewNullLogger(),
			}

			// Call function under test
			ctx := context.Background()
			result, err := GetIDPS(ctx, client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if tc.expectedCount == 0 {
					// For empty results, check if result is empty
					if result != nil {
						assert.Equal(t, 0, len(result.IDPS))
					}
				} else {
					assert.NotNil(t, result)
					assert.Equal(t, tc.expectedCount, len(result.IDPS))

					// Verify all returned IDPs have name and uuid
					for _, idp := range result.IDPS {
						assert.NotEmpty(t, idp.Name)
						assert.NotEmpty(t, idp.UUIDURL)
					}
				}
			}
		})
	}
}

func TestGetIDPDirectories(t *testing.T) {
	testCases := []struct {
		name           string
		idpUUID        string
		mockResponse   *DirectoryResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedCount  int
	}{
		{
			name:    "successful get IDP directories",
			idpUUID: "idp-uuid-123",
			mockResponse: &DirectoryResponse{
				Meta: Meta{
					TotalCount: 2,
					Limit:      20,
					Offset:     0,
				},
				DirectoryList: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
					},
					{
						Name: "Engineering Directory",
						UUID: "dir-uuid-2",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  2,
		},
		{
			name:    "empty directories list",
			idpUUID: "idp-uuid-empty",
			mockResponse: &DirectoryResponse{
				Meta: Meta{
					TotalCount: 0,
					Limit:      20,
					Offset:     0,
				},
				DirectoryList: []DirectoryData{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
		{
			name:           "server error",
			idpUUID:        "idp-uuid-error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "idp directories get failed",
		},
		{
			name:           "bad request",
			idpUUID:        "idp-uuid-error",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "idp directories get failed",
		},
		{
			name:           "unauthorized",
			idpUUID:        "idp-uuid-error",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "idp directories get failed",
		},
		{
			name:           "forbidden",
			idpUUID:        "idp-uuid-error",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "idp directories get failed",
		},
		{
			name:           "not found",
			idpUUID:        "idp-uuid-error",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "idp directories get failed",
		},
		{
			name:    "directories with empty name or UUID are skipped",
			idpUUID: "idp-uuid-123",
			mockResponse: &DirectoryResponse{
				Meta: Meta{
					TotalCount: 3,
					Limit:      20,
					Offset:     0,
				},
				DirectoryList: []DirectoryData{
					{
						Name: "Valid Directory",
						UUID: "dir-uuid-1",
					},
					{
						Name: "", // Empty name - should be skipped
						UUID: "dir-uuid-2",
					},
					{
						Name: "Another Valid Directory",
						UUID: "", // Empty UUID - should be skipped
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  1, // Only one valid directory should be returned
		},
		{
			name:    "groups with empty name or UUID are skipped",
			idpUUID: "idp-uuid-123",
			mockResponse: &DirectoryResponse{
				Meta: Meta{
					TotalCount: 1,
					Limit:      20,
					Offset:     0,
				},
				DirectoryList: []DirectoryData{
					{
						Name: "Valid Directory",
						UUID: "dir-uuid-1",
						Groups: []GroupData{
							{
								Name:     "Valid Group",
								UUID_URL: "group-uuid-1",
							},
							{
								Name:     "", // Empty name - should be skipped
								UUID_URL: "group-uuid-2",
							},
							{
								Name:     "Another Valid Group",
								UUID_URL: "", // Empty UUID - should be skipped
							},
						},
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  1, // One directory with one valid group
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := fmt.Sprintf("/crux/v1/mgmt-pop/idp/%s/directories", tc.idpUUID)
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)

				if tc.mockResponse != nil {
					jsonResp, err := json.Marshal(tc.mockResponse)
					require.NoError(t, err)
					w.Write(jsonResp)
				} else if tc.expectError && tc.mockStatusCode >= http.StatusBadRequest {
					// Send ErrorResponse for error cases
					errorResp := ErrorResponse{
						Title:  "Internal Server Error",
						Detail: tc.errorContains,
					}
					json.NewEncoder(w).Encode(errorResp)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create test client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           server.Client(), // Use TLS client from server
				Signer:           &MockSigner{},
				Host:             serverURL.Host,
				Logger:           hclog.NewNullLogger(),
			}

			// Call function under test
			result, err := GetIDPDirectories(client, tc.idpUUID)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if tc.expectedCount == 0 {
					// For empty results, the function returns empty slice
					assert.NotNil(t, result)
					assert.Equal(t, 0, len(result))
				} else {
					assert.NotNil(t, result)
					assert.Equal(t, tc.expectedCount, len(result))

					// Verify all returned directories have name and uuid
					for _, dir := range result {
						assert.NotEmpty(t, dir.Name)
						assert.NotEmpty(t, dir.UUID)
					}
				}
			}
		})
	}
}

func TestGetIdpWithName(t *testing.T) {
	testCases := []struct {
		name           string
		idpName        string
		mockResponse   *IDPResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedFound  bool
		expectedUUID   string
	}{
		{
			name:    "successful find IDP by name",
			idpName: "Corporate AD",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 3,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{
					{
						Name:    "External LDAP",
						UUIDURL: "idp-uuid-1",
					},
					{
						Name:    "Corporate AD",
						UUIDURL: "idp-uuid-2",
					},
					{
						Name:    "Third Party IDP",
						UUIDURL: "idp-uuid-3",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedFound:  true,
			expectedUUID:   "idp-uuid-2",
		},
		{
			name:    "IDP not found by name",
			idpName: "Nonexistent IDP",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 2,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{
					{
						Name:    "Corporate AD",
						UUIDURL: "idp-uuid-1",
					},
					{
						Name:    "External LDAP",
						UUIDURL: "idp-uuid-2",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
			errorContains:  "IDP with name not found",
			expectedFound:  false,
		},
		{
			name:    "case sensitive search",
			idpName: "corporate ad", // lowercase
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 1,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{
					{
						Name:    "Corporate AD", // uppercase
						UUIDURL: "idp-uuid-1",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
			errorContains:  "IDP with name not found",
			expectedFound:  false, // Should not find due to case mismatch
		},
		{
			name:    "empty IDPs list",
			idpName: "Any IDP",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 0,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
			errorContains:  "IDP with name not found",
			expectedFound:  false,
		},
		{
			name:           "GetIDPS error",
			idpName:        "Test IDP",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:           "GetIDPS bad request",
			idpName:        "Test IDP",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:           "GetIDPS unauthorized",
			idpName:        "Test IDP",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:           "GetIDPS forbidden",
			idpName:        "Test IDP",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "idps get failed",
		},
		{
			name:    "GetIDPDirectories fails after finding IDP",
			idpName: "Corporate AD",
			mockResponse: &IDPResponse{
				Meta: Meta{
					TotalCount: 1,
					Limit:      20,
					Offset:     0,
				},
				IDPS: []IDPResponseData{
					{
						Name:    "Corporate AD",
						UUIDURL: "idp-uuid-1",
					},
				},
			},
			mockStatusCode: http.StatusInternalServerError, // This will be used for directory requests
			expectError:    true,
			errorContains:  "idps get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server to handle multiple endpoints
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)

				// Handle main IDP endpoint
				if r.URL.Path == "/crux/v1/mgmt-pop/idp" {
					w.WriteHeader(tc.mockStatusCode)

					if tc.mockResponse != nil {
						jsonResp, err := json.Marshal(tc.mockResponse)
						require.NoError(t, err)
						w.Write(jsonResp)
					} else if tc.expectError && tc.mockStatusCode >= http.StatusBadRequest {
						// Send ErrorResponse for error cases
						errorResp := ErrorResponse{
							Title:  "Internal Server Error",
							Detail: tc.errorContains,
						}
						json.NewEncoder(w).Encode(errorResp)
					}
				} else if strings.HasPrefix(r.URL.Path, "/crux/v1/mgmt-pop/idp/") && strings.HasSuffix(r.URL.Path, "/directories") {
					// Handle directories endpoint
					// Check if we should return error for directory requests
					if tc.mockStatusCode >= http.StatusBadRequest {
						w.WriteHeader(tc.mockStatusCode)
						errorResp := ErrorResponse{
							Title:  "Internal Server Error",
							Detail: "idp directories get failed",
						}
						json.NewEncoder(w).Encode(errorResp)
					} else {
						w.WriteHeader(http.StatusOK)
						dirResponse := DirectoryResponse{
							Meta: Meta{
								TotalCount: 0,
								Limit:      20,
								Offset:     0,
							},
							DirectoryList: []DirectoryData{},
						}
						json.NewEncoder(w).Encode(dirResponse)
					}
				} else {
					// Unexpected endpoint
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create test client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           server.Client(), // Use TLS client from server
				Signer:           &MockSigner{},
				Host:             serverURL.Host,
				Logger:           hclog.NewNullLogger(),
			}

			// Call function under test
			ctx := context.Background()
			result, err := GetIdpWithName(ctx, client, tc.idpName)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if tc.expectedFound {
					assert.NotNil(t, result)
					assert.Equal(t, tc.idpName, result.Name)
					assert.Equal(t, tc.expectedUUID, result.UUIDURL)
				} else {
					assert.Nil(t, result)
				}
			}
		})
	}
}

// TestGetIdpDirectory tests the GetIdpDirectory method on IDPData
func TestGetIdpDirectory(t *testing.T) {
	testCases := []struct {
		name          string
		idpData       *IDPData
		dirName       string
		expectError   bool
		errorContains string
		expectedName  string
		expectedUUID  string
	}{
		{
			name: "successful get directory by name",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
					},
					{
						Name: "Engineering Directory",
						UUID: "dir-uuid-2",
					},
				},
			},
			dirName:       "Sales Directory",
			expectError:   false,
			expectedName:  "Sales Directory",
			expectedUUID:  "dir-uuid-1",
		},
		{
			name: "directory not found",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
					},
				},
			},
			dirName:       "Nonexistent Directory",
			expectError:   true,
			errorContains: "IDP with name not found",
		},
		{
			name: "empty directories list",
			idpData: &IDPData{
				Name:        "Corporate AD",
				UUIDURL:     "idp-uuid-1",
				Directories: []DirectoryData{},
			},
			dirName:       "Any Directory",
			expectError:   true,
			errorContains: "IDP with name not found",
		},
		{
			name: "case sensitive search",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
					},
				},
			},
			dirName:       "sales directory", // lowercase
			expectError:   true,
			errorContains: "IDP with name not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test client
			client := &EaaClient{
				Logger: hclog.NewNullLogger(),
			}

			// Call function under test
			ctx := context.Background()
			result, err := tc.idpData.GetIdpDirectory(ctx, client, tc.dirName)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.expectedName, result.Name)
				assert.Equal(t, tc.expectedUUID, result.UUID)
			}
		})
	}
}

// TestAssignIdpDirectories tests the AssignIdpDirectories method on IDPData
func TestAssignIdpDirectories(t *testing.T) {
	testCases := []struct {
		name                 string
		idpData              *IDPData
		appDirs              interface{}
		appUUID              string
		mockStatusCode       int
		expectError          bool
		errorContains        string
		groupAssignmentFails bool // Special flag to indicate group assignment should fail while directory succeeds
	}{
		{
			name: "successful assign directories",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
					},
					{
						Name: "Engineering Directory",
						UUID: "dir-uuid-2",
					},
				},
			},
			appDirs: []interface{}{
				map[string]interface{}{
					"name":       "Sales Directory",
					"enable_mfa": false,
				},
			},
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "successful assign directories with groups",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
						Groups: []GroupData{
							{
								Name:     "Sales Team",
								UUID_URL: "group-uuid-1",
							},
						},
					},
				},
			},
			appDirs: []interface{}{
				map[string]interface{}{
					"name": "Sales Directory",
					"app_groups": []interface{}{
						map[string]interface{}{
							"name": "Sales Team",
						},
					},
				},
			},
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "successful assign all directory groups",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
						Groups: []GroupData{
							{
								Name:     "Sales Team",
								UUID_URL: "group-uuid-1",
							},
						},
					},
				},
			},
			appDirs: []interface{}{
				map[string]interface{}{
					"name":       "Sales Directory",
					"app_groups": []interface{}{}, // Empty list assigns all groups
				},
			},
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "directory not found in IDP - skipped",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
					},
				},
			},
			appDirs: []interface{}{
				map[string]interface{}{
					"name": "Nonexistent Directory",
				},
			},
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false, // Directory not found is skipped, not an error
		},
		{
			name: "directory assignment fails",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
					},
				},
			},
			appDirs: []interface{}{
				map[string]interface{}{
					"name": "Sales Directory",
				},
			},
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "assigning directory to the app failed",
		},
		{
			name: "group assignment fails",
			idpData: &IDPData{
				Name:    "Corporate AD",
				UUIDURL: "idp-uuid-1",
				Directories: []DirectoryData{
					{
						Name: "Sales Directory",
						UUID: "dir-uuid-1",
						Groups: []GroupData{
							{
								Name:     "Sales Team",
								UUID_URL: "group-uuid-1",
							},
						},
					},
				},
			},
			appDirs: []interface{}{
				map[string]interface{}{
					"name": "Sales Directory",
					"app_groups": []interface{}{
						map[string]interface{}{
							"name": "Sales Team",
						},
					},
				},
			},
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "assigning groups to the app failed",
			groupAssignmentFails: true, // Special flag to indicate group assignment should fail
		},
		{
			name: "invalid appDirs type",
			idpData: &IDPData{
				Name:        "Corporate AD",
				UUIDURL:     "idp-uuid-1",
				Directories: []DirectoryData{},
			},
			appDirs:        "invalid-type", // Not a list
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false, // Invalid type is silently ignored
		},
		{
			name: "empty appDirs list",
			idpData: &IDPData{
				Name:        "Corporate AD",
				UUIDURL:     "idp-uuid-1",
				Directories: []DirectoryData{},
			},
			appDirs:        []interface{}{},
			appUUID:        "app-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
	}

		for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle directory assignment endpoint
				if strings.Contains(r.URL.Path, "/crux/v1/mgmt-pop/appdirectories") {
					// For group assignment failure test, directory assignment should succeed
					if tc.groupAssignmentFails {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"success": true}`))
					} else {
						w.WriteHeader(tc.mockStatusCode)
						if tc.mockStatusCode == http.StatusOK {
							w.Write([]byte(`{"success": true}`))
						} else {
							errorResp := ErrorResponse{
								Title:  "Internal Server Error",
								Detail: "assigning directory to the app failed",
							}
							json.NewEncoder(w).Encode(errorResp)
						}
					}
				} else if strings.Contains(r.URL.Path, "/crux/v1/mgmt-pop/appidp") || strings.Contains(r.URL.Path, "/crux/v1/mgmt-pop/appgroups") {
					// Handle group assignment endpoint
					if tc.groupAssignmentFails {
						// For group assignment failure test, return error
						w.WriteHeader(tc.mockStatusCode)
						errorResp := ErrorResponse{
							Title:  "Internal Server Error",
							Detail: "assigning groups to the app failed",
						}
						json.NewEncoder(w).Encode(errorResp)
					} else {
						w.WriteHeader(tc.mockStatusCode)
						if tc.mockStatusCode == http.StatusOK {
							w.Write([]byte(`{"success": true}`))
						} else {
							errorResp := ErrorResponse{
								Title:  "Internal Server Error",
								Detail: "assigning groups to the app failed",
							}
							json.NewEncoder(w).Encode(errorResp)
						}
					}
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create test client
			client := &EaaClient{
				ContractID:       "G-12345",
				AccountSwitchKey: "",
				Client:           server.Client(),
				Signer:           &MockSigner{},
				Host:             serverURL.Host,
				Logger:           hclog.NewNullLogger(),
			}

			// Call function under test
			ctx := context.Background()
			err := tc.idpData.AssignIdpDirectories(ctx, tc.appDirs, tc.appUUID, client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
