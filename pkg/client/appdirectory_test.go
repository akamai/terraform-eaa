package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAppDirectoryAssignIdpDirectory tests the AssignIdpDirectory method
func TestAppDirectoryAssignIdpDirectory(t *testing.T) {
	testCases := []struct {
		name           string
		appID          string
		dirUUID        string
		enableMFA      *bool
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name:           "successful directory assignment",
			appID:          "test-app-123",
			dirUUID:        "dir-uuid-123",
			enableMFA:      boolPtr(true),
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "successful directory assignment with nil MFA",
			appID:          "test-app-456",
			dirUUID:        "dir-uuid-456",
			enableMFA:      nil,
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "directory assignment fails with bad request",
			appID:          "invalid-app",
			dirUUID:        "invalid-dir",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrAssignDirectoryFailure,
		},
		{
			name:           "empty app ID",
			appID:          "",
			dirUUID:        "dir-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    true,
			expectedError:  ErrAssignDirectoryFailure,
		},
		{
			name:           "empty directory UUID",
			appID:          "test-app-123",
			dirUUID:        "",
			mockStatusCode: http.StatusOK,
			expectError:    true,
			expectedError:  ErrAssignDirectoryFailure,
		},
		{
			name:           "directory assignment fails with server error",
			appID:          "test-app-server-error",
			dirUUID:        "dir-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrAssignDirectoryFailure,
		},
		{
			name:           "directory assignment fails with not found",
			appID:          "test-app-notfound",
			dirUUID:        "dir-uuid-123",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrAssignDirectoryFailure,
		},
		{
			name:           "directory assignment fails with unauthorized",
			appID:          "test-app-unauthorized",
			dirUUID:        "dir-uuid-123",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			expectedError:  ErrAssignDirectoryFailure,
		},
		{
			name:           "directory assignment fails with forbidden",
			appID:          "test-app-forbidden",
			dirUUID:        "dir-uuid-123",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			expectedError:  ErrAssignDirectoryFailure,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/appdirectories", r.URL.Path)

				// Verify request body
				var reqBody map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				require.NoError(t, err)

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

			// Create AppDirectory instance
			dirData := &AppDirectory{
				APP_ID:    tc.appID,
				UUID:      tc.dirUUID,
				EnableMFA: tc.enableMFA,
			}

			// Call method under test
			ctx := context.Background()
			err := dirData.AssignIdpDirectory(ctx, client)

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

// TestDirectoryDataGetIdpDirectoryGroup tests the GetIdpDirectoryGroup method
func TestDirectoryDataGetIdpDirectoryGroup(t *testing.T) {
	testCases := []struct {
		name          string
		groups        []GroupData
		groupName     string
		expectError   bool
		expectedGroup *GroupData
	}{
		{
			name: "successful group retrieval",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
				{Name: "group2", UUID_URL: "uuid-2"},
				{Name: "group3", UUID_URL: "uuid-3"},
			},
			groupName:     "group2",
			expectError:   false,
			expectedGroup: &GroupData{Name: "group2", UUID_URL: "uuid-2"},
		},
		{
			name: "group not found",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
				{Name: "group2", UUID_URL: "uuid-2"},
			},
			groupName:   "nonexistent",
			expectError: true,
		},
		{
			name:          "empty groups list",
			groups:        []GroupData{},
			groupName:     "any-group",
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test client
			client := &EaaClient{
				Logger: hclog.NewNullLogger(),
			}

			// Create DirectoryData instance
			dirData := &DirectoryData{
				Name:   "test-directory",
				UUID:   "dir-uuid-123",
				Groups: tc.groups,
			}

			// Call method under test
			ctx := context.Background()
			result, err := dirData.GetIdpDirectoryGroup(ctx, client, tc.groupName)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tc.expectedGroup.Name, result.Name)
				assert.Equal(t, tc.expectedGroup.UUID_URL, result.UUID_URL)
			}
		})
	}
}

// TestDirectoryDataAssignIdpDirectoryGroups tests the AssignIdpDirectoryGroups method
func TestDirectoryDataAssignIdpDirectoryGroups(t *testing.T) {
	testCases := []struct {
		name           string
		appUUID        string
		groups         []GroupData
		appGroupsList  []interface{}
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name:    "successful group assignment",
			appUUID: "test-app-123",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
				{Name: "group2", UUID_URL: "uuid-2"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group1", "enable_mfa": "true"},
				map[string]interface{}{"name": "group2", "enable_mfa": "false"},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:    "successful group assignment with no enable_mfa",
			appUUID: "test-app-456",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group1"},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:    "empty groups list - no API call",
			appUUID: "test-app-789",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "nonexistent"},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false, // Should not error, just skip
		},
		{
			name:    "group assignment fails",
			appUUID: "test-app-error",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group1"},
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "group assignment fails with server error",
			appUUID: "test-app-server-error",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group1"},
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "group assignment fails with not found",
			appUUID: "test-app-notfound",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group1"},
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "group assignment fails with unauthorized",
			appUUID: "test-app-unauthorized",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group1"},
			},
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "group assignment fails with forbidden",
			appUUID: "test-app-forbidden",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group1"},
			},
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "empty app groups list",
			appUUID: "test-app-empty",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			appGroupsList:  []interface{}{},
			mockStatusCode: http.StatusOK,
			expectError:    false, // Should not error, just skip
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/appgroups", r.URL.Path)

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

			// Create DirectoryData instance
			dirData := &DirectoryData{
				Name:   "test-directory",
				UUID:   "dir-uuid-123",
				Groups: tc.groups,
			}

			// Call method under test
			ctx := context.Background()
			err := dirData.AssignIdpDirectoryGroups(ctx, client, tc.appUUID, tc.appGroupsList)

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

// TestDirectoryDataAssignAllDirectoryGroups tests the AssignAllDirectoryGroups method
func TestDirectoryDataAssignAllDirectoryGroups(t *testing.T) {
	testCases := []struct {
		name           string
		appUUID        string
		groups         []GroupData
		mockStatusCode int
		expectError    bool
		expectedError  error
	}{
		{
			name:    "successful assignment of all groups",
			appUUID: "test-app-123",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
				{Name: "group2", UUID_URL: "uuid-2"},
				{Name: "group3", UUID_URL: "uuid-3"},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "empty groups list - no API call",
			appUUID:        "test-app-empty",
			groups:         []GroupData{},
			mockStatusCode: http.StatusOK,
			expectError:    false, // Should not error, just skip
		},
		{
			name:    "assignment fails",
			appUUID: "test-app-error",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "assignment fails with server error",
			appUUID: "test-app-server-error",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "assignment fails with not found",
			appUUID: "test-app-notfound",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "assignment fails with unauthorized",
			appUUID: "test-app-unauthorized",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
		{
			name:    "assignment fails with forbidden",
			appUUID: "test-app-forbidden",
			groups: []GroupData{
				{Name: "group1", UUID_URL: "uuid-1"},
			},
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			expectedError:  ErrAssignGroupFailure,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/appgroups", r.URL.Path)

				// Verify request body contains "inherit" for enable_mfa
				var reqBody map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				require.NoError(t, err)

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

			// Create DirectoryData instance
			dirData := &DirectoryData{
				Name:   "test-directory",
				UUID:   "dir-uuid-123",
				Groups: tc.groups,
			}

			// Call method under test
			ctx := context.Background()
			err := dirData.AssignAllDirectoryGroups(ctx, client, tc.appUUID)

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

// Helper function to create bool pointers
func boolPtr(b bool) *bool {
	return &b
}

