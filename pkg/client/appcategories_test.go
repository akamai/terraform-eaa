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

func TestGetAppCategories(t *testing.T) {
	testCases := []struct {
		name           string
		mockResponse   *AppCategoryResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedCount  int
	}{
		{
			name: "successful get app categories",
			mockResponse: &AppCategoryResponse{
				Meta: struct {
					Limit      int     `json:"limit,omitempty"`
					Next       *string `json:"next,omitempty"`
					Offset     int     `json:"offset,omitempty"`
					Previous   *string `json:"previous,omitempty"`
					TotalCount int     `json:"total_count,omitempty"`
				}{
					TotalCount: 3,
					Limit:      20,
					Offset:     0,
				},
				AppCategories: []AppCate{
					{
						Name:    "Web Applications",
						UUIDURL: "category-uuid-1",
					},
					{
						Name:    "Database Applications",
						UUIDURL: "category-uuid-2",
					},
					{
						Name:    "File Sharing",
						UUIDURL: "category-uuid-3",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  3,
		},
		{
			name: "empty categories list",
			mockResponse: &AppCategoryResponse{
				Meta: struct {
					Limit      int     `json:"limit,omitempty"`
					Next       *string `json:"next,omitempty"`
					Offset     int     `json:"offset,omitempty"`
					Previous   *string `json:"previous,omitempty"`
					TotalCount int     `json:"total_count,omitempty"`
				}{
					TotalCount: 0,
					Limit:      20,
					Offset:     0,
				},
				AppCategories: []AppCate{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
		{
			name: "filter categories with missing name or uuid",
			mockResponse: &AppCategoryResponse{
				Meta: struct {
					Limit      int     `json:"limit,omitempty"`
					Next       *string `json:"next,omitempty"`
					Offset     int     `json:"offset,omitempty"`
					Previous   *string `json:"previous,omitempty"`
					TotalCount int     `json:"total_count,omitempty"`
				}{
					TotalCount: 4,
					Limit:      20,
					Offset:     0,
				},
				AppCategories: []AppCate{
					{
						Name:    "Valid Category",
						UUIDURL: "category-uuid-1",
					},
					{
						Name:    "", // Missing name - should be filtered
						UUIDURL: "category-uuid-2",
					},
					{
						Name:    "Missing UUID Category",
						UUIDURL: "", // Missing UUID - should be filtered
					},
					{
						Name:    "Another Valid Category",
						UUIDURL: "category-uuid-4",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  2, // Only 2 valid categories
		},
		{
			name:           "server error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "app categories get failed",
		},
		{
			name:           "not found error",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "app categories get failed",
		},
		{
			name:           "bad request error",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "app categories get failed",
		},
		{
			name:           "unauthorized error",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "app categories get failed",
		},
		{
			name:           "forbidden error",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "app categories get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/appcategories", r.URL.Path)

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
			result, err := GetAppCategories(client)

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
					// For empty results, the function returns nil slice
					assert.Nil(t, result)
				} else {
					assert.NotNil(t, result)
					assert.Equal(t, tc.expectedCount, len(result))

					// Verify all returned categories have name and uuid
					for _, category := range result {
						assert.NotEmpty(t, category.Name)
						assert.NotEmpty(t, category.UUIDURL)
					}
				}
			}
		})
	}
}

func TestGetAppCategoryUuid(t *testing.T) {
	testCases := []struct {
		name         string
		searchName   string
		mockResponse *AppCategoryResponse
		expectFound  bool
		expectedUUID string
		expectError  bool
		errorMsg     string
	}{
		{
			name:       "successful find category by name",
			searchName: "Web Applications",
			mockResponse: &AppCategoryResponse{
				Meta: struct {
					Limit      int     `json:"limit,omitempty"`
					Next       *string `json:"next,omitempty"`
					Offset     int     `json:"offset,omitempty"`
					Previous   *string `json:"previous,omitempty"`
					TotalCount int     `json:"total_count,omitempty"`
				}{TotalCount: 2},
				AppCategories: []AppCate{
					{
						Name:    "Web Applications",
						UUIDURL: "category-uuid-web",
					},
					{
						Name:    "Database Applications",
						UUIDURL: "category-uuid-db",
					},
				},
			},
			expectFound:  true,
			expectedUUID: "category-uuid-web",
			expectError:  false,
		},
		{
			name:       "category not found",
			searchName: "Non-existent Category",
			mockResponse: &AppCategoryResponse{
				Meta: struct {
					Limit      int     `json:"limit,omitempty"`
					Next       *string `json:"next,omitempty"`
					Offset     int     `json:"offset,omitempty"`
					Previous   *string `json:"previous,omitempty"`
					TotalCount int     `json:"total_count,omitempty"`
				}{TotalCount: 1},
				AppCategories: []AppCate{
					{
						Name:    "Web Applications",
						UUIDURL: "category-uuid-web",
					},
				},
			},
			expectFound: false,
			expectError: true,
			errorMsg:    "category 'Non-existent Category' not found",
		},
		{
			name:       "empty categories list",
			searchName: "Any Category",
			mockResponse: &AppCategoryResponse{
				Meta: struct {
					Limit      int     `json:"limit,omitempty"`
					Next       *string `json:"next,omitempty"`
					Offset     int     `json:"offset,omitempty"`
					Previous   *string `json:"previous,omitempty"`
					TotalCount int     `json:"total_count,omitempty"`
				}{TotalCount: 0},
				AppCategories: []AppCate{},
			},
			expectFound: false,
			expectError: true,
			errorMsg:    "category 'Any Category' not found",
		},
		{
			name:       "case sensitive search",
			searchName: "web applications", // lowercase
			mockResponse: &AppCategoryResponse{
				Meta: struct {
					Limit      int     `json:"limit,omitempty"`
					Next       *string `json:"next,omitempty"`
					Offset     int     `json:"offset,omitempty"`
					Previous   *string `json:"previous,omitempty"`
					TotalCount int     `json:"total_count,omitempty"`
				}{TotalCount: 1},
				AppCategories: []AppCate{
					{
						Name:    "Web Applications", // capitalized
						UUIDURL: "category-uuid-web",
					},
				},
			},
			expectFound: false,
			expectError: true,
			errorMsg:    "category 'web applications' not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/appcategories", r.URL.Path)

				w.WriteHeader(http.StatusOK)
				jsonResp, err := json.Marshal(tc.mockResponse)
				require.NoError(t, err)
				w.Write(jsonResp)
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
			uuid, err := GetAppCategoryUuid(client, tc.searchName)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				assert.Empty(t, uuid)
			} else {
				assert.NoError(t, err)
				if tc.expectFound {
					assert.Equal(t, tc.expectedUUID, uuid)
				} else {
					assert.Empty(t, uuid)
				}
			}
		})
	}
}

func TestGetAppCategoryUuid_GetCategoriesError(t *testing.T) {
	// Test case where GetAppCategories fails
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		errorResp := ErrorResponse{
			Title:  "Internal Server Error",
			Detail: "Server error",
		}
		json.NewEncoder(w).Encode(errorResp)
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
	uuid, err := GetAppCategoryUuid(client, "Test Category")

	// Verify results
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "app categories get failed")
	assert.Empty(t, uuid)
}
