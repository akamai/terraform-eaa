package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateRegistrationTokenRequestFromSchema tests CreateRegistrationTokenRequestFromSchema
func TestCreateRegistrationTokenRequestFromSchema(t *testing.T) {
	testCases := []struct {
		name        string
		data        map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful token request creation",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":              "test-token",
						"max_use":           5,
						"expires_in_days":   30,
						"generate_embedded_img": true,
					},
				},
			},
			expectError: false,
		},
		{
			name: "token request with defaults",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "default-token",
						"max_use":         1, // Default value
						"expires_in_days": 30, // Required for validation
					},
				},
			},
			expectError: false,
		},
		{
			name: "no registration tokens",
			data: map[string]interface{}{},
			expectError: true,
			errorMsg:    "no registration tokens found in schema",
		},
		{
			name: "empty registration tokens list",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{},
			},
			expectError: true,
			errorMsg:    "no registration tokens found in schema",
		},
		{
			name: "missing name field",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"max_use":         5,
						"expires_in_days": 30,
					},
				},
			},
			expectError: true,
			errorMsg:    "failed to validate token name",
		},
		{
			name: "invalid max_use - too low",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         0, // Below minimum
						"expires_in_days": 30,
					},
				},
			},
			expectError: true,
			errorMsg:    "max_use",
		},
		{
			name: "invalid max_use - too high",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         1001, // Above maximum
						"expires_in_days": 30,
					},
				},
			},
			expectError: true,
			errorMsg:    "max_use",
		},
		{
			name: "invalid expires_in_days - too low",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         5,
						"expires_in_days": 0, // Below minimum
					},
				},
			},
			expectError: true,
			errorMsg:    "expires_in_days",
		},
		{
			name: "invalid expires_in_days - too high",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         5,
						"expires_in_days": 701, // Above maximum
					},
				},
			},
			expectError: true,
			errorMsg:    "expires_in_days",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &EaaClient{
				Logger: hclog.NewNullLogger(),
			}

			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"registration_tokens": {
					Type: schema.TypeList,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name": {
								Type: schema.TypeString,
							},
							"max_use": {
								Type: schema.TypeInt,
							},
							"expires_in_days": {
								Type: schema.TypeInt,
							},
							"generate_embedded_img": {
								Type: schema.TypeBool,
							},
						},
					},
				},
			}, tc.data)

			req := &CreateRegistrationTokenRequest{}
			ctx := context.Background()
			err := req.CreateRegistrationTokenRequestFromSchema(ctx, d, client)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, req.Name)
			}
		})
	}
}

// TestCreateRegistrationToken tests CreateRegistrationToken
func TestCreateRegistrationToken(t *testing.T) {
	testCases := []struct {
		name           string
		request        *CreateRegistrationTokenRequest
		createResponse string
		createStatus   int
		listResponse   RegistrationTokenResponse
		listStatus     int
		expectError    bool
	}{
		{
			name: "successful token creation",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				MaxUse:        5,
				ConnectorPool: "pool-uuid-123",
				ExpiresAt:     time.Now().AddDate(0, 0, 30).Format(time.RFC3339),
			},
			createResponse: "",
			createStatus:   http.StatusCreated,
			listResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{
					{
						UUIDURL:      "token-uuid-123",
						Name:         "test-token",
						MaxUse:       5,
						ConnectorPool: "pool-uuid-123",
					},
				},
			},
			listStatus:  http.StatusOK,
			expectError: false,
		},
		{
			name: "create fails",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusBadRequest,
			expectError:  true,
		},
		{
			name: "create fails - unauthorized",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusUnauthorized,
			expectError:  true,
		},
		{
			name: "create fails - forbidden",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusForbidden,
			expectError:  true,
		},
		{
			name: "create fails - not found",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusNotFound,
			expectError:  true,
		},
		{
			name: "create fails - server error",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusInternalServerError,
			expectError:  true,
		},
		{
			name: "fetchTokensFromList fails",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusCreated,
			listStatus:    http.StatusInternalServerError, // GET request fails
			expectError:   true,
		},
		{
			name: "parseAndFindToken fails - invalid JSON",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createResponse: "invalid json",
			createStatus:   http.StatusCreated,
			listStatus:     http.StatusOK,
			listResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{},
			},
			expectError: true,
		},
		{
			name: "parseAndFindToken fails - empty list",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusCreated,
			listStatus:   http.StatusOK,
			listResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{},
			},
			expectError: true,
		},
		{
			name: "parseAndFindToken fails - no exact match and no name match",
			request: &CreateRegistrationTokenRequest{
				Name:          "test-token",
				ConnectorPool: "pool-uuid-123",
			},
			createStatus: http.StatusCreated,
			listStatus:   http.StatusOK,
			listResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{
					{
						Name:          "other-token",
						ConnectorPool: "pool-uuid-123",
					},
				},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					w.WriteHeader(tc.createStatus)
					if tc.createResponse != "" {
						w.Write([]byte(tc.createResponse))
					}
				} else if r.Method == "GET" {
					w.WriteHeader(tc.listStatus)
					if tc.listStatus == http.StatusOK {
						json.NewEncoder(w).Encode(tc.listResponse)
					}
				}
			}))
			defer server.Close()

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:],
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			ctx := context.Background()
			result, err := tc.request.CreateRegistrationToken(ctx, client)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}

// TestGetRegistrationTokens tests GetRegistrationTokens
func TestGetRegistrationTokens(t *testing.T) {
	testCases := []struct {
		name           string
		connectorPool  string
		mockResponse   RegistrationTokenResponse
		mockStatusCode int
		expectError    bool
		expectedCount  int
	}{
		{
			name:          "successful tokens retrieval",
			connectorPool: "pool-uuid-123",
			mockResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{
					{UUIDURL: "token-1", Name: "token1"},
					{UUIDURL: "token-2", Name: "token2"},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  2,
		},
		{
			name:           "API returns error",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "API returns unauthorized",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name:           "API returns forbidden",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
		},
		{
			name:           "API returns not found",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
		},
		{
			name:           "API returns server error",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
		{
			name:          "empty tokens list",
			connectorPool: "pool-uuid-123",
			mockResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Contains(t, r.URL.RawQuery, tc.connectorPool)

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockStatusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tc.mockResponse)
				}
			}))
			defer server.Close()

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:],
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			result, err := client.GetRegistrationTokens(tc.connectorPool)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tc.expectedCount, len(result))
			}
		})
	}
}

// TestGetRegistrationTokenByUUID tests GetRegistrationTokenByUUID
func TestGetRegistrationTokenByUUID(t *testing.T) {
	testCases := []struct {
		name           string
		uuidURL        string
		connectorPool  string
		mockResponse   RegistrationTokenResponse
		mockStatusCode int
		expectError    bool
		expectedToken  *RegistrationToken
	}{
		{
			name:          "successful token retrieval by UUID",
			uuidURL:       "token-uuid-123",
			connectorPool: "pool-uuid-123",
			mockResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{
					{UUIDURL: "token-uuid-123", Name: "token1"},
					{UUIDURL: "token-uuid-456", Name: "token2"},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedToken:  &RegistrationToken{UUIDURL: "token-uuid-123", Name: "token1"},
		},
		{
			name:          "token not found",
			uuidURL:       "nonexistent-uuid",
			connectorPool: "pool-uuid-123",
			mockResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{
					{UUIDURL: "token-uuid-123", Name: "token1"},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
		{
			name:           "API returns error",
			uuidURL:        "token-uuid-123",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "API returns unauthorized",
			uuidURL:        "token-uuid-123",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name:           "API returns forbidden",
			uuidURL:        "token-uuid-123",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
		},
		{
			name:           "API returns server error",
			uuidURL:        "token-uuid-123",
			connectorPool:  "pool-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
		{
			name:          "empty tokens list",
			uuidURL:       "token-uuid-123",
			connectorPool: "pool-uuid-123",
			mockResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.mockStatusCode)
				if tc.mockStatusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tc.mockResponse)
				}
			}))
			defer server.Close()

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:],
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			result, err := client.GetRegistrationTokenByUUID(tc.uuidURL, tc.connectorPool)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tc.expectedToken.UUIDURL, result.UUIDURL)
				assert.Equal(t, tc.expectedToken.Name, result.Name)
			}
		})
	}
}

// TestDeleteRegistrationTokenByUUID tests DeleteRegistrationTokenByUUID
func TestDeleteRegistrationTokenByUUID(t *testing.T) {
	testCases := []struct {
		name           string
		tokenUUID      string
		mockStatusCode int
		expectError    bool
	}{
		{
			name:           "successful token deletion",
			tokenUUID:      "token-uuid-123",
			mockStatusCode: http.StatusNoContent,
			expectError:    false,
		},
		{
			name:           "successful deletion with OK status",
			tokenUUID:      "token-uuid-456",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "deletion fails",
			tokenUUID:      "token-uuid-789",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "token not found",
			tokenUUID:      "nonexistent-uuid",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
		},
		{
			name:           "deletion fails - unauthorized",
			tokenUUID:      "token-uuid-123",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name:           "deletion fails - forbidden",
			tokenUUID:      "token-uuid-123",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
		},
		{
			name:           "deletion fails - server error",
			tokenUUID:      "token-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "DELETE", r.Method)
				assert.Contains(t, r.URL.Path, tc.tokenUUID)

				w.WriteHeader(tc.mockStatusCode)
			}))
			defer server.Close()

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:],
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			ctx := context.Background()
			err := DeleteRegistrationTokenByUUID(ctx, client, tc.tokenUUID)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCreateRegistrationTokensFromSchema tests CreateRegistrationTokensFromSchema
func TestCreateRegistrationTokensFromSchema(t *testing.T) {
	testCases := []struct {
		name           string
		data           map[string]interface{}
		poolUUID       string
		createStatus   int
		listResponse   RegistrationTokenResponse
		listStatus     int
		expectError    bool
	}{
		{
			name:     "successful token creation from schema",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         5,
						"expires_in_days": 30,
						"generate_embedded_img": false,
					},
				},
			},
			createStatus: http.StatusCreated,
			listResponse: RegistrationTokenResponse{
				Objects: []RegistrationToken{
					{UUIDURL: "token-uuid-123", Name: "test-token"},
				},
			},
			listStatus:  http.StatusOK,
			expectError: false,
		},
		{
			name:     "no registration tokens",
			poolUUID: "pool-uuid-123",
			data:     map[string]interface{}{},
			expectError: false, // Should not error, just skip
		},
		{
			name:     "create fails",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         1,
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusBadRequest,
			expectError:  true,
		},
		{
			name:     "create fails - unauthorized",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         1,
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusUnauthorized,
			expectError:  true,
		},
		{
			name:     "create fails - forbidden",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         1,
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusForbidden,
			expectError:  true,
		},
		{
			name:     "create fails - not found",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         1,
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusNotFound,
			expectError:  true,
		},
		{
			name:     "create fails - server error",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         1,
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusInternalServerError,
			expectError:  true,
		},
		{
			name:     "invalid max_use - too low",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         0, // Below minimum
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusOK,
			expectError:  true,
		},
		{
			name:     "invalid max_use - too high",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         1001, // Above maximum
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusOK,
			expectError:  true,
		},
		{
			name:     "invalid expires_in_days - too low",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         5,
						"expires_in_days": 0, // Below minimum
					},
				},
			},
			createStatus: http.StatusOK,
			expectError:  true,
		},
		{
			name:     "invalid expires_in_days - too high",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"name":            "test-token",
						"max_use":         5,
						"expires_in_days": 701, // Above maximum
					},
				},
			},
			createStatus: http.StatusOK,
			expectError:  true,
		},
		{
			name:     "missing name field",
			poolUUID: "pool-uuid-123",
			data: map[string]interface{}{
				"registration_tokens": []interface{}{
					map[string]interface{}{
						"max_use":         5,
						"expires_in_days": 30,
					},
				},
			},
			createStatus: http.StatusOK,
			expectError:  true,
		},
	}

		for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					if tc.createStatus > 0 {
						w.WriteHeader(tc.createStatus)
					}
				} else if r.Method == "GET" {
					if tc.listStatus > 0 {
						w.WriteHeader(tc.listStatus)
						if tc.listStatus == http.StatusOK {
							json.NewEncoder(w).Encode(tc.listResponse)
						}
					}
				}
			}))
			defer server.Close()

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			client := &EaaClient{
				Host:   server.URL[8:],
				Client: httpClient,
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"registration_tokens": {
					Type: schema.TypeList,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name":                 {Type: schema.TypeString},
							"max_use":              {Type: schema.TypeInt},
							"expires_in_days":      {Type: schema.TypeInt},
							"generate_embedded_img": {Type: schema.TypeBool},
						},
					},
				},
			}, tc.data)

			ctx := context.Background()
			err := CreateRegistrationTokensFromSchema(ctx, d, client, tc.poolUUID)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestNormalizeExpiresAt tests normalizeExpiresAt
func TestNormalizeExpiresAt(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normalize milliseconds",
			input:    "2024-01-01T00:00:00.000Z",
			expected: "2024-01-01T00:00:00Z",
		},
		{
			name:     "no milliseconds",
			input:    "2024-01-01T00:00:00Z",
			expected: "2024-01-01T00:00:00Z",
		},
		{
			name:     "short string",
			input:    "short",
			expected: "short",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &CreateRegistrationTokenRequest{}
			result := req.normalizeExpiresAt(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestFindExactMatches tests findExactMatches
func TestFindExactMatches(t *testing.T) {
	req := &CreateRegistrationTokenRequest{
		Name:          "test-token",
		MaxUse:        5,
		ConnectorPool: "pool-uuid-123",
		ExpiresAt:     "2024-01-01T00:00:00Z",
	}

	tokens := []RegistrationToken{
		{
			Name:          "test-token",
			MaxUse:        5,
			ConnectorPool: "pool-uuid-123",
			ExpiresAt:     "2024-01-01T00:00:00Z",
		},
		{
			Name:          "other-token",
			MaxUse:        5,
			ConnectorPool: "pool-uuid-123",
			ExpiresAt:     "2024-01-01T00:00:00Z",
		},
		{
			Name:          "test-token",
			MaxUse:        10, // Different max_use
			ConnectorPool: "pool-uuid-123",
			ExpiresAt:     "2024-01-01T00:00:00Z",
		},
	}

	client := &EaaClient{Logger: hclog.NewNullLogger()}
	matches := req.findExactMatches(tokens, client)

	assert.Equal(t, 1, len(matches))
	assert.Equal(t, "test-token", matches[0].Name)
}

// TestFindTokenByName tests findTokenByName
func TestFindTokenByName(t *testing.T) {
	req := &CreateRegistrationTokenRequest{
		Name: "test-token",
	}

	tokens := []RegistrationToken{
		{Name: "other-token"},
		{Name: "test-token"},
		{Name: "another-token"},
	}

	client := &EaaClient{Logger: hclog.NewNullLogger()}
	result, err := req.findTokenByName(tokens, client)

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "test-token", result.Name)
}

// TestFindTokenByNameNotFound tests findTokenByName when token not found
func TestFindTokenByNameNotFound(t *testing.T) {
	req := &CreateRegistrationTokenRequest{
		Name: "nonexistent-token",
	}

	tokens := []RegistrationToken{
		{Name: "other-token"},
		{Name: "test-token"},
	}

	client := &EaaClient{Logger: hclog.NewNullLogger()}
	result, err := req.findTokenByName(tokens, client)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no registration token found with matching name")
}

