package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTLSCipherSuites(t *testing.T) {
	testCases := []struct {
		name           string
		appUUIDURL     string
		mockResponse   *TLSCipherSuitesResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
	}{
		{
			name:       "successful get TLS cipher suites",
			appUUIDURL: "app-uuid-123",
			mockResponse: &TLSCipherSuitesResponse{
				TLSSuiteName: "Custom",
				TLSCipherSuite: map[string]TLSCipherSuite{
					"TLS_AES_256_GCM_SHA384": {
						Default:      true,
						Selected:     true,
						SSLCipher:    "TLS_AES_256_GCM_SHA384",
						SSLProtocols: "TLSv1.3",
						WeakCipher:   false,
					},
					"TLS_CHACHA20_POLY1305_SHA256": {
						Default:      false,
						Selected:     true,
						SSLCipher:    "TLS_CHACHA20_POLY1305_SHA256",
						SSLProtocols: "TLSv1.3",
						WeakCipher:   false,
					},
					"TLS_AES_128_GCM_SHA256": {
						Default:      false,
						Selected:     false,
						SSLCipher:    "TLS_AES_128_GCM_SHA256",
						SSLProtocols: "TLSv1.3",
						WeakCipher:   false,
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:       "empty TLS cipher suites response",
			appUUIDURL: "app-uuid-456",
			mockResponse: &TLSCipherSuitesResponse{
				TLSSuiteName:   "Default",
				TLSCipherSuite: map[string]TLSCipherSuite{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:       "TLS suite with weak ciphers",
			appUUIDURL: "app-uuid-789",
			mockResponse: &TLSCipherSuitesResponse{
				TLSSuiteName: "Legacy",
				TLSCipherSuite: map[string]TLSCipherSuite{
					"TLS_RSA_WITH_RC4_128_SHA": {
						Default:      false,
						Selected:     true,
						SSLCipher:    "TLS_RSA_WITH_RC4_128_SHA",
						SSLProtocols: "TLSv1.0",
						WeakCipher:   true,
					},
					"TLS_RSA_WITH_AES_256_CBC_SHA": {
						Default:      true,
						Selected:     true,
						SSLCipher:    "TLS_RSA_WITH_AES_256_CBC_SHA",
						SSLProtocols: "TLSv1.2",
						WeakCipher:   false,
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "server error 500",
			appUUIDURL:     "app-uuid-error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "TLS cipher suites get failed",
		},
		{
			name:           "not found error 404",
			appUUIDURL:     "app-uuid-notfound",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "TLS cipher suites get failed",
		},
		{
			name:           "unauthorized error 401",
			appUUIDURL:     "app-uuid-unauth",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "TLS cipher suites get failed",
		},
		{
			name:           "empty app UUID",
			appUUIDURL:     "",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "TLS cipher suites get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := fmt.Sprintf("/crux/v1/mgmt-pop/apps/%s", tc.appUUIDURL)
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)

				if tc.mockResponse != nil {
					jsonResp, err := json.Marshal(tc.mockResponse)
					require.NoError(t, err)
					w.Write(jsonResp)
				} else if tc.expectError && tc.mockStatusCode >= http.StatusBadRequest {
					// Send ErrorResponse for error cases
					errorResp := ErrorResponse{
						Title:  "Error",
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
			result, err := GetTLSCipherSuites(client, tc.appUUIDURL)

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
				assert.Equal(t, tc.mockResponse.TLSSuiteName, result.TLSSuiteName)
				assert.Equal(t, len(tc.mockResponse.TLSCipherSuite), len(result.TLSCipherSuite))

				// Verify cipher suite details
				for cipherName, expectedCipher := range tc.mockResponse.TLSCipherSuite {
					actualCipher, exists := result.TLSCipherSuite[cipherName]
					assert.True(t, exists, "Expected cipher suite %s to exist", cipherName)
					assert.Equal(t, expectedCipher.Default, actualCipher.Default)
					assert.Equal(t, expectedCipher.Selected, actualCipher.Selected)
					assert.Equal(t, expectedCipher.SSLCipher, actualCipher.SSLCipher)
					assert.Equal(t, expectedCipher.SSLProtocols, actualCipher.SSLProtocols)
					assert.Equal(t, expectedCipher.WeakCipher, actualCipher.WeakCipher)
				}
			}
		})
	}
}

func TestGetTLSCipherSuites_EdgeCases(t *testing.T) {
	testCases := []struct {
		name           string
		appUUIDURL     string
		mockResponse   interface{} // Can be malformed JSON
		mockStatusCode int
		expectError    bool
		errorContains  string
	}{
		{
			name:           "malformed JSON response",
			appUUIDURL:     "app-uuid-123",
			mockResponse:   `{"invalid": json}`, // Invalid JSON
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
		{
			name:       "nil cipher suites map",
			appUUIDURL: "app-uuid-nil",
			mockResponse: &TLSCipherSuitesResponse{
				TLSSuiteName:   "Empty",
				TLSCipherSuite: nil,
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:       "special characters in app UUID",
			appUUIDURL: "app-uuid-with-special@chars",
			mockResponse: &TLSCipherSuitesResponse{
				TLSSuiteName:   "Test",
				TLSCipherSuite: map[string]TLSCipherSuite{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := fmt.Sprintf("/crux/v1/mgmt-pop/apps/%s", tc.appUUIDURL)
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tc.mockStatusCode)

				if tc.mockResponse != nil {
					if str, ok := tc.mockResponse.(string); ok {
						// Write malformed JSON directly
						w.Write([]byte(str))
					} else {
						// Marshal valid response
						jsonResp, err := json.Marshal(tc.mockResponse)
						require.NoError(t, err)
						w.Write(jsonResp)
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
				Client:           server.Client(),
				Signer:           &MockSigner{},
				Host:             serverURL.Host,
				Logger:           hclog.NewNullLogger(),
			}

			// Call function under test
			result, err := GetTLSCipherSuites(client, tc.appUUIDURL)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}
