package client

import (
	"context"
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

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}

func TestGetCertificates(t *testing.T) {
	testCases := []struct {
		name           string
		mockResponse   *CertsResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedCount  int
	}{
		{
			name: "successful get certificates",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "test-cert-1.example.com",
						UUIDURL:   "cert-uuid-1",
						CertType:  CERT_TYPE_APP,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
					{
						Name:      "test}2.example.com",
						UUIDURL:   "cert-uuid-2",
						CertType:  CERT_TYPE_APP_SSC,
						ExpiredAt: "2025-06-30T23:59:59Z",
						CreatedAt: "2024-06-01T00:00:00Z",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  2,
		},
		{
			name: "empty certificates list",
			mockResponse: &CertsResponse{
				Objects: []CertObject{},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
		{
			name: "filter invalid certificates (missing name)",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "",
						UUIDURL:   "cert-uuid-1",
						CertType:  CERT_TYPE_APP,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
					{
						Name:      "valid-cert.example.com",
						UUIDURL:   "cert-uuid-2",
						CertType:  CERT_TYPE_APP,
						ExpiredAt: "2025-06-30T23:59:59Z",
						CreatedAt: "2024-06-01T00:00:00Z",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  1,
		},
		{
			name: "filter invalid certificates (missing UUID)",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "test-cert.example.com",
						UUIDURL:   "",
						CertType:  CERT_TYPE_APP,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
					{
						Name:      "valid-cert.example.com",
						UUIDURL:   "cert-uuid-2",
						CertType:  CERT_TYPE_APP,
						ExpiredAt: "2025-06-30T23:59:59Z",
						CreatedAt: "2024-06-01T00:00:00Z",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  1,
		},
		{
			name:           "server error 500",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "unauthorized error 401",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "not found error 404",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "forbidden error 403",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "bad request error 400",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/certificates/thin", r.URL.Path)

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
				Client:           server.Client(),
				Signer:           &MockSigner{},
				Host:             serverURL.Host,
				Logger:           hclog.NewNullLogger(),
			}

			// Call function under test
			result, err := GetCertificates(client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, tc.expectedCount)

				// Verify all returned certificates have valid name and UUID
				for _, cert := range result {
					assert.NotEmpty(t, cert.Name)
					assert.NotEmpty(t, cert.UUIDURL)
				}
			}
		})
	}
}

func TestDoesSelfSignedCertExistForHost(t *testing.T) {
	testCases := []struct {
		name         string
		hostName     string
		mockResponse *CertsResponse
		expectFound  bool
		expectedUUID string
		expectError  bool
		errorMsg     string
	}{
		{
			name:     "self-signed certificate found",
			hostName: "test-host.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "test-host.example.com",
						UUIDURL:   "cert-uuid-ssc",
						CertType:  CERT_TYPE_APP_SSC,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
					{
						Name:      "other-host.example.com",
						UUIDURL:   "cert-uuid-other",
						CertType:  CERT_TYPE_APP,
						ExpiredAt: "2025-06-30T23:59:59Z",
						CreatedAt: "2024-06-01T00:00:00Z",
					},
				},
			},
			expectFound:  true,
			expectedUUID: "cert-uuid-ssc",
			expectError:  false,
		},
		{
			name:     "certificate with same name but not self-signed",
			hostName: "test-host.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "test-host.example.com",
						UUIDURL:   "cert-uuid-regular",
						CertType:  CERT_TYPE_APP, // Not self-signed
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound: false,
			expectError: false,
		},
		{
			name:     "certificate not found",
			hostName: "non-existent.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "other-host.example.com",
						UUIDURL:   "cert-uuid-other",
						CertType:  CERT_TYPE_APP_SSC,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound: false,
			expectError: false,
		},
		{
			name:     "multiple certs with same name - returns first self-signed",
			hostName: "test.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "test.example.com",
						UUIDURL:   "cert-uuid-ssc-1",
						CertType:  CERT_TYPE_APP_SSC,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
					{
						Name:      "test.example.com",
						UUIDURL:   "cert-uuid-ssc-2",
						CertType:  CERT_TYPE_APP_SSC,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound:  true,
			expectedUUID: "cert-uuid-ssc-1", // Returns first match
			expectError:  false,
		},
		{
			name:     "empty certificates list",
			hostName: "any-host.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{},
			},
			expectFound: false,
			expectError: false,
		},
		{
			name:        "GetCertificates error",
			hostName:    "test-host.example.com",
			expectError: true,
			errorMsg:    "certificates get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/certificates/thin", r.URL.Path)

				if tc.expectError && tc.mockResponse == nil {
					w.WriteHeader(http.StatusInternalServerError)
					errorResp := ErrorResponse{
						Title:  "Error",
						Detail: tc.errorMsg,
					}
					json.NewEncoder(w).Encode(errorResp)
					return
				}

				w.WriteHeader(http.StatusOK)
				if tc.mockResponse != nil {
					jsonResp, err := json.Marshal(tc.mockResponse)
					require.NoError(t, err)
					w.Write(jsonResp)
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
			result, err := DoesSelfSignedCertExistForHost(client, tc.hostName)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if tc.expectFound {
					assert.NotNil(t, result)
					assert.Equal(t, tc.hostName, result.Name)
					assert.Equal(t, tc.expectedUUID, result.UUIDURL)
					assert.Equal(t, CERT_TYPE_APP_SSC, result.CertType)
				} else {
					assert.Nil(t, result)
				}
			}
		})
	}
}

func TestGetCertificate(t *testing.T) {
	testCases := []struct {
		name           string
		certUUID       string
		mockResponse   *CertificateResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
	}{
		{
			name:     "successful get certificate",
			certUUID: "cert-uuid-123",
			mockResponse: &CertificateResponse{
				AppCount:    2,
				Cert:        "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
				CertType:    CERT_TYPE_APP,
				CN:          "test.example.com",
				CreatedAt:   "2024-01-01T00:00:00Z",
				DaysLeft:    365,
				Description: stringPtr("Test certificate"),
				DirCount:    1,
				ExpiredAt:   "2025-01-01T00:00:00Z",
				HostName:    "test.example.com",
				IssuedAt:    "2024-01-01T00:00:00Z",
				Issuer:      "Test CA",
				ModifiedAt:  "2024-01-01T00:00:00Z",
				Name:        "test.example.com",
				Resource:    "/certificates/cert-uuid-123",
				Status:      1,
				Subject:     "CN=test.example.com",
				UUIDURL:     "cert-uuid-123",
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:     "self-signed certificate",
			certUUID: "cert-uuid-ssc",
			mockResponse: &CertificateResponse{
				AppCount:   1,
				Cert:       "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
				CertType:   CERT_TYPE_APP_SSC,
				CN:         "self-signed.example.com",
				CreatedAt:  "2024-06-01T00:00:00Z",
				DaysLeft:   180,
				DirCount:   0,
				ExpiredAt:  "2024-12-01T00:00:00Z",
				HostName:   "self-signed.example.com",
				IssuedAt:   "2024-06-01T00:00:00Z",
				Issuer:     "self-signed.example.com",
				ModifiedAt: "2024-06-01T00:00:00Z",
				Name:       "self-signed.example.com",
				Resource:   "/certificates/cert-uuid-ssc",
				Status:     1,
				Subject:    "CN=self-signed.example.com",
				UUIDURL:    "cert-uuid-ssc",
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "certificate not found",
			certUUID:       "non-existent-uuid",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "server error 500",
			certUUID:       "cert-uuid-error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "unauthorized error 401",
			certUUID:       "cert-uuid-unauth",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "empty certificate UUID",
			certUUID:       "",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
		{
			name:           "forbidden error 403",
			certUUID:       "cert-uuid-forbidden",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "certificates get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				expectedPath := fmt.Sprintf("/crux/v1/mgmt-pop/certificates/%s", tc.certUUID)
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
				Client:           server.Client(),
				Signer:           &MockSigner{},
				Host:             serverURL.Host,
				Logger:           hclog.NewNullLogger(),
			}

			// Call function under test
			result, err := GetCertificate(client, tc.certUUID)

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
				assert.Equal(t, tc.mockResponse.Name, result.Name)
				assert.Equal(t, tc.mockResponse.UUIDURL, result.UUIDURL)
				assert.Equal(t, tc.mockResponse.CertType, result.CertType)
				assert.Equal(t, tc.mockResponse.CN, result.CN)
				assert.Equal(t, tc.mockResponse.HostName, result.HostName)
				assert.Equal(t, tc.mockResponse.Issuer, result.Issuer)
				assert.Equal(t, tc.mockResponse.Subject, result.Subject)
			}
		})
	}
}

func TestDoesUploadedCertExist(t *testing.T) {
	testCases := []struct {
		name         string
		hostName     string
		mockResponse *CertsResponse
		expectFound  bool
		expectedUUID string
		expectError  bool
		errorMsg     string
	}{
		{
			name:     "uploaded certificate found",
			hostName: "uploaded-cert.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "uploaded-cert.example.com",
						UUIDURL:   "cert-uuid-uploaded",
						CertType:  CERT_TYPE_APP, // Not self-signed, not CA
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound:  true,
			expectedUUID: "cert-uuid-uploaded",
			expectError:  false,
		},
		{
			name:     "self-signed certificate ignored",
			hostName: "self-signed.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "self-signed.example.com",
						UUIDURL:   "cert-uuid-ssc",
						CertType:  CERT_TYPE_APP_SSC, // Self-signed - should be ignored
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound: false,
			expectError: true,
			errorMsg:    "certificate does not exist",
		},
		{
			name:     "CA certificate ignored",
			hostName: "ca-cert.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "ca-cert.example.com",
						UUIDURL:   "cert-uuid-ca",
						CertType:  CERT_TYPE_CA, // CA cert - should be ignored
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound: false,
			expectError: true,
			errorMsg:    "certificate does not exist",
		},
		{
			name:     "certificate not found",
			hostName: "non-existent.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "other-cert.example.com",
						UUIDURL:   "cert-uuid-other",
						CertType:  CERT_TYPE_APP,
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound: false,
			expectError: true,
			errorMsg:    "certificate does not exist",
		},
		{
			name:     "multiple certs with same name - returns uploaded cert",
			hostName: "test.example.com",
			mockResponse: &CertsResponse{
				Objects: []CertObject{
					{
						Name:      "test.example.com",
						UUIDURL:   "cert-uuid-ssc",
						CertType:  CERT_TYPE_APP_SSC, // Self-signed - should be ignored
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
					{
						Name:      "test.example.com",
						UUIDURL:   "cert-uuid-uploaded",
						CertType:  CERT_TYPE_APP, // Uploaded - should be returned
						ExpiredAt: "2025-12-31T23:59:59Z",
						CreatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
			expectFound:  true,
			expectedUUID: "cert-uuid-uploaded",
			expectError:  false,
		},
		{
			name:        "GetCertificates error",
			hostName:    "test-host.example.com",
			expectError: true,
			errorMsg:    "certificates get failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/crux/v1/mgmt-pop/certificates/thin", r.URL.Path)

				if tc.expectError && tc.mockResponse == nil {
					w.WriteHeader(http.StatusInternalServerError)
					errorResp := ErrorResponse{
						Title:  "Error",
						Detail: "certificates get failed",
					}
					json.NewEncoder(w).Encode(errorResp)
					return
				}

				w.WriteHeader(http.StatusOK)
				if tc.mockResponse != nil {
					jsonResp, err := json.Marshal(tc.mockResponse)
					require.NoError(t, err)
					w.Write(jsonResp)
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
			result, err := DoesUploadedCertExist(client, tc.hostName)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
				if !tc.expectFound {
					assert.Nil(t, result)
				}
			} else {
				assert.NoError(t, err)
				if tc.expectFound {
					assert.NotNil(t, result)
					assert.Equal(t, tc.hostName, result.Name)
					assert.Equal(t, tc.expectedUUID, result.UUIDURL)
					assert.NotEqual(t, CERT_TYPE_APP_SSC, result.CertType)
					assert.NotEqual(t, CERT_TYPE_CA, result.CertType)
				} else {
					assert.Nil(t, result)
				}
			}
		})
	}
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	testCases := []struct {
		name           string
		request        *CreateSelfSignedCertRequest
		mockResponse   *CertificateResponse
		mockStatusCode int
		expectError    bool
		errorContains  string
	}{
		{
			name: "successful certificate creation",
			request: &CreateSelfSignedCertRequest{
				HostName: "test.example.com",
			},
			mockResponse: &CertificateResponse{
				Name:      "test.example.com",
				UUIDURL:   "cert-uuid-new",
				CertType:  CERT_TYPE_APP_SSC,
				CN:        "test.example.com",
				HostName:  "test.example.com",
				CreatedAt: "2024-11-04T00:00:00Z",
				DaysLeft:  365,
				Status:    1,
			},
			mockStatusCode: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "invalid hostname - empty",
			request: &CreateSelfSignedCertRequest{
				HostName: "",
			},
			expectError:   true,
			errorContains: "value must be of the specified type",
		},
		{
			name: "server error during creation",
			request: &CreateSelfSignedCertRequest{
				HostName: "test.example.com",
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "app update failed",
		},
		{
			name: "bad request",
			request: &CreateSelfSignedCertRequest{
				HostName: "invalid hostname with spaces",
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "app update failed",
		},
		{
			name: "unauthorized error 401",
			request: &CreateSelfSignedCertRequest{
				HostName: "test.example.com",
			},
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "app update failed",
		},
		{
			name: "forbidden error 403",
			request: &CreateSelfSignedCertRequest{
				HostName: "test.example.com",
			},
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "app update failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server

			// Only create server if we expect to make HTTP requests
			if tc.request.HostName != "" {
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "POST", r.Method)
					assert.Equal(t, "/crux/v1/mgmt-pop/certificates", r.URL.Path)

					// Verify request body
					var requestBody CreateSelfSignedCertRequest
					err := json.NewDecoder(r.Body).Decode(&requestBody)
					require.NoError(t, err)
					assert.Equal(t, tc.request.HostName, requestBody.HostName)
					assert.Equal(t, CERT_TYPE_APP_SSC, requestBody.CertType)

					w.WriteHeader(tc.mockStatusCode)

					if tc.mockResponse != nil {
						jsonResp, err := json.Marshal(tc.mockResponse)
						require.NoError(t, err)
						w.Write(jsonResp)
					} else if tc.expectError && tc.mockStatusCode >= http.StatusBadRequest {
						// Send ErrorResponse for error cases
						errorResp := ErrorResponse{
							Title:  "Error",
							Detail: "app update failed",
						}
						json.NewEncoder(w).Encode(errorResp)
					}
				}))
				defer server.Close()
			}

			// Create test client
			var client *EaaClient
			if server != nil {
				serverURL, _ := url.Parse(server.URL)
				client = &EaaClient{
					ContractID:       "G-12345",
					AccountSwitchKey: "",
					Client:           server.Client(),
					Signer:           &MockSigner{},
					Host:             serverURL.Host,
					Logger:           hclog.NewNullLogger(),
				}
			} else {
				client = &EaaClient{
					ContractID:       "G-12345",
					AccountSwitchKey: "",
					Client:           &http.Client{},
					Signer:           &MockSigner{},
					Host:             "test-host",
					Logger:           hclog.NewNullLogger(),
				}
			}

			// Call function under test
			ctx := context.Background()
			result, err := tc.request.CreateSelfSignedCertificate(ctx, client)

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
				assert.Equal(t, tc.mockResponse.Name, result.Name)
				assert.Equal(t, tc.mockResponse.UUIDURL, result.UUIDURL)
				assert.Equal(t, CERT_TYPE_APP_SSC, result.CertType)
				assert.Equal(t, tc.mockResponse.HostName, result.HostName)
			}
		})
	}
}
