package client

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

// TestGetPops tests the GetPops function
func TestGetPops(t *testing.T) {
	testCases := []struct {
		name           string
		mockResponse   PopResponse
		mockStatusCode int
		expectError    bool
		expectedError  error
		expectedCount  int
	}{
		{
			name: "successful pops retrieval",
			mockResponse: PopResponse{
				Pops: []Pop{
					{
						Region:  "us-east-1",
						Name:    "US East",
						UUIDURL: "pop-uuid-1",
					},
					{
						Region:  "us-west-1",
						Name:    "US West",
						UUIDURL: "pop-uuid-2",
					},
					{
						Region:  "eu-west-1",
						Name:    "EU West",
						UUIDURL: "pop-uuid-3",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  3,
		},
		{
			name: "pops with missing fields filtered out",
			mockResponse: PopResponse{
				Pops: []Pop{
					{
						Region:  "us-east-1",
						Name:    "US East",
						UUIDURL: "pop-uuid-1",
					},
					{
						Region:  "", // Missing region - should be filtered
						Name:    "Invalid",
						UUIDURL: "pop-uuid-2",
					},
					{
						Region:  "us-west-1",
						Name:    "", // Missing name - should be filtered
						UUIDURL: "pop-uuid-3",
					},
					{
						Region:  "eu-west-1",
						Name:    "EU West",
						UUIDURL: "", // Missing UUID - should be filtered
					},
					{
						Region:  "ap-south-1",
						Name:    "AP South",
						UUIDURL: "pop-uuid-4",
					},
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  2, // Only 2 valid pops
		},
		{
			name:           "API returns error",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "API returns not found",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "API returns unauthorized",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "API returns forbidden",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "API returns server error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "empty pops list",
			mockResponse:   PopResponse{Pops: []Pop{}},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedCount:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/pops")
				assert.Contains(t, r.URL.RawQuery, "shared=true")

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockStatusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tc.mockResponse)
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
			result, err := GetPops(client)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != nil {
					assert.ErrorIs(t, err, tc.expectedError)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				// result can be nil or empty slice, both are valid
				if result == nil {
					result = []Pop{} // Normalize nil to empty slice
				}
				assert.Equal(t, tc.expectedCount, len(result))
			}
		})
	}
}

// TestGetPopUuid tests the GetPopUuid function
func TestGetPopUuid(t *testing.T) {
	testCases := []struct {
		name           string
		popRegion      string
		mockPops       []Pop
		mockStatusCode int
		expectError    bool
		expectedError  error
		expectedName   string
		expectedUUID   string
	}{
		{
			name:      "successful pop UUID retrieval",
			popRegion: "us-east-1",
			mockPops: []Pop{
				{
					Region:  "us-east-1",
					Name:    "US East",
					UUIDURL: "pop-uuid-1",
				},
				{
					Region:  "us-west-1",
					Name:    "US West",
					UUIDURL: "pop-uuid-2",
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedName:   "US East",
			expectedUUID:   "pop-uuid-1",
		},
		{
			name:      "pop region not found",
			popRegion: "nonexistent-region",
			mockPops: []Pop{
				{
					Region:  "us-east-1",
					Name:    "US East",
					UUIDURL: "pop-uuid-1",
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "GetPops fails",
			popRegion:      "us-east-1",
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:      "case sensitive region matching",
			popRegion:  "US-EAST-1", // Different case
			mockPops: []Pop{
				{
					Region:  "us-east-1", // Lowercase
					Name:    "US East",
					UUIDURL: "pop-uuid-1",
				},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true, // Should not match due to case difference
			expectedError:  ErrPopsGet,
		},
		{
			name:           "empty pops list",
			popRegion:      "us-east-1",
			mockPops:       []Pop{},
			mockStatusCode: http.StatusOK,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "GetPops returns unauthorized",
			popRegion:      "us-east-1",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "GetPops returns forbidden",
			popRegion:      "us-east-1",
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
		{
			name:           "GetPops returns server error",
			popRegion:      "us-east-1",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedError:  ErrPopsGet,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock TLS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/pops")

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockStatusCode == http.StatusOK {
					mockResponse := PopResponse{
						Pops: tc.mockPops,
					}
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
			name, uuid, err := GetPopUuid(client, tc.popRegion)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				if tc.expectedError != nil {
					assert.ErrorIs(t, err, tc.expectedError)
				}
				assert.Empty(t, name)
				assert.Empty(t, uuid)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedName, name)
				assert.Equal(t, tc.expectedUUID, uuid)
			}
		})
	}
}

