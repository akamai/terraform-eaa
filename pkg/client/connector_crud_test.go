package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

// MockSigner is defined in test_helpers.go

func TestUpdateConnector(t *testing.T) {
	testCases := []struct {
		name           string
		connector      *Connector
		setupMockData  func(d *schema.ResourceData)
		mockResponse   *Connector
		mockStatusCode int
		expectError    bool
		errorContains  string
	}{
		{
			name: "successful update connector",
			connector: &Connector{
				UUIDURL: "test-uuid-123",
				Name:    "old-name",
			},
			setupMockData: func(d *schema.ResourceData) {
				d.Set("name", "updated-connector")
				d.Set("package", "vmware")
				d.Set("description", "Updated description")
				d.Set("debug_channel_permitted", true)
			},
			mockResponse: &Connector{
				UUIDURL:               "test-uuid-123",
				Name:                  "updated-connector",
				Description:           stringPtrHelper("Updated description"),
				DebugChannelPermitted: true,
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "server error on update",
			connector: &Connector{
				UUIDURL: "test-uuid-error",
				Name:    "error-connector",
			},
			setupMockData: func(d *schema.ResourceData) {
				d.Set("name", "error-connector")
				d.Set("package", "docker")
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "connector update failed",
		},
		{
			name: "bad request on update",
			connector: &Connector{
				UUIDURL: "test-uuid-bad",
				Name:    "bad-connector",
			},
			setupMockData: func(d *schema.ResourceData) {
				d.Set("name", "bad-connector")
				d.Set("package", "docker")
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "connector update failed",
		},
		{
			name: "unauthorized on update",
			connector: &Connector{
				UUIDURL: "test-uuid-unauth",
				Name:    "unauth-connector",
			},
			setupMockData: func(d *schema.ResourceData) {
				d.Set("name", "unauth-connector")
				d.Set("package", "docker")
			},
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "connector update failed",
		},
		{
			name: "forbidden on update",
			connector: &Connector{
				UUIDURL: "test-uuid-forbidden",
				Name:    "forbidden-connector",
			},
			setupMockData: func(d *schema.ResourceData) {
				d.Set("name", "forbidden-connector")
				d.Set("package", "docker")
			},
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "connector update failed",
		},
		{
			name: "not found on update",
			connector: &Connector{
				UUIDURL: "test-uuid-notfound",
				Name:    "notfound-connector",
			},
			setupMockData: func(d *schema.ResourceData) {
				d.Set("name", "notfound-connector")
				d.Set("package", "docker")
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "connector update failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock HTTPS server (not HTTP)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/agents/"+tc.connector.UUIDURL)

				if tc.mockStatusCode == http.StatusOK {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(tc.mockResponse)
				} else {
					w.WriteHeader(tc.mockStatusCode)
					errorResp := map[string]interface{}{
						"error":  "Update failed",
						"detail": "Connector update failed",
					}
					json.NewEncoder(w).Encode(errorResp)
				}
			}))
			defer server.Close()

			// Create client with mock HTTPS server
			client := &EaaClient{
				Host:   getHostFromServerURL(server.URL),
				Client: server.Client(), // This client will ignore TLS errors
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			// Create resource data with schema
			resourceSchema := map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
				},
				"package": {
					Type:     schema.TypeString,
					Required: true,
				},
				"description": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"debug_channel_permitted": {
					Type:     schema.TypeBool,
					Optional: true,
				},
				"advanced_settings": {
					Type:     schema.TypeString,
					Optional: true,
				},
			}

			d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{})
			tc.setupMockData(d)

			// Call UpdateConnector
			result, err := tc.connector.UpdateConnector(context.Background(), d, client)

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
			}
		})
	}
}

func TestCreateConnector(t *testing.T) {
	testCases := []struct {
		name                   string
		createConnectorRequest *CreateConnectorRequest
		mockResponse           *Connector
		mockStatusCode         int
		expectError            bool
		errorContains          string
	}{
		{
			name: "successful create connector",
			createConnectorRequest: &CreateConnectorRequest{
				Name:                  "new-connector",
				Package:               1, // vmware package
				Description:           stringPtrHelper("Test connector"),
				DebugChannelPermitted: false,
			},
			mockResponse: &Connector{
				UUIDURL:               "new-uuid-123",
				Name:                  "new-connector",
				Description:           stringPtrHelper("Test connector"),
				Package:               1, // vmware package
				DebugChannelPermitted: false,
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "server error on create",
			createConnectorRequest: &CreateConnectorRequest{
				Name:    "error-connector",
				Package: 2, // docker package
			},
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "Connector creation failed",
		},
		{
			name: "bad request on create",
			createConnectorRequest: &CreateConnectorRequest{
				Name:    "bad-connector",
				Package: 2, // docker package
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "Connector creation failed",
		},
		{
			name: "unauthorized on create",
			createConnectorRequest: &CreateConnectorRequest{
				Name:    "unauth-connector",
				Package: 2, // docker package
			},
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "Connector creation failed",
		},
		{
			name: "forbidden on create",
			createConnectorRequest: &CreateConnectorRequest{
				Name:    "forbidden-connector",
				Package: 2, // docker package
			},
			mockStatusCode: http.StatusForbidden,
			expectError:    true,
			errorContains:  "Connector creation failed",
		},
		{
			name: "not found on create",
			createConnectorRequest: &CreateConnectorRequest{
				Name:    "notfound-connector",
				Package: 2, // docker package
			},
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "Connector creation failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock HTTPS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Contains(t, r.URL.Path, "/crux/v1/mgmt-pop/agents")

				if tc.mockStatusCode == http.StatusOK {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(tc.mockResponse)
				} else {
					w.WriteHeader(tc.mockStatusCode)
					errorResp := map[string]interface{}{
						"error":  "Create failed",
						"detail": "Connector creation failed",
					}
					json.NewEncoder(w).Encode(errorResp)
				}
			}))
			defer server.Close()

			// Create client with mock HTTPS server
			client := &EaaClient{
				Host:   getHostFromServerURL(server.URL),
				Client: server.Client(), // This client will ignore TLS errors
				Signer: &MockSigner{},
				Logger: hclog.NewNullLogger(),
			}

			// Call CreateConnector
			result, err := tc.createConnectorRequest.CreateConnector(context.Background(), client)

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
				assert.Equal(t, tc.mockResponse.Package, result.Package)
				assert.Equal(t, tc.mockResponse.Description, result.Description)
				assert.Equal(t, tc.mockResponse.DebugChannelPermitted, result.DebugChannelPermitted)
			}
		})
	}
}
