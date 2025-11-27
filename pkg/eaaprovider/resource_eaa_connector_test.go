package eaaprovider

import (
	"context"
	"fmt"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/testmocks"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createTestConnectorResourceData(data map[string]interface{}) *schema.ResourceData {
	resource := resourceEaaConnector()
	d := resource.Data(nil)
	for key, value := range data {
		d.Set(key, value)
	}
	return d
}

func TestConnectorCreate(t *testing.T) {
	ctx := context.Background()
	connectorID := "test-connector-uuid-123"

	tests := map[string]struct {
		resourceData   map[string]interface{}
		expectedError  bool
		setupMock      func(*testmocks.MockConnector)
	}{
		"successful_creation_with_minimal_data": {
			resourceData: map[string]interface{}{
				"name":    "test-connector",
				"package": "vmware",
			},
			expectedError: false,
			setupMock: func(m *testmocks.MockConnector) {
				m.WithData(testmocks.MockConnectorData{
					ConnectorID: connectorID,
					Name:        "test-connector",
					Status:      "active",
				}).MockCreateConnector().MockGetConnector()
			},
		},
		"successful_creation_with_all_fields": {
			resourceData: map[string]interface{}{
				"name":                  "test-connector-complete",
				"package":               "aws",
				"description":            "Test connector description",
				"debug_channel_permitted": true,
				"advanced_settings": []map[string]interface{}{
					{
						"network_info": []string{"192.168.1.0/24"},
					},
				},
			},
			expectedError: false,
			setupMock: func(m *testmocks.MockConnector) {
				m.WithData(testmocks.MockConnectorData{
					ConnectorID: connectorID,
					Name:        "test-connector-complete",
					Status:      "active",
				}).MockCreateConnector().MockGetConnector()
			},
		},
		"creation_with_missing_name": {
			resourceData: map[string]interface{}{
				"package": "vmware",
			},
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// No mock needed, validation should fail before API call
			},
		},
		"creation_with_missing_package": {
			resourceData: map[string]interface{}{
				"name": "test-connector",
			},
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// No mock needed, validation should fail before API call
			},
		},
		"creation_with_invalid_package": {
			resourceData: map[string]interface{}{
				"name":    "test-connector",
				"package": "invalid-package",
			},
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// No mock needed, validation should fail before API call
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			mockConnector := testmocks.NewMockConnector(mockClient, mockTransport)
			if tt.setupMock != nil {
				tt.setupMock(mockConnector)
			}

			// Create test resource data
			d := createTestConnectorResourceData(tt.resourceData)

			// Execute create
			diags := resourceEaaConnectorCreate(ctx, d, mockClient)

			// Check for errors
			if tt.expectedError {
				if len(diags) == 0 || !hasError(diags) {
					t.Errorf("Expected error but got none")
				}
			} else {
				if hasError(diags) {
					t.Errorf("Unexpected error: %v", diags)
				}
				// Verify resource ID is set
				if d.Id() == "" {
					t.Errorf("Expected resource ID to be set")
				}
				// Verify mock was called
				if mockConnector.GetCallCount("create") == 0 {
					t.Errorf("Expected create to be called")
				}
			}
		})
	}
}

func TestConnectorRead(t *testing.T) {
	ctx := context.Background()
	connectorID := "test-connector-uuid-123"

	tests := map[string]struct {
		connectorID    string
		expectedError  bool
		setupMock      func(*testmocks.MockConnector)
	}{
		"successful_read": {
			connectorID:   connectorID,
			expectedError: false,
			setupMock: func(m *testmocks.MockConnector) {
				m.WithData(testmocks.MockConnectorData{
					ConnectorID: connectorID,
					Name:        "test-connector",
					Status:      "active",
				}).MockGetConnector()
			},
		},
		"read_with_non_existent_id": {
			connectorID:   "non-existent-id",
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// Mock 404 response
				readURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents/%s", "non-existent-id")
				readURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", "non-existent-id")
				m.Transport().Responses[readURL] = testmocks.MockResponse{
					StatusCode: 404,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Not Found",
						"detail": "Connector not found",
					},
				}
				m.Transport().Responses[readURL2] = testmocks.MockResponse{
					StatusCode: 404,
					Body: map[string]interface{}{
						"type":    "error",
						"title":   "Not Found",
						"detail":  "Connector not found",
					},
				}
			},
		},
		"read_with_api_error": {
			connectorID:   connectorID,
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// Mock 500 response
				readURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents/%s", connectorID)
				readURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", connectorID)
				m.Transport().Responses[readURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Server error",
					},
				}
				m.Transport().Responses[readURL2] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":    "error",
						"title":   "Internal Server Error",
						"detail":  "Server error",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			mockConnector := testmocks.NewMockConnector(mockClient, mockTransport)
			if tt.setupMock != nil {
				tt.setupMock(mockConnector)
			}

			// Create test resource data with ID
			d := createTestConnectorResourceData(map[string]interface{}{})
			d.SetId(tt.connectorID)

			// Execute read
			diags := resourceEaaConnectorRead(ctx, d, mockClient)

			// Check for errors
			if tt.expectedError {
				if len(diags) == 0 || !hasError(diags) {
					t.Errorf("Expected error but got none")
				}
			} else {
				if hasError(diags) {
					t.Errorf("Unexpected error: %v", diags)
				}
				// Verify attributes are set
				if d.Get("name") == "" {
					t.Errorf("Expected name to be set")
				}
				// Verify mock was called
				if mockConnector.GetCallCount("get") == 0 {
					t.Errorf("Expected get to be called")
				}
			}
		})
	}
}

func TestConnectorUpdate(t *testing.T) {
	ctx := context.Background()
	connectorID := "test-connector-uuid-123"

	tests := map[string]struct {
		resourceData   map[string]interface{}
		expectedError  bool
		setupMock      func(*testmocks.MockConnector)
	}{
		"successful_update_with_state_change": {
			resourceData: map[string]interface{}{
				"name":    "test-connector-updated",
				"package": "vmware", // Required field
				"state":   "approved",
			},
			expectedError: false,
			setupMock: func(m *testmocks.MockConnector) {
				m.WithData(testmocks.MockConnectorData{
					ConnectorID: connectorID,
					Name:        "test-connector-updated",
					Status:      "active",
				}).MockGetConnector().MockUpdateConnector()
				// Mock approve endpoint
				approveURL1 := fmt.Sprintf("POST /crux/v1/mgmt-pop/agents/%s/approve", connectorID)
				approveURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s/approve", connectorID)
				m.Transport().Responses[approveURL1] = testmocks.MockResponse{
					StatusCode: 200,
					Body:       map[string]interface{}{"status": "approved"},
				}
				m.Transport().Responses[approveURL2] = testmocks.MockResponse{
					StatusCode: 200,
					Body:       map[string]interface{}{"status": "approved"},
				}
			},
		},
		"successful_update_without_state_change": {
			resourceData: map[string]interface{}{
				"name":        "test-connector-updated",
				"package":     "vmware", // Required field
				"description": "Updated description",
			},
			expectedError: false,
			setupMock: func(m *testmocks.MockConnector) {
				m.WithData(testmocks.MockConnectorData{
					ConnectorID: connectorID,
					Name:        "test-connector-updated",
					Status:      "active",
				}).MockGetConnector().MockUpdateConnector()
			},
		},
		"update_with_api_error": {
			resourceData: map[string]interface{}{
				"name": "test-connector-updated",
			},
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// Mock 500 response for GET
				readURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents/%s", connectorID)
				readURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", connectorID)
				m.Transport().Responses[readURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Server error",
					},
				}
				m.Transport().Responses[readURL2] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Server error",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			mockConnector := testmocks.NewMockConnector(mockClient, mockTransport)
			if tt.setupMock != nil {
				tt.setupMock(mockConnector)
			}

			// Create test resource data with ID
			d := createTestConnectorResourceData(tt.resourceData)
			d.SetId(connectorID)

			// Execute update
			diags := resourceEaaConnectorUpdate(ctx, d, mockClient)

			// Check for errors
			if tt.expectedError {
				if len(diags) == 0 || !hasError(diags) {
					t.Errorf("Expected error but got none")
				}
			} else {
				if hasError(diags) {
					t.Errorf("Unexpected error: %v", diags)
				}
			}
		})
	}
}

func TestConnectorDelete(t *testing.T) {
	ctx := context.Background()
	connectorID := "test-connector-uuid-123"

	tests := map[string]struct {
		connectorID    string
		expectedError  bool
		setupMock      func(*testmocks.MockConnector)
	}{
		"successful_deletion": {
			connectorID:   connectorID,
			expectedError: false,
			setupMock: func(m *testmocks.MockConnector) {
				m.WithData(testmocks.MockConnectorData{
					ConnectorID: connectorID,
				}).MockDeleteConnector()
			},
		},
		"deletion_with_non_existent_id": {
			connectorID:   "non-existent-id",
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// Mock 404 response
				deleteURL := fmt.Sprintf("DELETE /crux/v1/mgmt-pop/agents/%s", "non-existent-id")
				deleteURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", "non-existent-id")
				m.Transport().Responses[deleteURL] = testmocks.MockResponse{
					StatusCode: 404,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Not Found",
						"detail": "Connector not found",
					},
				}
				m.Transport().Responses[deleteURL2] = testmocks.MockResponse{
					StatusCode: 404,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Not Found",
						"detail": "Connector not found",
					},
				}
			},
		},
		"deletion_with_api_error": {
			connectorID:   connectorID,
			expectedError: true,
			setupMock: func(m *testmocks.MockConnector) {
				// Mock 500 response
				deleteURL := fmt.Sprintf("DELETE /crux/v1/mgmt-pop/agents/%s", connectorID)
				deleteURL2 := fmt.Sprintf("/crux/v1/mgmt-pop/agents/%s", connectorID)
				m.Transport().Responses[deleteURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Server error",
					},
				}
				m.Transport().Responses[deleteURL2] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Server error",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			mockConnector := testmocks.NewMockConnector(mockClient, mockTransport)
			if tt.setupMock != nil {
				tt.setupMock(mockConnector)
			}

			// Create test resource data with ID
			d := createTestConnectorResourceData(map[string]interface{}{})
			d.SetId(tt.connectorID)

			// Execute delete
			diags := resourceEaaConnectorDelete(ctx, d, mockClient)

			// Check for errors
			if tt.expectedError {
				if len(diags) == 0 || !hasError(diags) {
					t.Errorf("Expected error but got none")
				}
			} else {
				if hasError(diags) {
					t.Errorf("Unexpected error: %v", diags)
				}
				// Verify resource ID is cleared
				if d.Id() != "" {
					t.Errorf("Expected resource ID to be cleared after deletion")
				}
				// Verify mock was called
				if mockConnector.GetCallCount("delete") == 0 {
					t.Errorf("Expected delete to be called")
				}
			}
		})
	}
}

// Helper function to check if diagnostics contain errors
func hasError(diags diag.Diagnostics) bool {
	for _, d := range diags {
		if d.Severity == diag.Error {
			return true
		}
	}
	return false
}

