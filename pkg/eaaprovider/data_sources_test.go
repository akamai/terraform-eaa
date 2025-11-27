package eaaprovider

import (
	"context"
	"fmt"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/testmocks"

	"github.com/stretchr/testify/assert"
)

// TestDataSourceAppCategoriesRead tests the dataSourceAppCategoriesRead function
func TestDataSourceAppCategoriesRead(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		mockResponse       []client.AppCate
		expectedError      bool
		expectedCount      int
		expectedCategories []string
		setupMock          func(*testmocks.MockHTTPTransport)
	}{
		"successful app categories retrieval": {
			mockResponse: []client.AppCate{
				{
					UUIDURL: "category-001",
					Name:    "Web Applications",
				},
				{
					UUIDURL: "category-002",
					Name:    "SSH Applications",
				},
				{
					UUIDURL: "category-003",
					Name:    "Database Applications",
				},
			},
			expectedError:      false,
			expectedCount:      3,
			expectedCategories: []string{"Web Applications", "SSH Applications", "Database Applications"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/appcategories")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 3,
						},
						"objects": []map[string]interface{}{
							{"uuid_url": "category-001", "name": "Web Applications"},
							{"uuid_url": "category-002", "name": "SSH Applications"},
							{"uuid_url": "category-003", "name": "Database Applications"},
						},
					},
				}
			},
		},
		"empty app categories": {
			mockResponse:  []client.AppCate{},
			expectedError: false,
			expectedCount: 0,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/appcategories")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 0,
						},
						"objects": []map[string]interface{}{},
					},
				}
			},
		},
		"client error": {
			mockResponse:  nil,
			expectedError: true,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/appcategories")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Failed to get app categories",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			if tt.setupMock != nil {
				tt.setupMock(mockTransport)
			}

			// Create resource data using actual schema
			resource := dataSourceAppCategories()
			resourceData := resource.Data(nil)

			// Call the actual data source function
			diags := dataSourceAppCategoriesRead(ctx, resourceData, mockClient)

			// Verify results
			if tt.expectedError {
				assert.True(t, diags.HasError(), "Expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "Unexpected error: %v", diags)
				assert.Equal(t, "eaa_appcategories", resourceData.Id())

				if tt.expectedCount > 0 {
					categoriesData := resourceData.Get("appcategories").([]interface{})
					assert.Len(t, categoriesData, tt.expectedCount)

					// Verify category names
					for i, expectedName := range tt.expectedCategories {
						if i < len(categoriesData) {
							categoryMap := categoriesData[i].(map[string]interface{})
							assert.Equal(t, expectedName, categoryMap["name"])
						}
					}
				}
			}
		})
	}
}

// TestDataSourceAppsRead tests the dataSourceAppsRead function
func TestDataSourceAppsRead(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		expectedError bool
		expectedCount int
		expectedApps  []string
		setupMock     func(*testmocks.MockHTTPTransport)
	}{
		"successful apps retrieval": {
			expectedError: false,
			expectedCount: 3,
			expectedApps:  []string{"Corporate Portal", "Database Admin", "File Server"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v3/mgmt-pop/apps")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 3,
							"limit":       10,
						},
						"objects": []map[string]interface{}{
							{"uuid_url": "app-001", "name": "Corporate Portal"},
							{"uuid_url": "app-002", "name": "Database Admin"},
							{"uuid_url": "app-003", "name": "File Server"},
						},
					},
				}
			},
		},
		"empty apps list": {
			expectedError: false,
			expectedCount: 0,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v3/mgmt-pop/apps")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 0,
							"limit":       10,
						},
						"objects": []map[string]interface{}{},
					},
				}
			},
		},
		"single app": {
			expectedError: false,
			expectedCount: 1,
			expectedApps:  []string{"Single App"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v3/mgmt-pop/apps")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 1,
							"limit":       10,
						},
						"objects": []map[string]interface{}{
							{"uuid_url": "app-single", "name": "Single App"},
						},
					},
				}
			},
		},
		"client error": {
			expectedError: true,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v3/mgmt-pop/apps")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Failed to get applications",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			if tt.setupMock != nil {
				tt.setupMock(mockTransport)
			}

			// Create resource data using actual schema
			resource := dataSourceApps()
			resourceData := resource.Data(nil)

			// Call the actual data source function
			diags := dataSourceAppsRead(ctx, resourceData, mockClient)

			// Verify results
			if tt.expectedError {
				assert.True(t, diags.HasError(), "Expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "Unexpected error: %v", diags)
				assert.Equal(t, "eaa_apps", resourceData.Id())

				if tt.expectedCount > 0 {
					appsData := resourceData.Get("apps").([]interface{})
					assert.Len(t, appsData, tt.expectedCount)

					// Verify app names
					for i, expectedName := range tt.expectedApps {
						if i < len(appsData) {
							appMap := appsData[i].(map[string]interface{})
							assert.Equal(t, expectedName, appMap["name"])
						}
					}
				}
			}
		})
	}
}

// TestDataSourceAgentsRead tests the dataSourceAgentsRead function
func TestDataSourceAgentsRead(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		expectedError  bool
		expectedCount  int
		expectedAgents []string
		setupMock      func(*testmocks.MockHTTPTransport)
	}{
		"successful agents retrieval": {
			expectedError:  false,
			expectedCount:  3,
			expectedAgents: []string{"agent-us-east-001", "agent-eu-west-002", "agent-apac-003"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 3,
							"limit":       10,
						},
						"objects": []map[string]interface{}{
							{"uuid_url": "agent-us-east-001", "name": "agent-us-east-001"},
							{"uuid_url": "agent-eu-west-002", "name": "agent-eu-west-002"},
							{"uuid_url": "agent-apac-003", "name": "agent-apac-003"},
						},
					},
				}
			},
		},
		"empty agents list": {
			expectedError: false,
			expectedCount: 0,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 0,
							"limit":       10,
						},
						"objects": []map[string]interface{}{},
					},
				}
			},
		},
		"single agent": {
			expectedError:  false,
			expectedCount:  1,
			expectedAgents: []string{"agent-single-001"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 1,
							"limit":       10,
						},
						"objects": []map[string]interface{}{
							{"uuid_url": "agent-single-001", "name": "agent-single-001"},
						},
					},
				}
			},
		},
		"client error": {
			expectedError: true,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/agents")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Failed to get agents",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			if tt.setupMock != nil {
				tt.setupMock(mockTransport)
			}

			// Create resource data using actual schema
			resource := dataSourceAgents()
			resourceData := resource.Data(nil)

			// Call the actual data source function
			diags := dataSourceAgentsRead(ctx, resourceData, mockClient)

			// Verify results
			if tt.expectedError {
				assert.True(t, diags.HasError(), "Expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "Unexpected error: %v", diags)
				assert.Equal(t, "eaa_agents", resourceData.Id())

				if tt.expectedCount > 0 {
					agentsData := resourceData.Get("agents").([]interface{})
					assert.Len(t, agentsData, tt.expectedCount)

					// Verify agent UUIDs
					for i, expectedUUID := range tt.expectedAgents {
						if i < len(agentsData) {
							agentMap := agentsData[i].(map[string]interface{})
							assert.Equal(t, expectedUUID, agentMap["uuid_url"])
						}
					}
				}
			}
		})
	}
}

// TestDataSourceIdpsRead tests the dataSourceIdpsRead function
func TestDataSourceIdpsRead(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		expectedError bool
		expectedCount int
		expectedIdps  []string
		setupMock     func(*testmocks.MockHTTPTransport)
	}{
		"successful IDPs retrieval": {
			expectedError: false,
			expectedCount: 3,
			expectedIdps:  []string{"Corporate SAML", "External OIDC", "LDAP Directory"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 3,
						},
						"objects": []map[string]interface{}{
							{"uuid_url": "idp-001", "name": "Corporate SAML"},
							{"uuid_url": "idp-002", "name": "External OIDC"},
							{"uuid_url": "idp-003", "name": "LDAP Directory"},
						},
					},
				}
				// Mock directory endpoints for each IDP
				dirURL1 := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp/idp-001/directories")
				mt.Responses[dirURL1] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"objects": []map[string]interface{}{},
					},
				}
				dirURL2 := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp/idp-002/directories")
				mt.Responses[dirURL2] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"objects": []map[string]interface{}{},
					},
				}
				dirURL3 := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp/idp-003/directories")
				mt.Responses[dirURL3] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"objects": []map[string]interface{}{},
					},
				}
			},
		},
		"empty IDPs list": {
			expectedError: false,
			expectedCount: 0,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 0,
						},
						"objects": []map[string]interface{}{},
					},
				}
			},
		},
		"single IDP": {
			expectedError: false,
			expectedCount: 1,
			expectedIdps:  []string{"Single IDP"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 1,
						},
						"objects": []map[string]interface{}{
							{"uuid_url": "idp-single", "name": "Single IDP"},
						},
					},
				}
				dirURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp/idp-single/directories")
				mt.Responses[dirURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"objects": []map[string]interface{}{},
					},
				}
			},
		},
		"client error": {
			expectedError: true,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/idp")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Failed to get IDPs",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			if tt.setupMock != nil {
				tt.setupMock(mockTransport)
			}

			// Create resource data using actual schema
			resource := dataSourceIdps()
			resourceData := resource.Data(nil)

			// Call the actual data source function
			diags := dataSourceIdpsRead(ctx, resourceData, mockClient)

			// Verify results
			if tt.expectedError {
				assert.True(t, diags.HasError(), "Expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "Unexpected error: %v", diags)
				assert.Equal(t, "eaa_idps", resourceData.Id())

				if tt.expectedCount > 0 {
					idpsData := resourceData.Get("idps").([]interface{})
					assert.Len(t, idpsData, tt.expectedCount)

					// Verify IDP names
					for i, expectedName := range tt.expectedIdps {
						if i < len(idpsData) {
							idpMap := idpsData[i].(map[string]interface{})
							assert.Equal(t, expectedName, idpMap["name"])
						}
					}
				}
			}
		})
	}
}

// TestDataSourceConnectorPoolsRead tests the dataSourceConnectorPoolsRead function
func TestDataSourceConnectorPoolsRead(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		expectedError bool
		expectedCount int
		expectedPools []string
		setupMock     func(*testmocks.MockHTTPTransport)
	}{
		"successful connector pools retrieval": {
			expectedError: false,
			expectedCount: 3,
			expectedPools: []string{"Production Pool", "Staging Pool", "Development Pool"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/connector-pools")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 3,
							"limit":       10,
						},
						"objects": []map[string]interface{}{
							{
								"uuid_url":      "pool-001",
								"name":          "Production Pool",
								"description":   "Production environment connectors",
								"package_type":  0,
								"infra_type":    0,
								"operating_mode": 0,
							},
							{
								"uuid_url":      "pool-002",
								"name":          "Staging Pool",
								"description":   "Staging environment connectors",
								"package_type":  0,
								"infra_type":    0,
								"operating_mode": 0,
							},
							{
								"uuid_url":      "pool-003",
								"name":          "Development Pool",
								"description":   "Development environment connectors",
								"package_type":  0,
								"infra_type":    0,
								"operating_mode": 0,
							},
						},
					},
				}
			},
		},
		"empty pools list": {
			expectedError: false,
			expectedCount: 0,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/connector-pools")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 0,
							"limit":       10,
						},
						"objects": []map[string]interface{}{},
					},
				}
			},
		},
		"single pool": {
			expectedError: false,
			expectedCount: 1,
			expectedPools: []string{"Single Pool"},
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/connector-pools")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 200,
					Body: map[string]interface{}{
						"meta": map[string]interface{}{
							"total_count": 1,
							"limit":       10,
						},
						"objects": []map[string]interface{}{
							{
								"uuid_url":      "pool-single",
								"name":          "Single Pool",
								"description":   "Only pool available",
								"package_type":  0,
								"infra_type":    0,
								"operating_mode": 0,
							},
						},
					},
				}
			},
		},
		"client error": {
			expectedError: true,
			setupMock: func(mt *testmocks.MockHTTPTransport) {
				apiURL := fmt.Sprintf("GET /crux/v1/mgmt-pop/connector-pools")
				mt.Responses[apiURL] = testmocks.MockResponse{
					StatusCode: 500,
					Body: map[string]interface{}{
						"type":   "error",
						"title":  "Internal Server Error",
						"detail": "Failed to get connector pools",
					},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Setup structured mocks
			mockClient, mockTransport := testmocks.CreateMockEaaClientWithMocks()
			if tt.setupMock != nil {
				tt.setupMock(mockTransport)
			}

			// Create resource data using actual schema
			resource := dataSourceEaaConnectorPools()
			resourceData := resource.Data(nil)

			// Call the actual data source function
			diags := dataSourceEaaConnectorPoolsRead(ctx, resourceData, mockClient)

			// Verify results
			if tt.expectedError {
				assert.True(t, diags.HasError(), "Expected error but got none")
			} else {
				assert.False(t, diags.HasError(), "Unexpected error: %v", diags)
				assert.Equal(t, "eaa_connector_pools", resourceData.Id())

				if tt.expectedCount > 0 {
					poolsData := resourceData.Get("connector_pools").([]interface{})
					assert.Len(t, poolsData, tt.expectedCount)

					// Verify pool names
					for i, expectedName := range tt.expectedPools {
						if i < len(poolsData) {
							poolMap := poolsData[i].(map[string]interface{})
							assert.Equal(t, expectedName, poolMap["name"])
						}
					}
				}
			}
		})
	}
}
