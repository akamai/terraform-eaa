package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACLSetting_Validate(t *testing.T) {
	testCases := []struct {
		name        string
		setting     ACLSetting
		expectError bool
		errorText   string
	}{
		{
			name: "valid setting with IS operator and URL type",
			setting: ACLSetting{
				Operator: OPERATOR_IS,
				Type:     ACCESS_RULE_SETTING_URL,
				Value:    "/admin/*",
			},
			expectError: false,
		},
		{
			name: "valid setting with IS_NOT operator and GROUP type",
			setting: ACLSetting{
				Operator: OPERATOR_IS_NOT,
				Type:     ACCESS_RULE_SETTING_GROUP,
				Value:    "admin-group",
			},
			expectError: false,
		},
		{
			name: "valid setting with USER type",
			setting: ACLSetting{
				Operator: OPERATOR_IS,
				Type:     ACCESS_RULE_SETTING_USER,
				Value:    "john.doe@example.com",
			},
			expectError: false,
		},
		{
			name: "valid setting with CLIENTIP type",
			setting: ACLSetting{
				Operator: OPERATOR_IS,
				Type:     ACCESS_RULE_SETTING_CLIENTIP,
				Value:    "192.168.1.0/24",
			},
			expectError: false,
		},
		{
			name: "valid setting with COUNTRY type",
			setting: ACLSetting{
				Operator: OPERATOR_IS_NOT,
				Type:     ACCESS_RULE_SETTING_COUNTRY,
				Value:    "US",
			},
			expectError: false,
		},
		{
			name: "valid setting with TIME type",
			setting: ACLSetting{
				Operator: OPERATOR_IS,
				Type:     ACCESS_RULE_SETTING_TIME,
				Value:    "09:00-17:00",
			},
			expectError: false,
		},
		{
			name: "valid setting with METHOD type",
			setting: ACLSetting{
				Operator: OPERATOR_IS,
				Type:     ACCESS_RULE_SETTING_METHOD,
				Value:    "GET",
			},
			expectError: false,
		},
		{
			name: "invalid operator",
			setting: ACLSetting{
				Operator: "INVALID_OPERATOR",
				Type:     ACCESS_RULE_SETTING_URL,
				Value:    "/test",
			},
			expectError: true,
			errorText:   "invalid rule operator",
		},
		{
			name: "invalid rule type",
			setting: ACLSetting{
				Operator: OPERATOR_IS,
				Type:     "INVALID_TYPE",
				Value:    "test",
			},
			expectError: true,
			errorText:   "invalid rule type",
		},
		{
			name: "empty operator",
			setting: ACLSetting{
				Operator: "",
				Type:     ACCESS_RULE_SETTING_URL,
				Value:    "/test",
			},
			expectError: true,
			errorText:   "invalid rule operator",
		},
		{
			name: "empty type",
			setting: ACLSetting{
				Operator: OPERATOR_IS,
				Type:     "",
				Value:    "/test",
			},
			expectError: true,
			errorText:   "invalid rule type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.setting.Validate()

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorText != "" {
					assert.Contains(t, err.Error(), tc.errorText)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAccessRule_CreateAccessRule(t *testing.T) {
	testCases := []struct {
		name            string
		rule            AccessRule
		serviceUUIDURL  string
		mockStatusCode  int
		mockResponse    interface{}
		expectError     bool
		errorContains   string
		validateRequest func(*testing.T, *http.Request)
	}{
		{
			name: "successful create access rule",
			rule: AccessRule{
				Name:   "Block Admin Access",
				Status: 1,
				Settings: []ACLSetting{
					{
						Operator: OPERATOR_IS,
						Type:     ACCESS_RULE_SETTING_URL,
						Value:    "/admin/*",
					},
				},
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusOK,
			mockResponse:   map[string]interface{}{"success": true},
			expectError:    false,
			validateRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/services/service-uuid-123/rules"
				assert.Equal(t, expectedPath, r.URL.Path)

				// Validate request body
				var requestBody AccessRuleRequest
				err := json.NewDecoder(r.Body).Decode(&requestBody)
				require.NoError(t, err)

				assert.Equal(t, "Block Admin Access", requestBody.Name)
				assert.Equal(t, RULE_ACTION_DENY, requestBody.Action)
				assert.Equal(t, RULE_TYPE_ACCESS_CTRL, requestBody.RuleType)
				assert.Equal(t, "service-uuid-123", requestBody.Service)
				assert.Len(t, requestBody.Settings, 1)
				assert.Equal(t, OPERATOR_IS, requestBody.Settings[0].Operator)
				assert.Equal(t, ACCESS_RULE_SETTING_URL, requestBody.Settings[0].Type)
				assert.Equal(t, "/admin/*", requestBody.Settings[0].Value)
			},
		},
		{
			name: "create access rule with multiple settings",
			rule: AccessRule{
				Name:   "Complex Rule",
				Status: 1,
				Settings: []ACLSetting{
					{
						Operator: OPERATOR_IS,
						Type:     ACCESS_RULE_SETTING_URL,
						Value:    "/api/*",
					},
					{
						Operator: OPERATOR_IS_NOT,
						Type:     ACCESS_RULE_SETTING_GROUP,
						Value:    "api-users",
					},
				},
			},
			serviceUUIDURL: "service-uuid-456",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "empty service UUID URL",
			rule:           AccessRule{Name: "Test Rule"},
			serviceUUIDURL: "",
			expectError:    true,
			errorContains:  "create rule failed",
		},
		{
			name: "server error during creation",
			rule: AccessRule{
				Name:   "Test Rule",
				Status: 1,
			},
			serviceUUIDURL: "service-uuid-error",
			mockStatusCode: http.StatusInternalServerError,
			mockResponse: map[string]interface{}{
				"error": "Internal server error",
			},
			expectError:   true,
			errorContains: "create rule failed",
		},
		{
			name: "bad request error",
			rule: AccessRule{
				Name:   "Invalid Rule",
				Status: 1,
			},
			serviceUUIDURL: "service-uuid-bad",
			mockStatusCode: http.StatusBadRequest,
			mockResponse: map[string]interface{}{
				"error": "Invalid rule configuration",
			},
			expectError:   true,
			errorContains: "create rule failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.validateRequest != nil {
					tc.validateRequest(t, r)
				}

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(),
			}

			// Execute function
			ctx := context.Background()
			err := tc.rule.CreateAccessRule(ctx, client, tc.serviceUUIDURL)

			// Assertions
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

func TestAccessRule_DeleteAccessRule(t *testing.T) {
	testCases := []struct {
		name           string
		rule           AccessRule
		serviceUUIDURL string
		mockStatusCode int
		expectError    bool
		errorContains  string
	}{
		{
			name: "successful delete access rule",
			rule: AccessRule{
				UUID_URL: "rule-uuid-123",
				Name:     "Test Rule",
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "successful delete with status 204",
			rule: AccessRule{
				UUID_URL: "rule-uuid-456",
				Name:     "Another Rule",
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusNoContent,
			expectError:    false,
		},
		{
			name: "empty rule UUID URL",
			rule: AccessRule{
				UUID_URL: "",
				Name:     "Test Rule",
			},
			serviceUUIDURL: "service-uuid-123",
			expectError:    true,
			errorContains:  "delete rule failed",
		},
		{
			name: "empty service UUID URL",
			rule: AccessRule{
				UUID_URL: "rule-uuid-123",
				Name:     "Test Rule",
			},
			serviceUUIDURL: "",
			expectError:    true,
			errorContains:  "delete rule failed",
		},
		{
			name: "rule not found",
			rule: AccessRule{
				UUID_URL: "rule-uuid-notfound",
				Name:     "Non-existent Rule",
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "delete rule failed",
		},
		{
			name: "server error during deletion",
			rule: AccessRule{
				UUID_URL: "rule-uuid-error",
				Name:     "Error Rule",
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "delete rule failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "DELETE", r.Method)
				if tc.rule.UUID_URL != "" && tc.serviceUUIDURL != "" {
					expectedPath := "/crux/v1/mgmt-pop/services/" + tc.serviceUUIDURL + "/rules/" + tc.rule.UUID_URL
					assert.Equal(t, expectedPath, r.URL.Path)
				}

				w.WriteHeader(tc.mockStatusCode)
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(),
			}

			// Execute function
			ctx := context.Background()
			err := tc.rule.DeleteAccessRule(ctx, client, tc.serviceUUIDURL)

			// Assertions
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

func TestAccessRule_ModifyAccessRule(t *testing.T) {
	testCases := []struct {
		name            string
		rule            AccessRule
		serviceUUIDURL  string
		mockStatusCode  int
		mockResponse    interface{}
		expectError     bool
		errorContains   string
		validateRequest func(*testing.T, *http.Request)
	}{
		{
			name: "successful modify access rule",
			rule: AccessRule{
				UUID_URL: "rule-uuid-123",
				Name:     "Modified Rule",
				Status:   1,
				Settings: []ACLSetting{
					{
						Operator: OPERATOR_IS,
						Type:     ACCESS_RULE_SETTING_URL,
						Value:    "/modified/*",
					},
				},
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusOK,
			mockResponse:   map[string]interface{}{"success": true},
			expectError:    false,
			validateRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/services/service-uuid-123/rules/rule-uuid-123"
				assert.Equal(t, expectedPath, r.URL.Path)

				// Validate request body
				var requestBody AccessRuleRequest
				err := json.NewDecoder(r.Body).Decode(&requestBody)
				require.NoError(t, err)

				assert.Equal(t, "Modified Rule", requestBody.Name)
				assert.Equal(t, RULE_ACTION_DENY, requestBody.Action)
				assert.Equal(t, RULE_TYPE_ACCESS_CTRL, requestBody.RuleType)
				assert.Equal(t, "service-uuid-123", requestBody.Service)
			},
		},
		{
			name: "empty rule UUID URL",
			rule: AccessRule{
				UUID_URL: "",
				Name:     "Test Rule",
			},
			serviceUUIDURL: "service-uuid-123",
			expectError:    true,
			errorContains:  "modify rule failed",
		},
		{
			name: "empty service UUID URL",
			rule: AccessRule{
				UUID_URL: "rule-uuid-123",
				Name:     "Test Rule",
			},
			serviceUUIDURL: "",
			expectError:    true,
			errorContains:  "modify rule failed",
		},
		{
			name: "server error during modification",
			rule: AccessRule{
				UUID_URL: "rule-uuid-error",
				Name:     "Error Rule",
				Status:   1,
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusInternalServerError,
			mockResponse: map[string]interface{}{
				"error": "Internal server error",
			},
			expectError:   true,
			errorContains: "modify rule failed",
		},
		{
			name: "rule not found during modification",
			rule: AccessRule{
				UUID_URL: "rule-uuid-notfound",
				Name:     "Non-existent Rule",
				Status:   1,
			},
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "modify rule failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.validateRequest != nil {
					tc.validateRequest(t, r)
				}

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(),
			}

			// Execute function
			ctx := context.Background()
			err := tc.rule.ModifyAccessRule(ctx, client, tc.serviceUUIDURL)

			// Assertions
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

func TestAccessRule_ModifyAccessRule_EdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		scenario string
	}{
		{
			name:     "rule modification with complex settings",
			scenario: "multiple_settings",
		},
		{
			name:     "rule modification with empty settings",
			scenario: "empty_settings",
		},
		{
			name:     "rule modification with invalid timestamp handling",
			scenario: "timestamp_edge_case",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := AccessRule{
				UUID_URL: "rule-uuid-edge",
				Name:     "Edge Case Rule",
				Status:   1,
			}

			switch tc.scenario {
			case "multiple_settings":
				rule.Settings = []ACLSetting{
					{Operator: OPERATOR_IS, Type: ACCESS_RULE_SETTING_URL, Value: "/api/*"},
					{Operator: OPERATOR_IS_NOT, Type: ACCESS_RULE_SETTING_GROUP, Value: "blocked"},
					{Operator: OPERATOR_IS, Type: ACCESS_RULE_SETTING_CLIENTIP, Value: "10.0.0.0/8"},
				}
			case "empty_settings":
				rule.Settings = []ACLSetting{}
			case "timestamp_edge_case":
				rule.Settings = []ACLSetting{
					{Operator: OPERATOR_IS, Type: ACCESS_RULE_SETTING_TIME, Value: "00:00-23:59"},
				}
			}

			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)

				// Validate request body includes proper timestamps
				var requestBody AccessRuleRequest
				err := json.NewDecoder(r.Body).Decode(&requestBody)
				require.NoError(t, err)

				// Verify timestamp fields are set for modify operation
				assert.False(t, requestBody.ModifiedAt.IsZero())
				// CreatedAt is not set during modify operations, only ModifiedAt

				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"success": true}`))
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(),
			}

			ctx := context.Background()
			err := rule.ModifyAccessRule(ctx, client, "service-uuid-123")
			assert.NoError(t, err)
		})
	}
}

func TestAppService_EnableService(t *testing.T) {
	testCases := []struct {
		name            string
		appService      AppService
		mockStatusCode  int
		mockResponse    interface{}
		expectError     bool
		errorContains   string
		validateRequest func(*testing.T, *http.Request)
	}{
		{
			name: "successful enable service",
			appService: AppService{
				UUIDURL:     "service-uuid-123",
				Name:        "Access Control",
				ServiceType: SERVICE_TYPE_ACCESS_CTRL,
				Status:      "enabled",
			},
			mockStatusCode: http.StatusOK,
			mockResponse:   map[string]interface{}{"success": true},
			expectError:    false,
			validateRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "PUT", r.Method)
				expectedPath := "/crux/v1/mgmt-pop/services/service-uuid-123"
				assert.Equal(t, expectedPath, r.URL.Path)

				// Validate request body contains service info
				var requestBody AppService
				err := json.NewDecoder(r.Body).Decode(&requestBody)
				require.NoError(t, err)
				assert.Equal(t, "Access Control", requestBody.Name)
				assert.Equal(t, SERVICE_TYPE_ACCESS_CTRL, requestBody.ServiceType)
			},
		},
		{
			name: "enable service with different service type",
			appService: AppService{
				UUIDURL:     "service-uuid-waf",
				Name:        "WAF Service",
				ServiceType: SERVICE_TYPE_WAF,
				Status:      "enabled",
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name: "empty service UUID URL",
			appService: AppService{
				Name:        "Test Service",
				ServiceType: SERVICE_TYPE_ACCESS_CTRL,
			},
			expectError:   true,
			errorContains: "enable service failed",
		},
		{
			name: "server error during enable",
			appService: AppService{
				UUIDURL:     "service-uuid-error",
				Name:        "Error Service",
				ServiceType: SERVICE_TYPE_ACCESS_CTRL,
			},
			mockStatusCode: http.StatusInternalServerError,
			mockResponse: map[string]interface{}{
				"error": "Internal server error",
			},
			expectError:   true,
			errorContains: "enable service failed",
		},
		{
			name: "bad request error",
			appService: AppService{
				UUIDURL:     "service-uuid-bad",
				Name:        "Bad Service",
				ServiceType: SERVICE_TYPE_ACCESS_CTRL,
			},
			mockStatusCode: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "enable service failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.validateRequest != nil {
					tc.validateRequest(t, r)
				}

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(),
			}

			// Execute function
			err := tc.appService.EnableService(client)

			// Assertions
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

func TestGetACLService(t *testing.T) {
	testCases := []struct {
		name           string
		appUUIDURL     string
		mockStatusCode int
		mockResponse   *AppServicesResponse
		expectError    bool
		errorContains  string
		expectedResult *AppService
	}{
		{
			name:           "successful get ACL service",
			appUUIDURL:     "app-uuid-123",
			mockStatusCode: http.StatusOK,
			mockResponse: &AppServicesResponse{
				AppServices: []AppServiceData{
					{
						Service: AppService{
							UUIDURL:     "service-uuid-acl",
							Name:        "Access Control",
							ServiceType: SERVICE_TYPE_ACCESS_CTRL,
							Status:      "enabled",
						},
						Status:  1,
						UUIDURL: "service-uuid-acl",
					},
					{
						Service: AppService{
							UUIDURL:     "service-uuid-waf",
							Name:        "WAF",
							ServiceType: SERVICE_TYPE_WAF,
							Status:      "disabled",
						},
						Status:  0,
						UUIDURL: "service-uuid-waf",
					},
				},
			},
			expectError: false,
			expectedResult: &AppService{
				UUIDURL:     "service-uuid-acl",
				Name:        "Access Control",
				ServiceType: SERVICE_TYPE_ACCESS_CTRL,
				Status:      "enabled",
			},
		},
		{
			name:           "no ACL service found",
			appUUIDURL:     "app-uuid-no-acl",
			mockStatusCode: http.StatusOK,
			mockResponse: &AppServicesResponse{
				AppServices: []AppServiceData{
					{
						Service: AppService{
							UUIDURL:     "service-uuid-waf",
							Name:        "WAF",
							ServiceType: SERVICE_TYPE_WAF,
							Status:      "enabled",
						},
					},
				},
			},
			expectError:   true,
			errorContains: "get app services failed",
		},
		{
			name:           "empty services list",
			appUUIDURL:     "app-uuid-empty",
			mockStatusCode: http.StatusOK,
			mockResponse: &AppServicesResponse{
				AppServices: []AppServiceData{},
			},
			expectError:   true,
			errorContains: "get app services failed",
		},
		{
			name:          "empty app UUID URL",
			appUUIDURL:    "",
			expectError:   true,
			errorContains: "enable service failed",
		},
		{
			name:           "server error",
			appUUIDURL:     "app-uuid-error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "get app services failed",
		},
		{
			name:           "not found error",
			appUUIDURL:     "app-uuid-notfound",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "get app services failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				if tc.appUUIDURL != "" {
					expectedPath := "/crux/v1/mgmt-pop/apps/" + tc.appUUIDURL + "/services"
					assert.Equal(t, expectedPath, r.URL.Path)
				}

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(),
			}

			// Execute function
			result, err := GetACLService(client, tc.appUUIDURL)

			// Assertions
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tc.expectedResult != nil {
					assert.Equal(t, tc.expectedResult.UUIDURL, result.UUIDURL)
					assert.Equal(t, tc.expectedResult.Name, result.Name)
					assert.Equal(t, tc.expectedResult.ServiceType, result.ServiceType)
					assert.Equal(t, tc.expectedResult.Status, result.Status)
				}
			}
		})
	}
}

func TestGetAccessControlRules(t *testing.T) {
	testCases := []struct {
		name             string
		serviceUUIDURL   string
		mockStatusCode   int
		mockResponse     *ACLRulesResponse
		expectError      bool
		errorContains    string
		expectedRulesLen int
	}{
		{
			name:           "successful get access control rules",
			serviceUUIDURL: "service-uuid-123",
			mockStatusCode: http.StatusOK,
			mockResponse: &ACLRulesResponse{
				ACLRules: []AccessRule{
					{
						Name:     "Block Admin Access",
						Status:   ADMIN_STATE_ENABLED,
						UUID_URL: "rule-uuid-1",
						Settings: []ACLSetting{
							{
								Operator: OPERATOR_IS,
								Type:     ACCESS_RULE_SETTING_URL,
								Value:    "/admin/*",
							},
						},
					},
					{
						Name:     "Allow API Access",
						Status:   ADMIN_STATE_ENABLED,
						UUID_URL: "rule-uuid-2",
						Settings: []ACLSetting{
							{
								Operator: OPERATOR_IS,
								Type:     ACCESS_RULE_SETTING_URL,
								Value:    "/api/*",
							},
							{
								Operator: OPERATOR_IS,
								Type:     ACCESS_RULE_SETTING_GROUP,
								Value:    "api-users",
							},
						},
					},
				},
			},
			expectError:      false,
			expectedRulesLen: 2,
		},
		{
			name:           "empty rules response",
			serviceUUIDURL: "service-uuid-empty",
			mockStatusCode: http.StatusOK,
			mockResponse: &ACLRulesResponse{
				ACLRules: []AccessRule{},
			},
			expectError:      false,
			expectedRulesLen: 0,
		},
		{
			name:           "single rule with multiple settings",
			serviceUUIDURL: "service-uuid-complex",
			mockStatusCode: http.StatusOK,
			mockResponse: &ACLRulesResponse{
				ACLRules: []AccessRule{
					{
						Name:     "Complex Rule",
						Status:   ADMIN_STATE_ENABLED,
						UUID_URL: "rule-uuid-complex",
						Settings: []ACLSetting{
							{
								Operator: OPERATOR_IS,
								Type:     ACCESS_RULE_SETTING_URL,
								Value:    "/secure/*",
							},
							{
								Operator: OPERATOR_IS_NOT,
								Type:     ACCESS_RULE_SETTING_CLIENTIP,
								Value:    "192.168.1.0/24",
							},
							{
								Operator: OPERATOR_IS,
								Type:     ACCESS_RULE_SETTING_TIME,
								Value:    "09:00-17:00",
							},
						},
					},
				},
			},
			expectError:      false,
			expectedRulesLen: 1,
		},
		{
			name:           "empty service UUID URL",
			serviceUUIDURL: "",
			expectError:    true,
			errorContains:  "enable service failed",
		},
		{
			name:           "server error",
			serviceUUIDURL: "service-uuid-error",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "get app services failed",
		},
		{
			name:           "unauthorized error",
			serviceUUIDURL: "service-uuid-unauth",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
			errorContains:  "get app services failed",
		},
		{
			name:           "not found error",
			serviceUUIDURL: "service-uuid-notfound",
			mockStatusCode: http.StatusNotFound,
			expectError:    true,
			errorContains:  "get app services failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				if tc.serviceUUIDURL != "" {
					expectedPath := "/crux/v1/mgmt-pop/services/" + tc.serviceUUIDURL + "/rules"
					assert.Equal(t, expectedPath, r.URL.Path)
				}

				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					responseJSON, _ := json.Marshal(tc.mockResponse)
					w.Write(responseJSON)
				}
			}))
			defer server.Close()

			// Parse server URL
			serverURL, _ := url.Parse(server.URL)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Host:   serverURL.Host,
				Logger: logger,
				Signer: &MockSigner{},
				Client: server.Client(),
			}

			// Execute function
			result, err := GetAccessControlRules(client, tc.serviceUUIDURL)

			// Assertions
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.ACLRules, tc.expectedRulesLen)

				// Verify rule structure for non-empty responses
				if tc.expectedRulesLen > 0 {
					for _, rule := range result.ACLRules {
						assert.NotEmpty(t, rule.Name)
						assert.NotEmpty(t, rule.UUID_URL)
						if len(rule.Settings) > 0 {
							for _, setting := range rule.Settings {
								assert.NotEmpty(t, setting.Operator)
								assert.NotEmpty(t, setting.Type)
								assert.NotEmpty(t, setting.Value)
							}
						}
					}
				}
			}
		})
	}
}
