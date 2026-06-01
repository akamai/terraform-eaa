package eaaprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Schema validation
// ===========================================================================

func TestResourceEaaApplication_Schema(t *testing.T) {
	r := resourceEaaApplication()
	require.NotNil(t, r)

	t.Run("required fields", func(t *testing.T) {
		// Only "name" is Required at the top level
		assert.True(t, r.Schema["name"].Required, "name must be required")
	})

	t.Run("optional fields", func(t *testing.T) {
		optionalFields := []string{
			"description", "app_profile", "app_type", "protocol",
			"host", "bookmark_url", "domain", "origin_host",
			"orig_tls", "origin_port", "tunnel_internal_hosts",
			"servers", "pop", "popname", "popregion",
			"auth_enabled", "agents", "app_category",
			"cert_name", "cert_type", "cert",
			"generate_self_signed_cert", "advanced_settings",
			"app_bundle", "service", "client_app_mode",
			"app_operational", "app_status", "app_deployed",
			"cname", "uuid_url",
		}
		for _, field := range optionalFields {
			f, exists := r.Schema[field]
			require.True(t, exists, "field %q must exist", field)
			assert.True(t, f.Optional, "field %q must be optional", field)
		}
	})

	t.Run("computed fields", func(t *testing.T) {
		computedFields := []string{
			"domain_suffix", "client_app_mode", "host", "domain",
			"origin_host", "orig_tls", "origin_port",
			"pop", "popname", "popregion",
			"app_operational", "app_status", "app_deployed",
			"cname", "uuid_url", "cert",
			"advanced_settings",
		}
		for _, field := range computedFields {
			f, exists := r.Schema[field]
			require.True(t, exists, "field %q must exist", field)
			assert.True(t, f.Computed, "field %q must be computed", field)
		}
	})

	t.Run("computed-only fields", func(t *testing.T) {
		assert.True(t, r.Schema["domain_suffix"].Computed)
		assert.False(t, r.Schema["domain_suffix"].Optional)
	})

	t.Run("saml computed", func(t *testing.T) {
		assert.True(t, r.Schema["saml"].Computed)
	})

	t.Run("wsfed computed", func(t *testing.T) {
		assert.True(t, r.Schema["wsfed"].Computed)
	})

	t.Run("oidc computed", func(t *testing.T) {
		assert.True(t, r.Schema["oidc"].Computed)
	})

	t.Run("advanced_settings is TypeMap", func(t *testing.T) {
		assert.Equal(t, schema.TypeMap, r.Schema["advanced_settings"].Type)
	})

	t.Run("advanced_settings has DiffSuppressFunc", func(t *testing.T) {
		assert.NotNil(t, r.Schema["advanced_settings"].DiffSuppressFunc)
	})
}

// ===========================================================================
// CRUD operations configured
// ===========================================================================

func TestResourceEaaApplication_CRUDOperations(t *testing.T) {
	r := resourceEaaApplication()

	assert.NotNil(t, r.CreateContext, "CreateContext must be configured")
	assert.NotNil(t, r.ReadContext, "ReadContext must be configured")
	assert.NotNil(t, r.UpdateContext, "UpdateContext must be configured")
	assert.NotNil(t, r.DeleteContext, "DeleteContext must be configured")
}

// ===========================================================================
// Importer
// ===========================================================================

func TestResourceEaaApplication_Importer(t *testing.T) {
	r := resourceEaaApplication()

	require.NotNil(t, r.Importer, "Importer must be configured")
	assert.NotNil(t, r.Importer.StateContext, "StateContext must be configured")
}

// ===========================================================================
// Protocol validation
// ===========================================================================

func TestResourceEaaApplication_ProtocolValidation(t *testing.T) {
	r := resourceEaaApplication()
	vf := r.Schema["protocol"].ValidateFunc
	require.NotNil(t, vf, "protocol must have ValidateFunc")

	testValidateFunc(t, vf, "protocol", map[string]validateFuncCase{
		"valid_SAML":          {val: "SAML"},
		"valid_SAML2.0":       {val: "SAML2.0"},
		"valid_OIDC":          {val: "OIDC"},
		"valid_OpenIDConnect": {val: "OpenID Connect 1.0"},
		"valid_WSFed":         {val: "WSFed"},
		"valid_WS-Federation": {val: "WS-Federation"},
		"invalid_unknown":     {val: "unknown", wantErr: true},
		"invalid_empty":       {val: "", wantErr: true},
	})
}

// ===========================================================================
// Helper functions
// ===========================================================================

func TestConvertStringToInt(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected int
	}{
		"valid_number":  {input: "123", expected: 123},
		"zero":          {input: "0", expected: 0},
		"empty_string":  {input: "", expected: 0},
		"invalid_input": {input: "invalid", expected: 0},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := convertStringToInt(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStringPointerValue(t *testing.T) {
	t.Run("non_nil", func(t *testing.T) {
		s := "test"
		result := stringPointerValue(&s)
		assert.Equal(t, "test", result)
	})

	t.Run("empty_string", func(t *testing.T) {
		s := ""
		result := stringPointerValue(&s)
		assert.Equal(t, "", result)
	})

	t.Run("nil", func(t *testing.T) {
		result := stringPointerValue(nil)
		assert.Nil(t, result)
	})
}

// ===========================================================================
// validateAppAuthValue
// ===========================================================================

func TestValidateAppAuthValue(t *testing.T) {
	tests := map[string]struct {
		appAuth string
		wantErr bool
	}{
		"valid_none":    {appAuth: "none", wantErr: false},
		"valid_saml":    {appAuth: "saml", wantErr: false},
		"valid_oidc":    {appAuth: "oidc", wantErr: false},
		"valid_wsfed":   {appAuth: "wsfed", wantErr: false},
		"invalid_value": {appAuth: "invalid", wantErr: true},
		"empty_value":   {appAuth: "", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateAppAuthValue(tc.appAuth)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ===========================================================================
// validateWappAuthValue
// ===========================================================================

func TestValidateWappAuthValue(t *testing.T) {
	tests := map[string]struct {
		wappAuth string
		wantErr  bool
	}{
		"valid_basic":   {wappAuth: "basic", wantErr: false},
		"valid_none":    {wappAuth: "none", wantErr: false},
		"invalid_form":  {wappAuth: "form", wantErr: true},
		"invalid_value": {wappAuth: "invalid", wantErr: true},
		"empty_value":   {wappAuth: "", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateWappAuthValue(tc.wappAuth)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ===========================================================================
// validateAuthenticationMethodsForAppType
// ===========================================================================

func TestValidateAuthenticationMethodsForAppType(t *testing.T) {
	tests := map[string]struct {
		appType string
		saml    bool
		oidc    bool
		wsfed   bool
		wantErr bool
	}{
		"tunnel_saml_fails":       {appType: "tunnel", saml: true, wantErr: true},
		"tunnel_oidc_fails":       {appType: "tunnel", oidc: true, wantErr: true},
		"tunnel_wsfed_fails":      {appType: "tunnel", wsfed: true, wantErr: true},
		"tunnel_no_auth_passes":   {appType: "tunnel", wantErr: false},
		"enterprise_saml_passes":  {appType: "enterprise", saml: true, wantErr: false},
		"enterprise_oidc_passes":  {appType: "enterprise", oidc: true, wantErr: false},
		"enterprise_wsfed_passes": {appType: "enterprise", wsfed: true, wantErr: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resourceSchema := resourceEaaApplication().Schema
			resourceData := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
				"app_type": tc.appType,
				"saml":     tc.saml,
				"oidc":     tc.oidc,
				"wsfed":    tc.wsfed,
			})

			err := validateAuthenticationMethodsForAppType(resourceData)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ===========================================================================
// validateAppAuthValue via advanced_settings JSON
// ===========================================================================

func TestAppAuthInAdvancedSettings(t *testing.T) {
	tests := map[string]struct {
		advancedSettings string
		wantErr          bool
	}{
		"saml_enterprise":  {advancedSettings: `{"app_auth": "saml"}`, wantErr: false},
		"oidc_enterprise":  {advancedSettings: `{"app_auth": "oidc"}`, wantErr: false},
		"wsfed_enterprise": {advancedSettings: `{"app_auth": "wsfed"}`, wantErr: false},
		"saml_tunnel":      {advancedSettings: `{"app_auth": "saml"}`, wantErr: false},
		"invalid_method":   {advancedSettings: `{"app_auth": "invalid_method"}`, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var settings map[string]interface{}
			err := json.Unmarshal([]byte(tc.advancedSettings), &settings)
			require.NoError(t, err)

			appAuth, exists := settings["app_auth"]
			require.True(t, exists, "app_auth key must exist in test data")
			appAuthStr, ok := appAuth.(string)
			require.True(t, ok, "app_auth must be a string")

			err = validateAppAuthValue(appAuthStr)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ===========================================================================
// CRUD with mocked API
// ===========================================================================

func TestResourceEaaApplicationCRUDWithMockedAPI(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-uuid-123"

	t.Run("READ_Success", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)

		readPattern := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)
		mockTransport.Responses[readPattern] = MockResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"uuid_url":    appID,
				"name":        "test-read-app",
				"app_type":    1,
				"app_profile": 1,
				"host":        "read.example.com",
				"description": "Test application for read",
			},
		}

		servicesPattern := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)
		mockTransport.Responses[servicesPattern] = MockResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"objects": []map[string]interface{}{
					{
						"service": map[string]interface{}{
							"service_type": 6,
							"uuid_url":     "service-uuid-123",
						},
						"status":   1,
						"uuid_url": "service-data-uuid-123",
					},
				},
			},
		}

		agentsPattern := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)
		mockTransport.Responses[agentsPattern] = MockResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"objects": []map[string]interface{}{},
			},
		}

		rulesPattern := "GET /crux/v1/mgmt-pop/services/service-uuid-123/rules"
		mockTransport.Responses[rulesPattern] = MockResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"objects": []map[string]interface{}{},
			},
		}

		d := createTestApplicationResourceData(t, map[string]interface{}{})
		d.SetId(appID)

		diags := resourceEaaApplicationRead(ctx, d, mockClient)

		assert.Empty(t, diags, "Read should succeed with mocked response")
		assert.Equal(t, "test-read-app", d.Get("name"))
	})

	t.Run("READ_NotFound", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)

		readPattern := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)
		mockTransport.Responses[readPattern] = MockResponse{
			StatusCode: 404,
			Body: map[string]interface{}{
				"type":   "error",
				"title":  "Not Found",
				"detail": "Application not found",
			},
		}

		d := createTestApplicationResourceData(t, map[string]interface{}{})
		d.SetId(appID)

		diags := resourceEaaApplicationRead(ctx, d, mockClient)
		assert.NotEmpty(t, diags, "Expected error diagnostics for 404")
	})

	t.Run("DELETE_Success", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)

		getPattern := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)
		mockTransport.Responses[getPattern] = MockResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"uuid_url":    appID,
				"name":        "test-delete-app",
				"app_type":    1,
				"app_profile": 1,
			},
		}

		deletePattern := fmt.Sprintf("DELETE /crux/v1/mgmt-pop/apps/%s", appID)
		mockTransport.Responses[deletePattern] = MockResponse{
			StatusCode: 200,
			Body:       map[string]interface{}{"status": "deleted"},
		}

		d := createTestApplicationResourceData(t, map[string]interface{}{})
		d.SetId(appID)

		diags := resourceEaaApplicationDelete(ctx, d, mockClient)

		assert.False(t, diags.HasError(), "Delete should not have error diagnostics")
		assert.Equal(t, "", d.Id(), "ID should be cleared after delete")
	})
}

// ===========================================================================
// Create with validation (nil client)
// ===========================================================================

func TestResourceEaaApplicationCreateWithValidation(t *testing.T) {
	tests := map[string]struct {
		resourceData map[string]interface{}
	}{
		"basic_enterprise_app": {
			resourceData: map[string]interface{}{
				"name":        "test-app",
				"app_type":    "enterprise",
				"app_profile": "http",
				"host":        "test.example.com",
			},
		},
		"tunnel_app": {
			resourceData: map[string]interface{}{
				"name":        "test-tunnel",
				"app_type":    "tunnel",
				"app_profile": "tcp",
				"host":        "tunnel.example.com",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestApplicationResourceData(t, tc.resourceData)

			// Nil client will cause an error; this validates the function doesn't panic
			diags := resourceEaaApplicationCreateTwoPhase(context.Background(), d, nil)
			assert.NotEmpty(t, diags, "Expected error with nil client")
		})
	}
}

// ===========================================================================
// suppressServerComputedAdvSettingsKey
// ===========================================================================

func TestSuppressServerComputedAdvSettingsKey(t *testing.T) {
	tests := map[string]struct {
		key      string
		oldVal   string
		newVal   string
		suppress bool
	}{
		"server_computed_key_empty_new": {
			key: "advanced_settings.g2o_key", oldVal: "somevalue", newVal: "", suppress: true,
		},
		"server_computed_key_has_new_value": {
			key: "advanced_settings.g2o_key", oldVal: "old", newVal: "new", suppress: false,
		},
		"json_field_semantically_equal": {
			key:      "advanced_settings.custom_headers",
			oldVal:   `{"a":"1","b":"2"}`,
			newVal:   `{"b":"2","a":"1"}`,
			suppress: true,
		},
		"json_field_different": {
			key:      "advanced_settings.custom_headers",
			oldVal:   `{"a":"1"}`,
			newVal:   `{"a":"2"}`,
			suppress: false,
		},
		"regular_key_not_suppressed": {
			key: "advanced_settings.acceleration", oldVal: "true", newVal: "false", suppress: false,
		},
		"percent_key_not_suppressed": {
			key: "advanced_settings.%", oldVal: "5", newVal: "6", suppress: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := suppressServerComputedAdvSettingsKey(tc.key, tc.oldVal, tc.newVal, nil)
			assert.Equal(t, tc.suppress, result)
		})
	}
}

// ===========================================================================
// jsonSemanticEqual
// ===========================================================================

func TestJsonSemanticEqual(t *testing.T) {
	tests := map[string]struct {
		a     string
		b     string
		equal bool
	}{
		"identical":      {a: `{"x":1}`, b: `{"x":1}`, equal: true},
		"reordered_keys": {a: `{"a":1,"b":2}`, b: `{"b":2,"a":1}`, equal: true},
		"different":      {a: `{"a":1}`, b: `{"a":2}`, equal: false},
		"invalid_a":      {a: `not json`, b: `{"a":1}`, equal: false},
		"invalid_b":      {a: `{"a":1}`, b: `not json`, equal: false},
		"both_invalid":   {a: `x`, b: `y`, equal: false},
		"same_string":    {a: "hello", b: "hello", equal: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.equal, jsonSemanticEqual(tc.a, tc.b))
		})
	}
}

// ===========================================================================
// Mock infrastructure (shared across tests)
// ===========================================================================

// MockSigner is a no-op signer for testing
type MockSigner struct{}

func (m *MockSigner) SignRequest(req *http.Request) {}

func (m *MockSigner) CheckRequestLimit(requestLimit int) {}

// MockResponse holds mock response data
type MockResponse struct {
	Body       interface{}
	Header     http.Header
	StatusCode int
}

// MockHTTPTransport is a custom HTTP transport for testing
type MockHTTPTransport struct {
	t         *testing.T
	Responses map[string]MockResponse
}

func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	method := req.Method

	if resp, ok := m.Responses[url]; ok {
		return m.createHTTPResponse(req, resp)
	}

	methodPattern := fmt.Sprintf("%s %s", method, req.URL.Path)
	if resp, ok := m.Responses[methodPattern]; ok {
		return m.createHTTPResponse(req, resp)
	}

	m.t.Errorf("unregistered mock route: %s %s", method, req.URL)
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "404 Not Found",
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (m *MockHTTPTransport) createHTTPResponse(req *http.Request, mockResp MockResponse) (*http.Response, error) {
	var bodyBytes []byte

	if mockResp.Body != nil {
		var err error
		bodyBytes, err = json.Marshal(mockResp.Body)
		require.NoError(m.t, err, "failed to marshal mock response body")
	}

	header := mockResp.Header
	if header == nil {
		header = make(http.Header)
	}

	return &http.Response{
		StatusCode: mockResp.StatusCode,
		Status:     http.StatusText(mockResp.StatusCode),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Header:     header,
		Request:    req,
	}, nil
}

func createMockClient(t *testing.T) (*client.EaaClient, *MockHTTPTransport) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Info,
		Output: io.Discard,
	})

	mockTransport := &MockHTTPTransport{
		t:         t,
		Responses: make(map[string]MockResponse),
	}

	mockHTTPClient := &http.Client{
		Transport: mockTransport,
	}

	return &client.EaaClient{
		ContractID: "test-contract",
		Client:     mockHTTPClient,
		Signer:     &MockSigner{},
		Host:       "test.example.com",
		Logger:     logger,
	}, mockTransport
}

func createTestApplicationResourceData(t *testing.T, data map[string]interface{}) *schema.ResourceData {
	t.Helper()
	resource := resourceEaaApplication()
	d := resource.Data(nil)
	for key, value := range data {
		require.NoError(t, d.Set(key, value), "failed to set %q", key)
	}
	return d
}

func stringPtr(s string) *string {
	return &s
}
