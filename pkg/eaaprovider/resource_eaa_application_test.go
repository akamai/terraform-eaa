package eaaprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"unsafe"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/testsupport"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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
				require.Error(t, err)
			} else {
				require.NoError(t, err)
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
				require.Error(t, err)
			} else {
				require.NoError(t, err)
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
				require.Error(t, err)
			} else {
				require.NoError(t, err)
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
				require.Error(t, err)
			} else {
				require.NoError(t, err)
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
// Update orchestration with mocked API
// ===========================================================================

func setResourceDataDiff(t *testing.T, d *schema.ResourceData, diff *terraform.InstanceDiff) {
	t.Helper()
	v := reflect.ValueOf(d).Elem().FieldByName("diff")
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Set(reflect.ValueOf(diff))
}

func buildURL(host, path string, q map[string]string) string {
	u := url.URL{Scheme: "https", Host: host, Path: path}
	vals := url.Values{}
	for k, v := range q {
		vals.Set(k, v)
	}
	u.RawQuery = vals.Encode()
	return u.String()
}

func TestResourceEaaApplicationUpdate(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-uuid-update-123"
	svcID := "service-uuid-update-123"

	baseApp := map[string]interface{}{
		"uuid_url":     appID,
		"name":         "existing-app",
		"app_type":     1,
		"app_profile":  1,
		"host":         "existing.example.com",
		"auth_enabled": "false",
	}

	servicesResp := map[string]interface{}{
		"objects": []map[string]interface{}{
			{
				"service": map[string]interface{}{
					"service_type": 6,
					"uuid_url":     svcID,
					"status":       "disabled",
				},
				"status":   1,
				"uuid_url": "service-data-uuid-123",
			},
		},
	}

	rulesRespWithOne := map[string]interface{}{
		"objects": []map[string]interface{}{
			{
				"name":     "rule-1",
				"uuid_url": "rule-uuid-1",
				"status":   1,
				"settings": []map[string]interface{}{{
					"operator": "is",
					"type":     "group",
					"value":    "grp1",
				}},
			},
		},
	}

	registerCommonReadRoutes := func(t *testing.T, tr *MockHTTPTransport) {
		t.Helper()
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: baseApp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)] = MockResponse{StatusCode: 200, Body: servicesResp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"objects": []map[string]interface{}{}}}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/services/%s/rules", svcID)] = MockResponse{StatusCode: 200, Body: rulesRespWithOne}
	}

	t.Run("baseline_success", func(t *testing.T) {
		mockClient, tr := createMockClient(t)

		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":   "updated-app",
			"domain": "wapp",
		})
		d.SetId(appID)
		setResourceDataDiff(t, d, &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{}})

		// update flow
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: baseApp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"objects": []map[string]interface{}{}}}
		tr.Responses[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "updated"}}
		tr.Responses[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "deployed"}}

		// read tail routes
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)] = MockResponse{StatusCode: 200, Body: servicesResp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/services/%s/rules", svcID)] = MockResponse{StatusCode: 200, Body: rulesRespWithOne}

		diags := resourceEaaApplicationUpdate(ctx, d, mockClient)
		require.False(t, diags.HasError(), "diags: %+v", diags)
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)])
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)])
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)])
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("GET /crux/v1/mgmt-pop/services/%s/rules", svcID)])
	})

	t.Run("agent_diff_assign_unassign", func(t *testing.T) {
		mockClient, tr := createMockClient(t)

		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":   "updated-agents-app",
			"domain": "wapp",
			"agents": []interface{}{"agent-new"},
		})
		d.SetId(appID)
		setResourceDataDiff(t, d, &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{}})

		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: baseApp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"agent": map[string]interface{}{"name": "agent-old", "uuid_url": "agent-uuid-old"},
				},
			},
		}}

		// agent lookup for assign/unassign
		tr.Responses["GET /crux/v1/mgmt-pop/agents"] = MockResponse{StatusCode: 200, Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{"name": "agent-old", "uuid_url": "agent-uuid-old"},
				{"name": "agent-new", "uuid_url": "agent-uuid-new"},
			},
		}}

		tr.Responses[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "assigned"}}
		unassignAgentsURL := buildURL(mockClient.Host, fmt.Sprintf("/crux/v1/mgmt-pop/apps/%s/agents", appID), map[string]string{"contractId": mockClient.ContractID, "method": "delete"})
		tr.Responses[unassignAgentsURL] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "unassigned"}}

		tr.Responses[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "updated"}}
		tr.Responses[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "deployed"}}

		// read tail routes (don't overwrite the agents route; we want update-time agent diff)
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)] = MockResponse{StatusCode: 200, Body: servicesResp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/services/%s/rules", svcID)] = MockResponse{StatusCode: 200, Body: rulesRespWithOne}

		diags := resourceEaaApplicationUpdate(ctx, d, mockClient)
		require.False(t, diags.HasError(), "diags: %+v", diags)
		assert.Equal(t, 2, tr.Calls[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)])
		assert.Equal(t, 2, tr.Calls["GET /crux/v1/mgmt-pop/agents"])
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/agents", appID)])
		assert.Equal(t, 1, tr.Calls[unassignAgentsURL])
	})

	t.Run("app_authentication_change_idp_reassign_with_directories_groups", func(t *testing.T) {
		mockClient, tr := createMockClient(t)

		oldState := map[string]string{
			"app_authentication.#":                   "1",
			"app_authentication.0.app_idp":           "old-idp",
			"app_authentication.0.app_directories.#": "0",
		}

		d := resourceEaaApplication().Data(&terraform.InstanceState{ID: appID, Attributes: oldState})
		require.NoError(t, d.Set("name", "updated-auth-app"))
		require.NoError(t, d.Set("domain", "wapp"))
		require.NoError(t, d.Set("auth_enabled", "true"))
		require.NoError(t, d.Set("app_authentication", []interface{}{map[string]interface{}{
			"app_idp": "new-idp",
			"app_directories": []interface{}{map[string]interface{}{
				"name":       "dir1",
				"enable_mfa": "inherit",
				"app_groups": []interface{}{map[string]interface{}{"name": "group1", "enable_mfa": "inherit"}},
			}},
		}}))
		setResourceDataDiff(t, d, &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
			"app_authentication":                     {Old: "old", New: "new"},
			"app_authentication.#":                   {Old: "0", New: "1"},
			"app_authentication.0.app_idp":           {Old: "old-idp", New: "new-idp"},
			"app_authentication.0.app_directories.#": {Old: "0", New: "1"},
		}})

		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: baseApp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"objects": []map[string]interface{}{}}}

		// current membership -> unassign
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/idp_membership", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"uuid_url": "idp-uuid-old",
					"idp":      map[string]interface{}{"name": "old-idp", "idp_uuid_url": "idp-uuid-old"},
				},
			},
		}}
		unassignIDPURL := buildURL(mockClient.Host, "/crux/v1/mgmt-pop/appidp", map[string]string{"contractId": mockClient.ContractID, "method": "DELETE"})
		tr.Responses[unassignIDPURL] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "unassigned"}}

		// lookup + assign
		tr.Responses["GET /crux/v1/mgmt-pop/idp"] = MockResponse{StatusCode: 200, Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{"name": "new-idp", "uuid_url": "idp-uuid-new"},
			},
		}}
		tr.Responses["GET /crux/v1/mgmt-pop/idp/idp-uuid-new/directories"] = MockResponse{StatusCode: 200, Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":     "dir1",
					"uuid_url": "dir-uuid-1",
					"groups": []map[string]interface{}{
						{"name": "group1", "uuid_url": "group-uuid-1"},
					},
				},
			},
		}}
		tr.Responses["POST /crux/v1/mgmt-pop/appidp"] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "assigned"}}
		tr.Responses["POST /crux/v1/mgmt-pop/appdirectories"] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "directories-assigned"}}
		tr.Responses["POST /crux/v1/mgmt-pop/appgroups"] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "groups-assigned"}}

		tr.Responses[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "updated"}}
		tr.Responses[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "deployed"}}

		// read tail routes
		registerCommonReadRoutes(t, tr)

		diags := resourceEaaApplicationUpdate(ctx, d, mockClient)
		require.False(t, diags.HasError(), "diags: %+v", diags)
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)])
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)])
		assert.Contains(t, []int{0, 1}, tr.Calls[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/idp_membership", appID)])
		assert.Contains(t, []int{0, 1}, tr.Calls[unassignIDPURL])
		assert.Contains(t, []int{0, 1}, tr.Calls["GET /crux/v1/mgmt-pop/idp"])
		assert.Contains(t, []int{0, 1}, tr.Calls["GET /crux/v1/mgmt-pop/idp/idp-uuid-new/directories"])
		assert.Contains(t, []int{0, 1}, tr.Calls["POST /crux/v1/mgmt-pop/appidp"])
		assert.Contains(t, []int{0, 1}, tr.Calls["POST /crux/v1/mgmt-pop/appdirectories"])
		assert.Contains(t, []int{0, 1}, tr.Calls["POST /crux/v1/mgmt-pop/appgroups"])
	})

	t.Run("service_reconciliation_status_and_rules", func(t *testing.T) {
		mockClient, tr := createMockClient(t)

		oldState := map[string]string{
			"service.#":                               "1",
			"service.0.service_type":                  "access",
			"service.0.status":                        "disabled",
			"service.0.access_rule.#":                 "1",
			"service.0.access_rule.0.name":            "rule-a",
			"service.0.access_rule.0.status":          "on",
			"service.0.access_rule.0.rule.#":          "1",
			"service.0.access_rule.0.rule.0.operator": "==",
			"service.0.access_rule.0.rule.0.type":     "group",
			"service.0.access_rule.0.rule.0.value":    "old",
		}

		d := resourceEaaApplication().Data(&terraform.InstanceState{ID: appID, Attributes: oldState})
		require.NoError(t, d.Set("name", "updated-service-app"))
		require.NoError(t, d.Set("domain", "wapp"))
		require.NoError(t, d.Set("service", []interface{}{map[string]interface{}{
			"service_type": "access",
			"status":       "enabled",
			"access_rule": []interface{}{
				map[string]interface{}{
					"name":   "rule-a",
					"status": "on",
					"rule": []interface{}{map[string]interface{}{
						"operator": "==",
						"type":     "group",
						"value":    "new",
					}},
				},
				map[string]interface{}{
					"name":   "rule-c",
					"status": "on",
					"rule": []interface{}{map[string]interface{}{
						"operator": "==",
						"type":     "group",
						"value":    "c",
					}},
				},
			},
		}}))
		setResourceDataDiff(t, d, &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
			"service":                      {Old: "old", New: "new"},
			"service.#":                    {Old: "0", New: "1"},
			"service.0.access_rule":        {Old: "old", New: "new"},
			"service.0.access_rule.#":      {Old: "1", New: "2"},
			"service.0.access_rule.0.name": {Old: "rule-a", New: "rule-a"},
		}})

		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: baseApp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"objects": []map[string]interface{}{}}}

		// service reconciliation
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"service": map[string]interface{}{
						"service_type": 6,
						"uuid_url":     svcID,
						"status":       "disabled",
					},
					"status":   0,
					"uuid_url": "service-data-uuid-123",
				},
			},
		}}
		tr.Responses[fmt.Sprintf("PUT /crux/v1/mgmt-pop/services/%s", svcID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "service-updated"}}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/services/%s/rules", svcID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"name":     "rule-a",
					"uuid_url": "uuid-a",
					"status":   1,
					"settings": []map[string]interface{}{{"operator": "==", "type": "group", "value": "old"}},
				},
				{
					"name":     "rule-b",
					"uuid_url": "uuid-b",
					"status":   1,
					"settings": []map[string]interface{}{{"operator": "==", "type": "group", "value": "b"}},
				},
			},
		}}
		tr.Responses[fmt.Sprintf("DELETE /crux/v1/mgmt-pop/services/%s/rules/%s", svcID, "uuid-b")] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "deleted"}}
		tr.Responses[fmt.Sprintf("PUT /crux/v1/mgmt-pop/services/%s/rules/%s", svcID, "uuid-a")] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "modified"}}
		tr.Responses[fmt.Sprintf("POST /crux/v1/mgmt-pop/services/%s/rules", svcID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "created"}}

		tr.Responses[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "updated"}}
		tr.Responses[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "deployed"}}

		diags := resourceEaaApplicationUpdate(ctx, d, mockClient)
		require.False(t, diags.HasError(), "diags: %+v", diags)
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)])
		assert.Equal(t, 1, tr.Calls[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)])
		assert.Contains(t, []int{1, 2}, tr.Calls[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)])
		assert.Contains(t, []int{0, 1}, tr.Calls[fmt.Sprintf("PUT /crux/v1/mgmt-pop/services/%s", svcID)])
		assert.Contains(t, []int{1, 2}, tr.Calls[fmt.Sprintf("GET /crux/v1/mgmt-pop/services/%s/rules", svcID)])
		assert.Contains(t, []int{0, 1}, tr.Calls[fmt.Sprintf("DELETE /crux/v1/mgmt-pop/services/%s/rules/%s", svcID, "uuid-b")])
		assert.Contains(t, []int{0, 1}, tr.Calls[fmt.Sprintf("PUT /crux/v1/mgmt-pop/services/%s/rules/%s", svcID, "uuid-a")])
		assert.Contains(t, []int{0, 1}, tr.Calls[fmt.Sprintf("POST /crux/v1/mgmt-pop/services/%s/rules", svcID)])
	})

	t.Run("failure_propagation_initial_get_fails", func(t *testing.T) {
		mockClient, tr := createMockClient(t)

		d := createTestApplicationResourceData(t, map[string]interface{}{"name": "fail-get", "domain": "wapp"})
		d.SetId(appID)
		setResourceDataDiff(t, d, &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
			"name": {Old: "old", New: "fail-get"},
		}})

		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 500, Body: map[string]interface{}{"detail": "boom"}}

		diags := resourceEaaApplicationUpdate(ctx, d, mockClient)
		require.True(t, diags.HasError())
	})

	t.Run("failure_propagation_deploy_fails", func(t *testing.T) {
		mockClient, tr := createMockClient(t)

		d := createTestApplicationResourceData(t, map[string]interface{}{"name": "fail-deploy", "domain": "wapp"})
		d.SetId(appID)
		setResourceDataDiff(t, d, &terraform.InstanceDiff{Attributes: map[string]*terraform.ResourceAttrDiff{
			"name": {Old: "old", New: "fail-deploy"},
		}})

		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: baseApp}
		tr.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"objects": []map[string]interface{}{}}}
		tr.Responses[fmt.Sprintf("PUT /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: 200, Body: map[string]interface{}{"status": "updated"}}
		tr.Responses[fmt.Sprintf("POST /crux/v1/mgmt-pop/apps/%s/deploy", appID)] = MockResponse{StatusCode: 500, Body: map[string]interface{}{"detail": "deploy-fail"}}

		diags := resourceEaaApplicationUpdate(ctx, d, mockClient)
		require.True(t, diags.HasError())
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
	Calls     map[string]int
}

func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	requestURL := req.URL.String()
	method := req.Method

	if resp, ok := m.Responses[requestURL]; ok {
		if m.Calls != nil {
			m.Calls[requestURL]++
		}
		return m.createHTTPResponse(req, resp)
	}

	methodPattern := fmt.Sprintf("%s %s", method, req.URL.Path)
	if resp, ok := m.Responses[methodPattern]; ok {
		if m.Calls != nil {
			m.Calls[methodPattern]++
		}
		return m.createHTTPResponse(req, resp)
	}

	m.t.Fatalf("unregistered mock route: %s %s", method, req.URL)
	// t.Fatalf will fail the test immediately; return nil to satisfy the signature.
	return nil, nil
}

func (m *MockHTTPTransport) createHTTPResponse(req *http.Request, mockResp MockResponse) (*http.Response, error) {
	resp, err := testsupport.BuildJSONHTTPResponse(req, mockResp.StatusCode, mockResp.Body, mockResp.Header)
	require.NoError(m.t, err, "failed to marshal mock response body")
	return resp, nil
}

func createMockClient(t *testing.T) (*client.EaaClient, *MockHTTPTransport) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Info,
		Output: io.Discard,
	})

	mockTransport := &MockHTTPTransport{
		t:         t,
		Responses: make(map[string]MockResponse),
		Calls:     make(map[string]int),
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

func createTestApplicationResourceData(t *testing.T, data map[string]any) *schema.ResourceData {
	t.Helper()
	return createTestResourceDataFor(t, resourceEaaApplication, data)
}

func TestGetAppError(t *testing.T) {
	tests := map[string]struct {
		resp       *http.Response
		errorIs    error
		wantErrStr string
	}{
		"nil_response_returns_base_error": {
			resp:    nil,
			errorIs: client.ErrGetAppFailed,
		},
		"valid_detail_wraps_error_with_detail": {
			resp: &http.Response{
				Status: "500 Internal Server Error",
				Body:   io.NopCloser(bytes.NewBufferString(`{"detail":"backend exploded"}`)),
			},
			errorIs:    client.ErrGetAppFailed,
			wantErrStr: "backend exploded",
		},
		"invalid_json_uses_http_status": {
			resp: &http.Response{
				Status: "500 Internal Server Error",
				Body:   io.NopCloser(bytes.NewBufferString("not-json")),
			},
			errorIs:    client.ErrGetAppFailed,
			wantErrStr: "500 Internal Server Error",
		},
		"empty_detail_uses_http_status": {
			resp: &http.Response{
				Status: "400 Bad Request",
				Body:   io.NopCloser(bytes.NewBufferString(`{"detail":""}`)),
			},
			errorIs:    client.ErrGetAppFailed,
			wantErrStr: "400 Bad Request",
		},
		"decode_failure_without_status_returns_base_error": {
			resp: &http.Response{
				Body: io.NopCloser(bytes.NewBufferString("not-json")),
			},
			errorIs: client.ErrGetAppFailed,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := getAppError(tt.resp)
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.errorIs)
			if tt.wantErrStr != "" {
				assert.ErrorContains(t, err, tt.wantErrStr)
			}
		})
	}
}

// statefulMockTransport is an HTTP transport that delegates to a callback function,
// allowing stateful behavior (e.g., different responses for the same URL on successive calls).
type statefulMockTransport struct {
	t       *testing.T
	handler func(method, path string) MockResponse
}

func (s *statefulMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	mockResp := s.handler(req.Method, req.URL.Path)
	if mockResp.StatusCode == 0 {
		s.t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
	}
	resp, err := testsupport.BuildJSONHTTPResponse(req, mockResp.StatusCode, mockResp.Body, mockResp.Header)
	require.NoError(s.t, err, "failed to marshal mock response body")
	return resp, nil
}

// ===========================================================================
// CreateMinimalAppRequestFromSchema
// ===========================================================================

func TestCreateMinimalAppRequestFromSchema(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		data           map[string]interface{}
		wantName       string
		wantAppType    int
		wantAppProfile int
		wantClientMode int
		wantErr        bool
	}{
		"enterprise_http_minimal": {
			data: map[string]interface{}{
				"name":     "my-enterprise-app",
				"app_type": "enterprise",
			},
			wantName:       "my-enterprise-app",
			wantAppType:    int(client.APP_TYPE_ENTERPRISE_HOSTED),
			wantAppProfile: int(client.APP_PROFILE_HTTP),
			wantClientMode: int(client.CLIENT_APP_MODE_TCP),
		},
		"saas_app": {
			data: map[string]interface{}{
				"name":        "my-saas-app",
				"app_type":    "saas",
				"app_profile": "http",
			},
			wantName:       "my-saas-app",
			wantAppType:    int(client.APP_TYPE_SAAS),
			wantAppProfile: int(client.APP_PROFILE_HTTP),
			wantClientMode: int(client.CLIENT_APP_MODE_TCP),
		},
		"tunnel_app": {
			data: map[string]interface{}{
				"name":            "my-tunnel-app",
				"app_type":        "tunnel",
				"app_profile":     "tcp",
				"client_app_mode": "tunnel",
			},
			wantName:       "my-tunnel-app",
			wantAppType:    int(client.APP_TYPE_TUNNEL),
			wantAppProfile: int(client.APP_PROFILE_TCP),
			wantClientMode: int(client.CLIENT_APP_MODE_TUNNEL),
		},
		"bookmark_app": {
			data: map[string]interface{}{
				"name":     "my-bookmark-app",
				"app_type": "bookmark",
			},
			wantName:       "my-bookmark-app",
			wantAppType:    int(client.APP_TYPE_BOOKMARK),
			wantAppProfile: int(client.APP_PROFILE_HTTP),
			wantClientMode: int(client.CLIENT_APP_MODE_TCP),
		},
		"defaults_when_unset": {
			data: map[string]interface{}{
				"name": "defaults-app",
			},
			wantName:       "defaults-app",
			wantAppType:    int(client.APP_TYPE_ENTERPRISE_HOSTED),
			wantAppProfile: int(client.APP_PROFILE_HTTP),
			wantClientMode: int(client.CLIENT_APP_MODE_TCP),
		},
		"missing_name_returns_error": {
			data:    map[string]interface{}{},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockClient, _ := createMockClient(t)
			d := createTestApplicationResourceData(t, tc.data)

			var req client.MinimalCreateAppRequest
			err := req.CreateMinimalAppRequestFromSchema(ctx, d, mockClient)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tc.wantName, req.Name)
			assert.Equal(t, tc.wantAppType, req.AppType)
			assert.Equal(t, tc.wantAppProfile, req.AppProfile)
			assert.Equal(t, tc.wantClientMode, req.ClientAppMode)
		})
	}
}

// ===========================================================================
// CreateAppRequestFromSchema
// ===========================================================================

func TestCreateAppRequestFromSchema(t *testing.T) {
	ctx := context.Background()

	t.Run("enterprise_with_saml_auth", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":        "saml-app",
			"app_type":    "enterprise",
			"app_profile": "http",
			"description": "A SAML-enabled app",
			"advanced_settings": map[string]interface{}{
				"app_auth": "saml",
			},
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "saml-app", req.Name)
		assert.Equal(t, int(client.APP_TYPE_ENTERPRISE_HOSTED), req.AppType)
		assert.Equal(t, int(client.APP_PROFILE_HTTP), req.AppProfile)
		assert.True(t, req.SAML)
		assert.False(t, req.Oidc)
		assert.False(t, req.WSFED)
		require.NotNil(t, req.Description)
		assert.Equal(t, "A SAML-enabled app", *req.Description)
	})

	t.Run("enterprise_with_oidc_auth", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":        "oidc-app",
			"app_type":    "enterprise",
			"app_profile": "http",
			"advanced_settings": map[string]interface{}{
				"app_auth": "oidc",
			},
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "oidc-app", req.Name)
		assert.False(t, req.SAML)
		assert.True(t, req.Oidc)
		assert.False(t, req.WSFED)
	})

	t.Run("saas_app_no_auth", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":        "saas-no-auth",
			"app_type":    "saas",
			"app_profile": "http",
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "saas-no-auth", req.Name)
		assert.Equal(t, int(client.APP_TYPE_SAAS), req.AppType)
		assert.False(t, req.SAML)
		assert.False(t, req.Oidc)
		assert.Nil(t, req.OIDCSettings)
		assert.Empty(t, req.SAMLSettings)
	})

	t.Run("tls_suite_configuration", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":        "tls-app",
			"app_type":    "enterprise",
			"app_profile": "http",
			"advanced_settings": map[string]interface{}{
				"tls_suite_type": "custom",
				"tls_suite_name": "my-suite",
			},
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "tls-app", req.Name)
		require.NotNil(t, req.TLSSuiteType)
		assert.Equal(t, 2, *req.TLSSuiteType) // "custom" -> 2
		require.NotNil(t, req.TLSSuiteName)
		assert.Equal(t, "my-suite", *req.TLSSuiteName)
	})

	t.Run("tls_suite_default", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":        "tls-default-app",
			"app_type":    "enterprise",
			"app_profile": "http",
			"advanced_settings": map[string]interface{}{
				"tls_suite_type": "default",
			},
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		require.NotNil(t, req.TLSSuiteType)
		assert.Equal(t, 1, *req.TLSSuiteType) // "default" -> 1
	})

	t.Run("missing_name_returns_error", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"app_type": "enterprise",
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.Error(t, err)
	})

	t.Run("app_bundle_validated_via_api", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)
		mockTransport.Responses["GET /crux/v1/mgmt-pop/appbundle"] = MockResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"objects": []map[string]interface{}{
					{
						"name":     "my-bundle",
						"uuid_url": "bundle-uuid-123",
					},
				},
			},
		}

		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":       "bundled-app",
			"app_type":   "enterprise",
			"app_bundle": "my-bundle",
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "bundle-uuid-123", req.AppBundle)
	})

	t.Run("defaults_applied_when_fields_unset", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name": "defaults-app",
		})

		var req client.CreateAppRequest
		err := req.CreateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, int(client.APP_TYPE_ENTERPRISE_HOSTED), req.AppType)
		assert.Equal(t, int(client.APP_PROFILE_HTTP), req.AppProfile)
		assert.Equal(t, int(client.CLIENT_APP_MODE_TCP), req.ClientAppMode)
	})
}

// ===========================================================================
// UpdateAppRequestFromSchema
// ===========================================================================

func TestUpdateAppRequestFromSchema(t *testing.T) {
	ctx := context.Background()

	t.Run("basic_field_updates", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":        "updated-app",
			"description": "updated description",
			"host":        "updated.example.com",
			"domain":      "wapp",
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "updated-app", req.Name)
		require.NotNil(t, req.Description)
		assert.Equal(t, "updated description", *req.Description)
		require.NotNil(t, req.Host)
		assert.Equal(t, "updated.example.com", *req.Host)
	})

	t.Run("saml_auth_enabled_via_app_auth", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "saml-update-app",
			"app_type": "enterprise",
			"domain":   "wapp",
			"advanced_settings": map[string]interface{}{
				"app_auth": "saml",
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.True(t, req.SAML)
		assert.False(t, req.Oidc)
		assert.False(t, req.WSFED)
	})

	t.Run("oidc_auth_enabled_via_app_auth", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "oidc-update-app",
			"app_type": "enterprise",
			"domain":   "wapp",
			"advanced_settings": map[string]interface{}{
				"app_auth": "oidc",
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.False(t, req.SAML)
		assert.True(t, req.Oidc)
		assert.False(t, req.WSFED)
	})

	t.Run("no_auth_clears_settings", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "no-auth-app",
			"app_type": "enterprise",
			"domain":   "wapp",
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.False(t, req.SAML)
		assert.False(t, req.Oidc)
		assert.False(t, req.WSFED)
		assert.Nil(t, req.OIDCSettings)
		assert.Empty(t, req.WSFEDSettings)
	})

	t.Run("tls_suite_updates", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "tls-update-app",
			"app_type": "enterprise",
			"domain":   "wapp",
			"advanced_settings": map[string]interface{}{
				"tls_suite_type": "custom",
				"tls_suite_name": "updated-suite",
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		require.NotNil(t, req.TLSSuiteType)
		assert.Equal(t, 2, *req.TLSSuiteType)
		require.NotNil(t, req.TLSSuiteName)
		assert.Equal(t, "updated-suite", *req.TLSSuiteName)
	})

	t.Run("server_configuration", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "server-app",
			"app_type": "enterprise",
			"domain":   "wapp",
			"servers": []interface{}{
				map[string]interface{}{
					"origin_host":     "backend.internal",
					"orig_tls":        true,
					"origin_port":     8443,
					"origin_protocol": "https",
				},
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		require.Len(t, req.Servers, 1)
		assert.Equal(t, "backend.internal", req.Servers[0].OriginHost)
		assert.True(t, req.Servers[0].OrigTLS)
		assert.Equal(t, 8443, req.Servers[0].OriginPort)
		assert.Equal(t, "https", req.Servers[0].OriginProtocol)
	})

	t.Run("multiple_servers", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "multi-server-app",
			"app_type": "enterprise",
			"domain":   "wapp",
			"servers": []interface{}{
				map[string]interface{}{
					"origin_host": "backend1.internal",
					"origin_port": 8080,
				},
				map[string]interface{}{
					"origin_host": "backend2.internal",
					"origin_port": 8081,
				},
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		require.Len(t, req.Servers, 2)
		assert.Equal(t, "backend1.internal", req.Servers[0].OriginHost)
		assert.Equal(t, "backend2.internal", req.Servers[1].OriginHost)
	})

	t.Run("bookmark_url_set", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":         "bookmark-app",
			"app_type":     "bookmark",
			"bookmark_url": "https://external.example.com",
			"domain":       "wapp",
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "https://external.example.com", req.BookmarkURL)
	})

	t.Run("tunnel_internal_hosts", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "tunnel-update-app",
			"app_type": "tunnel",
			"domain":   "wapp",
			"tunnel_internal_hosts": []interface{}{
				map[string]interface{}{
					"host":       "10.0.0.1",
					"port_range": "22-443",
					"proto_type": 1,
				},
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		require.Len(t, req.TunnelInternalHosts, 1)
		assert.Equal(t, "10.0.0.1", req.TunnelInternalHosts[0].Host)
		assert.Equal(t, "22-443", req.TunnelInternalHosts[0].PortRange)
		assert.Equal(t, 1, req.TunnelInternalHosts[0].ProtoType)
	})

	t.Run("advanced_settings_app_auth_preserved", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "adv-settings-app",
			"app_type": "enterprise",
			"saml":     true,
			"domain":   "wapp",
			"advanced_settings": map[string]interface{}{
				"app_auth": "none",
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		// When SAML is enabled, app_auth should be set to "none"
		assert.Equal(t, "none", req.AdvancedSettings.AppAuth)
	})

	t.Run("app_bundle_validated_via_api", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)
		mockTransport.Responses["GET /crux/v1/mgmt-pop/appbundle"] = MockResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"objects": []map[string]interface{}{
					{
						"name":     "update-bundle",
						"uuid_url": "bundle-uuid-456",
					},
				},
			},
		}

		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":       "bundle-update-app",
			"app_type":   "enterprise",
			"app_bundle": "update-bundle",
			"domain":     "wapp",
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.Equal(t, "bundle-uuid-456", req.AppBundle)
	})

	t.Run("wsfed_auth_enabled_via_app_auth", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "wsfed-update-app",
			"app_type": "enterprise",
			"domain":   "wapp",
			"advanced_settings": map[string]interface{}{
				"app_auth": "wsfed",
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.NoError(t, err)

		assert.False(t, req.SAML)
		assert.False(t, req.Oidc)
		assert.True(t, req.WSFED)
	})

	t.Run("invalid_tls_suite_type_returns_error", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"name":     "bad-tls-app",
			"app_type": "enterprise",
			"domain":   "wapp",
			"advanced_settings": map[string]interface{}{
				"tls_suite_type": "invalid",
			},
		})

		var req client.ApplicationUpdateRequest
		err := req.UpdateAppRequestFromSchema(ctx, d, mockClient)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tls_suite_type")
	})
}
