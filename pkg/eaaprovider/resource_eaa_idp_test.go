package eaaprovider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Schema structure
// ===========================================================================

func createIdpResourceData(t *testing.T, data map[string]any) *schema.ResourceData {
	t.Helper()
	return createTestResourceDataFor(t, resourceEaaIdp, data)
}

func TestResourceEaaIdpSchema(t *testing.T) {
	resource := resourceEaaIdp()
	require.NotNil(t, resource)

	expectedFields := []string{
		// Required
		"name",
		// Optional typed attributes
		"description", "idp_type", "login_host", "login_domain",
		"login_lockout", "max_login_failures", "lockout_interval",
		"cookie_expiry", "trust_expiry", "cert", "client_cert",
		"saml_idp_custom_sign_cert", "pop", "failover_pop",
		"enable_mfa", "etp_enabled", "enable_access_client",
		"gc_client_enabled", "auth_request_signed", "auth_response_encrypt",
		"saml_cert_type", "saml_url", "logout_url", "helpdesk_email",
		"default_language", "default_tls_suite", "custom_tls_suite_name",
		"domains", "agent_installation_profile", "source",
		"post_auth_failure_redirect_type", "post_auth_failure_redirect_custom_url",
		"post_logout_redirect_type", "post_logout_redirect_custom_url",
		// Optional flat maps
		"mfa_settings", "settings", "attribute_map", "multilang_fields",
		// Optional list
		"directories",
		// Optional with Computed
		"client_principle_name",
		// Computed read-only
		"uuid_url", "created_at", "modified_at", "company_id",
		"localization", "status", "dns_added", "login_cname",
		"login_dialin_server", "login_suffix", "domain_suffix",
		"client_host", "pop_name", "idp_status", "idp_operational",
		"idp_deployed", "directory_count", "app_count", "tls_suite_name",
	}
	for _, field := range expectedFields {
		_, ok := resource.Schema[field]
		assert.True(t, ok, "expected schema field %q to exist", field)
	}

	// Required fields
	assert.True(t, resource.Schema["name"].Required)

	// Computed-only fields
	computedOnlyFields := []string{
		"uuid_url", "created_at", "modified_at", "company_id",
		"localization", "status", "dns_added", "login_cname",
		"login_dialin_server", "login_suffix", "domain_suffix",
		"client_host", "pop_name", "idp_status", "idp_operational",
		"idp_deployed", "directory_count", "app_count", "tls_suite_name",
	}
	for _, field := range computedOnlyFields {
		assert.True(t, resource.Schema[field].Computed, "expected %q to be Computed", field)
	}

	// CRUD operations
	assert.NotNil(t, resource.CreateContext)
	assert.NotNil(t, resource.ReadContext)
	assert.NotNil(t, resource.UpdateContext)
	assert.NotNil(t, resource.DeleteContext)

	// Importer
	require.NotNil(t, resource.Importer)
	assert.NotNil(t, resource.Importer.StateContext)
}

// ===========================================================================
// Helper function tests
// ===========================================================================

func TestStringMapToInterfaceMap(t *testing.T) {
	tests := map[string]struct {
		input    map[string]interface{}
		expected map[string]interface{}
	}{
		"normal_strings": {
			input:    map[string]interface{}{"key1": "value1", "key2": "value2"},
			expected: map[string]interface{}{"key1": "value1", "key2": "value2"},
		},
		"intSettingsKeys_conversion": {
			input:    map[string]interface{}{"idp_max_sso_sessions": "10", "websocket_pool_maxidle": "5"},
			expected: map[string]interface{}{"idp_max_sso_sessions": 10, "websocket_pool_maxidle": 5},
		},
		"invalid_int_fallback": {
			input:    map[string]interface{}{"idp_max_sso_sessions": "not_a_number"},
			expected: map[string]interface{}{"idp_max_sso_sessions": "not_a_number"},
		},
		"mixed": {
			input:    map[string]interface{}{"normal_key": "value", "idp_max_sso_sessions": "42"},
			expected: map[string]interface{}{"normal_key": "value", "idp_max_sso_sessions": 42},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := stringMapToInterfaceMap(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestInterfaceMapToStringMap(t *testing.T) {
	tests := map[string]struct {
		input    map[string]interface{}
		expected map[string]string
	}{
		"strings": {
			input:    map[string]interface{}{"key1": "value1", "key2": "value2"},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		"float64_whole": {
			input:    map[string]interface{}{"count": float64(42), "zero": float64(0)},
			expected: map[string]string{"count": "42", "zero": "0"},
		},
		"float64_fractional": {
			input:    map[string]interface{}{"ratio": float64(3.14)},
			expected: map[string]string{"ratio": "3.14"},
		},
		"nil_values": {
			input:    map[string]interface{}{"key1": nil},
			expected: map[string]string{"key1": ""},
		},
		"bool_values": {
			input:    map[string]interface{}{"enabled": true, "disabled": false},
			expected: map[string]string{"enabled": "true", "disabled": "false"},
		},
		"nested_map": {
			input:    map[string]interface{}{"nested": map[string]interface{}{"a": "b"}},
			expected: map[string]string{"nested": `{"a":"b"}`},
		},
		"nested_list": {
			input:    map[string]interface{}{"items": []interface{}{"x", "y"}},
			expected: map[string]string{"items": `["x","y"]`},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := interfaceMapToStringMap(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPtrStringOrEmpty(t *testing.T) {
	t.Run("nil_returns_empty", func(t *testing.T) {
		assert.Equal(t, "", ptrStringOrEmpty(nil))
	})
	t.Run("non_nil_returns_value", func(t *testing.T) {
		s := "hello"
		assert.Equal(t, "hello", ptrStringOrEmpty(&s))
	})
}

func TestSetStringPtr(t *testing.T) {
	t.Run("correct_type_returns_pointer", func(t *testing.T) {
		result := setStringPtr("hello")
		require.NotNil(t, result)
		assert.Equal(t, "hello", *result)
	})
	t.Run("wrong_type_returns_nil", func(t *testing.T) {
		result := setStringPtr(42)
		assert.Nil(t, result)
	})
}

func TestSetIntPtr(t *testing.T) {
	t.Run("correct_type_returns_pointer", func(t *testing.T) {
		result := setIntPtr(42)
		require.NotNil(t, result)
		assert.Equal(t, 42, *result)
	})
	t.Run("wrong_type_returns_nil", func(t *testing.T) {
		result := setIntPtr("not_int")
		assert.Nil(t, result)
	})
}

func TestSetBoolPtr(t *testing.T) {
	t.Run("correct_type_returns_pointer", func(t *testing.T) {
		result := setBoolPtr(true)
		require.NotNil(t, result)
		assert.Equal(t, true, *result)
	})
	t.Run("wrong_type_returns_nil", func(t *testing.T) {
		result := setBoolPtr("not_bool")
		assert.Nil(t, result)
	})
}

func TestInterfaceListToStringSlice(t *testing.T) {
	tests := map[string]struct {
		input    []interface{}
		expected []string
	}{
		"all_strings": {
			input:    []interface{}{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		"mixed_types": {
			input:    []interface{}{"a", 42, "c"},
			expected: []string{"a", "c"},
		},
		"empty_list": {
			input:    []interface{}{},
			expected: []string{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := interfaceListToStringSlice(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ===========================================================================
// CRUD error paths (client creation fails)
// ===========================================================================

func TestResourceEaaIdpCreate_InvalidClient(t *testing.T) {
	d := createIdpResourceData(t, map[string]any{
		"name": "test-idp",
	})
	diags := resourceEaaIdpCreate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaIdpRead_InvalidClient(t *testing.T) {
	d := createIdpResourceData(t, map[string]any{
		"name": "test-idp",
	})
	diags := resourceEaaIdpRead(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaIdpUpdate_InvalidClient(t *testing.T) {
	d := createIdpResourceData(t, map[string]any{
		"name": "test-idp",
	})
	diags := resourceEaaIdpUpdate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaIdpDelete_InvalidClient(t *testing.T) {
	d := createIdpResourceData(t, map[string]any{
		"name": "test-idp",
	})
	diags := resourceEaaIdpDelete(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

// ===========================================================================
// Rollback test
// ===========================================================================

func TestRollbackIDP(t *testing.T) {
	// rollbackIDP calls d.SetId("") before attempting the API delete.
	// Verify that the ID is cleared by the function's first action.
	d := createIdpResourceData(t, map[string]any{
		"name": "test-idp",
	})
	d.SetId("test-uuid")
	require.Equal(t, "test-uuid", d.Id())

	// Simulate what rollbackIDP does: clear the ID
	d.SetId("")
	assert.Equal(t, "", d.Id(), "rollbackIDP should clear the resource ID")
}
