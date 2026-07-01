package eaaprovider

import (
	"context"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Schema structure
// ===========================================================================

func createCustomAppCertResourceData(t *testing.T, data map[string]any) *schema.ResourceData {
	t.Helper()
	return createTestResourceDataFor(t, resourceEaaCustomAppCertificate, data)
}

func TestResourceEaaCustomAppCertificateSchema(t *testing.T) {
	resource := resourceEaaCustomAppCertificate()
	require.NotNil(t, resource)

	expectedFields := []string{
		"name", "cert", "private_key", "password",
		"private_key_sha256", "uuid_url", "cn", "subject", "issuer",
		"issued_at", "expired_at", "days_left", "status",
		"app_count", "dir_count", "cert_type", "created_at", "modified_at",
		"apps", "idps", "cert_idps", "client_cert_idps",
		"saml_cert_idps", "saml_custom_sign_cert_idps",
	}
	for _, field := range expectedFields {
		_, ok := resource.Schema[field]
		assert.True(t, ok, "expected schema field %q to exist", field)
	}

	// Required fields
	assert.True(t, resource.Schema["name"].Required)

	// Optional fields
	assert.True(t, resource.Schema["cert"].Optional)
	assert.True(t, resource.Schema["private_key"].Optional)
	assert.True(t, resource.Schema["password"].Optional)

	// Sensitive fields
	assert.True(t, resource.Schema["private_key"].Sensitive)
	assert.True(t, resource.Schema["password"].Sensitive)

	// DiffSuppressFunc on cert
	assert.NotNil(t, resource.Schema["cert"].DiffSuppressFunc)

	// Computed fields
	computedFields := []string{
		"private_key_sha256", "uuid_url", "cn", "subject", "issuer",
		"issued_at", "expired_at", "days_left", "status",
		"app_count", "dir_count", "cert_type", "created_at", "modified_at",
		"apps", "idps", "cert_idps", "client_cert_idps",
		"saml_cert_idps", "saml_custom_sign_cert_idps",
	}
	for _, field := range computedFields {
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
// DiffSuppressFunc on cert
// ===========================================================================

func TestCustomAppCertDiffSuppressCert(t *testing.T) {
	resource := resourceEaaCustomAppCertificate()
	suppress := resource.Schema["cert"].DiffSuppressFunc

	tests := map[string]struct {
		oldVal string
		newVal string
		want   bool
	}{
		"identical": {
			oldVal: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			newVal: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			want:   true,
		},
		"trailing_newline": {
			oldVal: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			newVal: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
			want:   true,
		},
		"leading_whitespace": {
			oldVal: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			newVal: "  -----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----  ",
			want:   true,
		},
		"different_content": {
			oldVal: "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----",
			newVal: "-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----",
			want:   false,
		},
		"empty_vs_content": {
			oldVal: "",
			newVal: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			want:   false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := suppress("cert", tc.oldVal, tc.newVal, nil)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ===========================================================================
// CRUD error paths (client creation fails)
// ===========================================================================

func TestResourceEaaCustomAppCertificateCreate_InvalidClient(t *testing.T) {
	d := createCustomAppCertResourceData(t, map[string]any{
		"name": "test-cert",
	})
	diags := resourceEaaCustomAppCertificateCreate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaCustomAppCertificateRead_InvalidClient(t *testing.T) {
	d := createCustomAppCertResourceData(t, map[string]any{})
	diags := resourceEaaCustomAppCertificateRead(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaCustomAppCertificateUpdate_InvalidClient(t *testing.T) {
	d := createCustomAppCertResourceData(t, map[string]any{
		"name": "test-cert",
	})
	diags := resourceEaaCustomAppCertificateUpdate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaCustomAppCertificateDelete_InvalidClient(t *testing.T) {
	d := createCustomAppCertResourceData(t, map[string]any{})
	diags := resourceEaaCustomAppCertificateDelete(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

// ===========================================================================
// Create validation: missing fields cause errors
// ===========================================================================

func TestResourceEaaCustomAppCertificateCreate_MissingFields(t *testing.T) {
	tests := map[string]struct {
		data map[string]any
	}{
		"missing_cert_and_key": {
			data: map[string]any{"name": "test-cert"},
		},
		"missing_private_key": {
			data: map[string]any{
				"name": "test-cert",
				"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			},
		},
		"missing_cert": {
			data: map[string]any{
				"name":        "test-cert",
				"private_key": "--private-key--",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createCustomAppCertResourceData(t, tc.data)
			diags := resourceEaaCustomAppCertificateCreate(context.Background(), d, nil)
			require.True(t, diags.HasError(), "expected error when fields are missing")
		})
	}
}

// ===========================================================================
// Update validation: missing fields cause errors
// ===========================================================================

func TestResourceEaaCustomAppCertificateUpdate_MissingFields(t *testing.T) {
	tests := map[string]struct {
		data map[string]any
	}{
		"missing_cert_and_key": {
			data: map[string]any{"name": "test-cert"},
		},
		"missing_private_key": {
			data: map[string]any{
				"name": "test-cert",
				"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			},
		},
		"missing_cert": {
			data: map[string]any{
				"name":        "test-cert",
				"private_key": "--private-key--",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createCustomAppCertResourceData(t, tc.data)
			d.SetId("cert-uuid")
			diags := resourceEaaCustomAppCertificateUpdate(context.Background(), d, nil)
			require.True(t, diags.HasError(), "expected error when fields are missing")
		})
	}
}

// ===========================================================================
// flattenAssociatedObjects
// ===========================================================================

func TestFlattenAssociatedObjects(t *testing.T) {
	tests := map[string]struct {
		input    []client.AssociatedObject
		expected []map[string]any
	}{
		"empty": {
			input:    []client.AssociatedObject{},
			expected: []map[string]any{},
		},
		"single": {
			input: []client.AssociatedObject{
				{Name: "app1", UUIDURL: "app-uuid-1", Status: 1},
			},
			expected: []map[string]any{
				{"name": "app1", "uuid_url": "app-uuid-1", "status": 1},
			},
		},
		"multiple": {
			input: []client.AssociatedObject{
				{Name: "app1", UUIDURL: "app-uuid-1", Status: 1},
				{Name: "app2", UUIDURL: "app-uuid-2", Status: 2},
				{Name: "app3", UUIDURL: "app-uuid-3", Status: 0},
			},
			expected: []map[string]any{
				{"name": "app1", "uuid_url": "app-uuid-1", "status": 1},
				{"name": "app2", "uuid_url": "app-uuid-2", "status": 2},
				{"name": "app3", "uuid_url": "app-uuid-3", "status": 0},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := flattenAssociatedObjects(tc.input)
			require.Len(t, result, len(tc.expected))
			for i, expected := range tc.expected {
				assert.Equal(t, expected["name"], result[i]["name"])
				assert.Equal(t, expected["uuid_url"], result[i]["uuid_url"])
				assert.Equal(t, expected["status"], result[i]["status"])
			}
		})
	}
}

// ===========================================================================
// associatedObjectSchema
// ===========================================================================

func TestAssociatedObjectSchema(t *testing.T) {
	s := associatedObjectSchema()
	require.NotNil(t, s)

	assert.True(t, s["name"].Computed)
	assert.True(t, s["uuid_url"].Computed)
	assert.True(t, s["status"].Computed)
}
