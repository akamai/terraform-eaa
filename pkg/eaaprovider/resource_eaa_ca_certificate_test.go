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

func createCACertResourceData(t *testing.T, data map[string]any) *schema.ResourceData {
	t.Helper()
	return createTestResourceDataFor(t, resourceEaaCACertificate, data)
}

func TestResourceEaaCACertificateSchema(t *testing.T) {
	resource := resourceEaaCACertificate()
	require.NotNil(t, resource)

	expectedFields := []string{
		"name", "cert", "password",
		"uuid_url", "cn", "subject", "issuer",
		"issued_at", "expired_at", "days_left", "cert_file_name",
		"status", "app_count", "dir_count", "cert_type",
		"created_at", "modified_at",
		"apps", "idps", "cert_idps", "client_cert_idps",
		"saml_cert_idps", "saml_custom_sign_cert_idps",
	}
	for _, field := range expectedFields {
		_, ok := resource.Schema[field]
		assert.True(t, ok, "expected schema field %q to exist", field)
	}

	// Required fields
	assert.True(t, resource.Schema["name"].Required)
	assert.True(t, resource.Schema["cert"].Required)

	// Optional fields
	assert.True(t, resource.Schema["password"].Optional)

	// Sensitive fields
	assert.True(t, resource.Schema["password"].Sensitive)

	// DiffSuppressFunc on cert
	assert.NotNil(t, resource.Schema["cert"].DiffSuppressFunc)

	// CA cert should NOT have private_key or private_key_sha256
	_, hasPrivateKey := resource.Schema["private_key"]
	assert.False(t, hasPrivateKey, "CA cert should not have private_key field")
	_, hasPrivateKeySHA := resource.Schema["private_key_sha256"]
	assert.False(t, hasPrivateKeySHA, "CA cert should not have private_key_sha256 field")

	// CA cert should have cert_file_name (unique to CA certs)
	assert.True(t, resource.Schema["cert_file_name"].Computed)

	// Computed fields
	computedFields := []string{
		"uuid_url", "cn", "subject", "issuer",
		"issued_at", "expired_at", "days_left", "cert_file_name",
		"status", "app_count", "dir_count", "cert_type",
		"created_at", "modified_at",
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

func TestCACertDiffSuppressCert(t *testing.T) {
	resource := resourceEaaCACertificate()
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
		"leading_and_trailing_whitespace": {
			oldVal: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			newVal: "\n  -----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n  ",
			want:   true,
		},
		"different_content": {
			oldVal: "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----",
			newVal: "-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----",
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

func TestResourceEaaCACertificateCreate_InvalidClient(t *testing.T) {
	d := createCACertResourceData(t, map[string]any{
		"name": "test-ca",
		"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	diags := resourceEaaCACertificateCreate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaCACertificateRead_InvalidClient(t *testing.T) {
	d := createCACertResourceData(t, map[string]any{
		"name": "test-ca",
		"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	diags := resourceEaaCACertificateRead(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaCACertificateUpdate_InvalidClient(t *testing.T) {
	d := createCACertResourceData(t, map[string]any{
		"name": "test-ca",
		"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	diags := resourceEaaCACertificateUpdate(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}

func TestResourceEaaCACertificateDelete_InvalidClient(t *testing.T) {
	d := createCACertResourceData(t, map[string]any{
		"name": "test-ca",
		"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	diags := resourceEaaCACertificateDelete(context.Background(), d, nil)
	require.NotEmpty(t, diags)
}
