package client

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// convertNestedBlocksToSAMLConfig
// ---------------------------------------------------------------------------

func TestConvertNestedBlocksToSAMLConfig_CompleteConfig(t *testing.T) {
	input := map[string]interface{}{
		"sp": []interface{}{
			map[string]interface{}{
				"entity_id": "https://sp.example.com",
				"acs_url":   "https://sp.example.com/acs",
				"slo_url":   "https://sp.example.com/slo",
				"dst_url":   "https://sp.example.com/dst",
				"resp_bind": "post",
				"encr_algo": "aes128-cbc",
			},
		},
		"idp": []interface{}{
			map[string]interface{}{
				"entity_id":   "https://idp.example.com",
				"sign_algo":   "rsa-sha512",
				"sign_cert":   "MIIC...",
				"sign_key":    "MIIE...",
				"self_signed": false,
			},
		},
		"subject": []interface{}{
			map[string]interface{}{
				"fmt":  "unspecified",
				"src":  "user.name",
				"val":  "john",
				"rule": "match-all",
			},
		},
		"attrmap": []interface{}{
			map[string]interface{}{
				"name":  "email",
				"fname": "Email Address",
				"fmt":   "basic",
				"val":   "user@example.com",
				"src":   "user.email",
				"rule":  "default",
			},
			map[string]interface{}{
				"name": "role",
				"src":  "user.role",
			},
		},
	}

	config, err := convertNestedBlocksToSAMLConfig(input)
	require.NoError(t, err)

	// SP
	assert.Equal(t, "https://sp.example.com", config.SP.EntityID)
	assert.Equal(t, "https://sp.example.com/acs", config.SP.ACSURL)
	assert.Equal(t, "https://sp.example.com/slo", config.SP.SLOURL)
	assert.Equal(t, "https://sp.example.com/dst", config.SP.DSTURL)
	assert.Equal(t, "post", config.SP.ReqBind, "resp_bind maps to SP.ReqBind")
	assert.Equal(t, "aes128-cbc", config.SP.EncrAlgo)

	// IDP
	assert.Equal(t, "https://idp.example.com", config.IDP.EntityID)
	assert.Equal(t, "rsa-sha512", config.IDP.SignAlgo)
	require.NotNil(t, config.IDP.SignCert)
	assert.Equal(t, "MIIC...", *config.IDP.SignCert)
	assert.Equal(t, "MIIE...", config.IDP.SignKey)
	assert.False(t, config.IDP.SelfSigned)

	// Subject
	assert.Equal(t, "unspecified", config.Subject.Fmt)
	assert.Equal(t, "user.name", config.Subject.Src)
	assert.Equal(t, "john", config.Subject.Val)
	assert.Equal(t, "match-all", config.Subject.Rule)

	// Attrmap
	require.Len(t, config.Attrmap, 2)
	assert.Equal(t, "email", config.Attrmap[0].Name)
	assert.Equal(t, "Email Address", config.Attrmap[0].Fname)
	assert.Equal(t, "basic", config.Attrmap[0].Fmt)
	assert.Equal(t, "user@example.com", config.Attrmap[0].Val)
	assert.Equal(t, "user.email", config.Attrmap[0].Src)
	assert.Equal(t, "default", config.Attrmap[0].Rule)
	assert.Equal(t, "role", config.Attrmap[1].Name)
	assert.Equal(t, "user.role", config.Attrmap[1].Src)
}

func TestConvertNestedBlocksToSAMLConfig_MinimalConfig(t *testing.T) {
	// Empty input: all fields remain at DefaultSAMLConfig values
	input := map[string]interface{}{}

	config, err := convertNestedBlocksToSAMLConfig(input)
	require.NoError(t, err)

	assert.Equal(t, DefaultSAMLConfig.SP.ReqBind, config.SP.ReqBind)
	assert.Equal(t, DefaultSAMLConfig.SP.EncrAlgo, config.SP.EncrAlgo)
	assert.Equal(t, DefaultSAMLConfig.IDP.SignAlgo, config.IDP.SignAlgo)
	assert.Equal(t, DefaultSAMLConfig.IDP.SelfSigned, config.IDP.SelfSigned)
	assert.Equal(t, DefaultSAMLConfig.Subject.Fmt, config.Subject.Fmt)
	assert.Equal(t, DefaultSAMLConfig.Subject.Src, config.Subject.Src)
	assert.Empty(t, config.Attrmap)
}

func TestConvertNestedBlocksToSAMLConfig_OnlySP(t *testing.T) {
	input := map[string]interface{}{
		"sp": []interface{}{
			map[string]interface{}{
				"entity_id": "https://sp.example.com",
				"acs_url":   "https://sp.example.com/acs",
			},
		},
	}

	config, err := convertNestedBlocksToSAMLConfig(input)
	require.NoError(t, err)

	assert.Equal(t, "https://sp.example.com", config.SP.EntityID)
	assert.Equal(t, "https://sp.example.com/acs", config.SP.ACSURL)
	// IDP and Subject retain defaults
	assert.Equal(t, DefaultSAMLConfig.IDP.SignAlgo, config.IDP.SignAlgo)
	assert.Equal(t, DefaultSAMLConfig.Subject.Fmt, config.Subject.Fmt)
}

func TestConvertNestedBlocksToSAMLConfig_OnlyAttrmap(t *testing.T) {
	input := map[string]interface{}{
		"attrmap": []interface{}{
			map[string]interface{}{
				"name": "department",
				"val":  "engineering",
			},
		},
	}

	config, err := convertNestedBlocksToSAMLConfig(input)
	require.NoError(t, err)

	require.Len(t, config.Attrmap, 1)
	assert.Equal(t, "department", config.Attrmap[0].Name)
	assert.Equal(t, "engineering", config.Attrmap[0].Val)
	// Unset fields remain zero
	assert.Equal(t, "", config.Attrmap[0].Fname)
}

func TestConvertNestedBlocksToSAMLConfig_InvalidSPBlock(t *testing.T) {
	// SP block contains a non-map entry
	input := map[string]interface{}{
		"sp": []interface{}{
			"not-a-map",
		},
	}

	_, err := convertNestedBlocksToSAMLConfig(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "saml_settings.sp")
}

func TestConvertNestedBlocksToSAMLConfig_InvalidIDPBlock(t *testing.T) {
	input := map[string]interface{}{
		"idp": []interface{}{
			42,
		},
	}

	_, err := convertNestedBlocksToSAMLConfig(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "saml_settings.idp")
}

func TestConvertNestedBlocksToSAMLConfig_InvalidSubjectBlock(t *testing.T) {
	input := map[string]interface{}{
		"subject": []interface{}{
			true,
		},
	}

	_, err := convertNestedBlocksToSAMLConfig(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "saml_settings.subject")
}

func TestConvertNestedBlocksToSAMLConfig_AttrmapSkipsNonMapEntries(t *testing.T) {
	input := map[string]interface{}{
		"attrmap": []interface{}{
			"bad-entry",
			map[string]interface{}{"name": "valid"},
		},
	}

	config, err := convertNestedBlocksToSAMLConfig(input)
	require.NoError(t, err)
	require.Len(t, config.Attrmap, 1)
	assert.Equal(t, "valid", config.Attrmap[0].Name)
}

// ---------------------------------------------------------------------------
// convertNestedBlocksToOIDCConfig
// ---------------------------------------------------------------------------

func TestConvertNestedBlocksToOIDCConfig_CompleteConfig(t *testing.T) {
	input := map[string]interface{}{
		"oidc_clients": []interface{}{
			map[string]interface{}{
				"client_name":        "My App",
				"client_id":          "abc-123",
				"type":               "confidential",
				"implicit_grant":     true,
				"response_type":      []interface{}{"code", "token"},
				"redirect_uris":      []interface{}{"https://app.example.com/callback"},
				"javascript_origins": []interface{}{"https://app.example.com"},
				"claims": []interface{}{
					map[string]interface{}{
						"name":  "email",
						"scope": "openid",
						"val":   "user@example.com",
						"src":   "user.email",
						"rule":  "include",
					},
				},
			},
		},
	}

	config, err := convertNestedBlocksToOIDCConfig(input)
	require.NoError(t, err)
	require.NotNil(t, config)
	require.Len(t, config.OIDCClients, 1)

	client := config.OIDCClients[0]
	assert.Equal(t, "My App", client.ClientName)
	assert.Equal(t, "abc-123", client.ClientID)
	assert.Equal(t, "confidential", client.Type)
	assert.True(t, client.ImplicitGrant)
	assert.Equal(t, []string{"code", "token"}, client.ResponseType)
	assert.Equal(t, []string{"https://app.example.com/callback"}, client.RedirectURIs)
	assert.Equal(t, []string{"https://app.example.com"}, client.JavaScriptOrigins)

	require.Len(t, client.Claims, 1)
	assert.Equal(t, "email", client.Claims[0].Name)
	assert.Equal(t, "openid", client.Claims[0].Scope)
	assert.Equal(t, "user@example.com", client.Claims[0].Val)
	assert.Equal(t, "user.email", client.Claims[0].Src)
	assert.Equal(t, "include", client.Claims[0].Rule)
}

func TestConvertNestedBlocksToOIDCConfig_MinimalClient(t *testing.T) {
	input := map[string]interface{}{
		"oidc_clients": []interface{}{
			map[string]interface{}{
				"client_name": "Minimal",
			},
		},
	}

	config, err := convertNestedBlocksToOIDCConfig(input)
	require.NoError(t, err)
	require.Len(t, config.OIDCClients, 1)

	assert.Equal(t, "Minimal", config.OIDCClients[0].ClientName)
	assert.Empty(t, config.OIDCClients[0].ClientID)
	assert.False(t, config.OIDCClients[0].ImplicitGrant)
	assert.Nil(t, config.OIDCClients[0].ResponseType)
	assert.Nil(t, config.OIDCClients[0].RedirectURIs)
	assert.Nil(t, config.OIDCClients[0].Claims)
}

func TestConvertNestedBlocksToOIDCConfig_EmptyInput(t *testing.T) {
	input := map[string]interface{}{}

	config, err := convertNestedBlocksToOIDCConfig(input)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Nil(t, config.OIDCClients)
}

func TestConvertNestedBlocksToOIDCConfig_MultipleClients(t *testing.T) {
	input := map[string]interface{}{
		"oidc_clients": []interface{}{
			map[string]interface{}{
				"client_name": "Client A",
				"client_id":   "id-a",
			},
			map[string]interface{}{
				"client_name": "Client B",
				"client_id":   "id-b",
			},
		},
	}

	config, err := convertNestedBlocksToOIDCConfig(input)
	require.NoError(t, err)
	require.Len(t, config.OIDCClients, 2)
	assert.Equal(t, "Client A", config.OIDCClients[0].ClientName)
	assert.Equal(t, "Client B", config.OIDCClients[1].ClientName)
}

func TestConvertNestedBlocksToOIDCConfig_SkipsNonMapClients(t *testing.T) {
	input := map[string]interface{}{
		"oidc_clients": []interface{}{
			"not-a-map",
			map[string]interface{}{"client_name": "Valid"},
		},
	}

	config, err := convertNestedBlocksToOIDCConfig(input)
	require.NoError(t, err)
	require.Len(t, config.OIDCClients, 1)
	assert.Equal(t, "Valid", config.OIDCClients[0].ClientName)
}

func TestConvertNestedBlocksToOIDCConfig_ClaimsSkipsNonMapEntries(t *testing.T) {
	input := map[string]interface{}{
		"oidc_clients": []interface{}{
			map[string]interface{}{
				"client_name": "Test",
				"claims": []interface{}{
					"not-a-map",
					map[string]interface{}{"name": "valid-claim"},
				},
			},
		},
	}

	config, err := convertNestedBlocksToOIDCConfig(input)
	require.NoError(t, err)
	require.Len(t, config.OIDCClients[0].Claims, 1)
	assert.Equal(t, "valid-claim", config.OIDCClients[0].Claims[0].Name)
}

func TestConvertNestedBlocksToOIDCConfig_EmptySliceFields(t *testing.T) {
	input := map[string]interface{}{
		"oidc_clients": []interface{}{
			map[string]interface{}{
				"client_name":        "Test",
				"response_type":      []interface{}{},
				"redirect_uris":      []interface{}{},
				"javascript_origins": []interface{}{},
				"claims":             []interface{}{},
			},
		},
	}

	config, err := convertNestedBlocksToOIDCConfig(input)
	require.NoError(t, err)
	require.Len(t, config.OIDCClients, 1)

	client := config.OIDCClients[0]
	assert.Empty(t, client.ResponseType)
	assert.Empty(t, client.RedirectURIs)
	assert.Empty(t, client.JavaScriptOrigins)
	assert.Empty(t, client.Claims)
}

// ---------------------------------------------------------------------------
// getAppAuthFromAdvancedSettings
// ---------------------------------------------------------------------------

// authTestSchema returns a minimal schema suitable for testing auth functions
// that read advanced_settings as a TypeMap.
func authTestSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"app_type": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"protocol": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"advanced_settings": {
			Type:     schema.TypeMap,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"saml_settings": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"dummy": {Type: schema.TypeString, Optional: true},
				},
			},
		},
		"oidc_settings": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"dummy": {Type: schema.TypeString, Optional: true},
				},
			},
		},
		"wsfed_settings": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"dummy": {Type: schema.TypeString, Optional: true},
				},
			},
		},
	}
}

func TestGetAppAuthFromAdvancedSettings(t *testing.T) {
	tests := map[string]struct {
		rawData  map[string]interface{}
		wantAuth string
	}{
		"returns_app_auth_saml": {
			rawData: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "saml",
				},
			},
			wantAuth: "saml",
		},
		"returns_app_auth_oidc": {
			rawData: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "oidc",
				},
			},
			wantAuth: "oidc",
		},
		"returns_empty_when_no_advanced_settings": {
			rawData:  map[string]interface{}{},
			wantAuth: "",
		},
		"returns_default_when_app_auth_missing_from_block": {
			rawData: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"is_ssl": "true",
				},
			},
			wantAuth: "none", // ParseAdvancedSettingsWithDefaults fills default "none"
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, authTestSchema(), tt.rawData)
			got := getAppAuthFromAdvancedSettings(d)
			assert.Equal(t, tt.wantAuth, got)
		})
	}
}

// ---------------------------------------------------------------------------
// applyAuthTransformation
// ---------------------------------------------------------------------------

func TestApplyAuthTransformation(t *testing.T) {
	tests := map[string]struct {
		rawData     map[string]interface{}
		wantAppAuth string
		wantSAML    bool
		wantOIDC    bool
		wantWSFED   bool
	}{
		"saml_via_advanced_settings": {
			rawData: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "saml",
				},
			},
			wantSAML:    true,
			wantAppAuth: string(AppAuthNone),
		},
		"oidc_via_advanced_settings": {
			rawData: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "oidc",
				},
			},
			wantOIDC:    true,
			wantAppAuth: "oidc",
		},
		"wsfed_via_advanced_settings": {
			rawData: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "wsfed",
				},
			},
			wantWSFED:   true,
			wantAppAuth: string(AppAuthNone),
		},
		"no_auth_returns_passthrough": {
			rawData: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "none",
				},
			},
			wantAppAuth: "none",
		},
		"empty_advanced_settings_no_auth": {
			rawData:     map[string]interface{}{},
			wantAppAuth: "",
		},
		"saas_saml_protocol": {
			rawData: map[string]interface{}{
				"app_type": "saas",
				"protocol": "SAML",
			},
			wantSAML:    true,
			wantAppAuth: string(AppAuthNone),
		},
		"saas_oidc_protocol": {
			rawData: map[string]interface{}{
				"app_type": "saas",
				"protocol": "OIDC",
			},
			wantOIDC:    true,
			wantAppAuth: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, authTestSchema(), tt.rawData)
			result := applyAuthTransformation(d)
			assert.Equal(t, tt.wantSAML, result.EnableSAML, "EnableSAML")
			assert.Equal(t, tt.wantOIDC, result.EnableOIDC, "EnableOIDC")
			assert.Equal(t, tt.wantWSFED, result.EnableWSFED, "EnableWSFED")
			assert.Equal(t, tt.wantAppAuth, result.AppAuth, "AppAuth")
		})
	}
}
