package client

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestGetAuthProtocolConfig(t *testing.T) {
	tests := map[string]struct {
		protocolType AuthProtocolType
		wantKey      string
		wantEmpty    bool
	}{
		"saml": {
			protocolType: AuthProtocolTypeSAML,
			wantKey:      "saml_settings",
		},
		"oidc": {
			protocolType: AuthProtocolTypeOIDC,
			wantKey:      "oidc_settings",
		},
		"wsfed": {
			protocolType: AuthProtocolTypeWSFED,
			wantKey:      "wsfed_settings",
		},
		"unknown": {
			protocolType: AuthProtocolType("unknown"),
			wantEmpty:    true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := getAuthProtocolConfig(tt.protocolType)
			if tt.wantEmpty {
				assert.Equal(t, AuthProtocolConfig{}, got)
				return
			}
			assert.Equal(t, tt.wantKey, got.SettingsKey)
			assert.NotEmpty(t, got.ProtocolValues)
			assert.NotEmpty(t, got.AppAuthValues)
		})
	}
}

func TestDecideAuthFromConfig(t *testing.T) {
	// Create a minimal schema for test resource data
	testSchema := map[string]*schema.Schema{
		"app_type": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"protocol": {
			Type:     schema.TypeString,
			Optional: true,
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

	tests := map[string]struct {
		rawData            map[string]interface{}
		appAuth            string
		wantNormalizedAuth string
		wantSAML           bool
		wantOIDC           bool
		wantWSFED          bool
	}{
		"saml_via_appauth": {
			rawData:            map[string]interface{}{},
			appAuth:            "saml",
			wantSAML:           true,
			wantNormalizedAuth: string(AppAuthNone),
		},
		"saml2_via_appauth": {
			rawData:            map[string]interface{}{},
			appAuth:            "SAML2.0",
			wantSAML:           true,
			wantNormalizedAuth: string(AppAuthNone),
		},
		"oidc_via_appauth": {
			rawData:            map[string]interface{}{},
			appAuth:            "oidc",
			wantOIDC:           true,
			wantNormalizedAuth: "oidc",
		},
		"oidc_full_via_appauth": {
			rawData:            map[string]interface{}{},
			appAuth:            "OpenID Connect 1.0",
			wantOIDC:           true,
			wantNormalizedAuth: "oidc",
		},
		"wsfed_via_appauth": {
			rawData:            map[string]interface{}{},
			appAuth:            "wsfed",
			wantWSFED:          true,
			wantNormalizedAuth: string(AppAuthNone),
		},
		"wsfed_full_via_appauth": {
			rawData:            map[string]interface{}{},
			appAuth:            "WS-Federation",
			wantWSFED:          true,
			wantNormalizedAuth: string(AppAuthNone),
		},
		"no_auth": {
			rawData:            map[string]interface{}{},
			appAuth:            "none",
			wantNormalizedAuth: "none",
		},
		"saas_with_saml_protocol": {
			rawData: map[string]interface{}{
				"app_type": "saas",
				"protocol": "SAML",
			},
			appAuth:            "",
			wantSAML:           true,
			wantNormalizedAuth: string(AppAuthNone),
		},
		"saas_with_oidc_protocol": {
			rawData: map[string]interface{}{
				"app_type": "saas",
				"protocol": "OIDC",
			},
			appAuth:            "",
			wantOIDC:           true,
			wantNormalizedAuth: "", // appAuth is empty, OIDC keeps it as-is
		},
		"saas_with_wsfed_protocol": {
			rawData: map[string]interface{}{
				"app_type": "saas",
				"protocol": "WSFed",
			},
			appAuth:            "",
			wantWSFED:          true,
			wantNormalizedAuth: string(AppAuthNone),
		},
		"kerberos_no_match": {
			rawData:            map[string]interface{}{},
			appAuth:            "kerberos",
			wantNormalizedAuth: "kerberos",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, testSchema, tt.rawData)
			enableSAML, enableOIDC, enableWSFED, normalizedAppAuth := decideAuthFromConfig(d, tt.appAuth)
			assert.Equal(t, tt.wantSAML, enableSAML, "enableSAML mismatch")
			assert.Equal(t, tt.wantOIDC, enableOIDC, "enableOIDC mismatch")
			assert.Equal(t, tt.wantWSFED, enableWSFED, "enableWSFED mismatch")
			assert.Equal(t, tt.wantNormalizedAuth, normalizedAppAuth, "normalizedAppAuth mismatch")
		})
	}
}
