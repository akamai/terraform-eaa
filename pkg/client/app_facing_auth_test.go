package client

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestShouldEnableSAMLForCreate(t *testing.T) {
	tests := []struct {
		name       string
		data       map[string]interface{}
		appAuth    string
		wantResult bool
	}{
		{
			name:       "SAML via app_auth",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "saml",
			wantResult: true,
		},
		{
			name:       "SAML2.0 via app_auth",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "SAML2.0",
			wantResult: true,
		},
		{
			name: "SaaS with SAML protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "SAML",
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name: "SaaS with SAML2.0 protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "SAML2.0",
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name: "SaaS with different protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "OIDC",
			},
			appAuth:    "",
			wantResult: false,
		},
		{
			name: "enterprise with saml_settings",
			data: map[string]interface{}{
				"app_type":     "enterprise",
				"saml_settings": []interface{}{map[string]interface{}{"idp": "test-idp"}},
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name:       "no SAML indicators",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "none",
			wantResult: false,
		},
		{
			name: "empty saml_settings",
			data: map[string]interface{}{
				"app_type":     "enterprise",
				"saml_settings": []interface{}{},
			},
			appAuth:    "",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &schema.Resource{
				Schema: map[string]*schema.Schema{
					"app_type": {Type: schema.TypeString},
					"protocol": {Type: schema.TypeString},
					"saml_settings": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeMap,
						},
					},
				},
			}
			d := resource.Data(nil)
			for k, v := range tt.data {
				if err := d.Set(k, v); err != nil {
					t.Fatalf("Failed to set %s: %v", k, err)
				}
			}

			result := shouldEnableAuthForCreate(d, tt.appAuth, getAuthProtocolConfig(AuthProtocolTypeSAML))
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestShouldEnableOIDCForCreate(t *testing.T) {
	tests := []struct {
		name       string
		data       map[string]interface{}
		appAuth    string
		wantResult bool
	}{
		{
			name:       "OIDC via app_auth",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "oidc",
			wantResult: true,
		},
		{
			name:       "OpenID Connect 1.0 via app_auth",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "OpenID Connect 1.0",
			wantResult: true,
		},
		{
			name: "SaaS with OIDC protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "OIDC",
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name: "SaaS with OpenID Connect 1.0 protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "OpenID Connect 1.0",
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name: "SaaS with different protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "SAML",
			},
			appAuth:    "",
			wantResult: false,
		},
		{
			name: "enterprise with oidc_settings",
			data: map[string]interface{}{
				"app_type":     "enterprise",
				"oidc_settings": []interface{}{map[string]interface{}{"idp": "test-idp"}},
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name:       "no OIDC indicators",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "none",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &schema.Resource{
				Schema: map[string]*schema.Schema{
					"app_type": {Type: schema.TypeString},
					"protocol": {Type: schema.TypeString},
					"oidc_settings": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeMap,
						},
					},
				},
			}
			d := resource.Data(nil)
			for k, v := range tt.data {
				if err := d.Set(k, v); err != nil {
					t.Fatalf("Failed to set %s: %v", k, err)
				}
			}

			result := shouldEnableAuthForCreate(d, tt.appAuth, getAuthProtocolConfig(AuthProtocolTypeOIDC))
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestShouldEnableWSFEDForCreate(t *testing.T) {
	tests := []struct {
		name       string
		data       map[string]interface{}
		appAuth    string
		wantResult bool
	}{
		{
			name:       "WS-Fed via app_auth",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "wsfed",
			wantResult: true,
		},
		{
			name:       "WS-Federation via app_auth",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "WS-Federation",
			wantResult: true,
		},
		{
			name: "SaaS with WSFed protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "WSFed",
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name: "SaaS with WS-Federation protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "WS-Federation",
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name: "SaaS with different protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "OIDC",
			},
			appAuth:    "",
			wantResult: false,
		},
		{
			name: "enterprise with wsfed_settings",
			data: map[string]interface{}{
				"app_type":      "enterprise",
				"wsfed_settings": []interface{}{map[string]interface{}{"idp": "test-idp"}},
			},
			appAuth:    "",
			wantResult: true,
		},
		{
			name:       "no WS-Fed indicators",
			data:       map[string]interface{}{"app_type": "enterprise"},
			appAuth:    "none",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &schema.Resource{
				Schema: map[string]*schema.Schema{
					"app_type": {Type: schema.TypeString},
					"protocol": {Type: schema.TypeString},
					"wsfed_settings": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeMap,
						},
					},
				},
			}
			d := resource.Data(nil)
			for k, v := range tt.data {
				if err := d.Set(k, v); err != nil {
					t.Fatalf("Failed to set %s: %v", k, err)
				}
			}

			result := shouldEnableAuthForCreate(d, tt.appAuth, getAuthProtocolConfig(AuthProtocolTypeWSFED))
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestDecideAuthFromConfig(t *testing.T) {
	tests := []struct {
		name           string
		data           map[string]interface{}
		appAuth        string
		wantSAML       bool
		wantOIDC       bool
		wantWSFED      bool
		wantNormalized string
	}{
		{
			name:           "SAML takes precedence",
			data:           map[string]interface{}{"app_type": "enterprise"},
			appAuth:        "saml",
			wantSAML:       true,
			wantOIDC:       false,
			wantWSFED:      false,
			wantNormalized: "none",
		},
		{
			name:           "OIDC when SAML not present",
			data:           map[string]interface{}{"app_type": "enterprise"},
			appAuth:        "oidc",
			wantSAML:       false,
			wantOIDC:       true,
			wantWSFED:      false,
			wantNormalized: "oidc", // updated expectation to match new logic
		},
		{
			name:           "WS-Fed when SAML/OIDC not present",
			data:           map[string]interface{}{"app_type": "enterprise"},
			appAuth:        "wsfed",
			wantSAML:       false,
			wantOIDC:       false,
			wantWSFED:      true,
			wantNormalized: "none",
		},
		{
			name:           "no auth flags, return original appAuth",
			data:           map[string]interface{}{"app_type": "enterprise"},
			appAuth:        "kerberos",
			wantSAML:       false,
			wantOIDC:       false,
			wantWSFED:      false,
			wantNormalized: "kerberos",
		},
		{
			name: "SaaS SAML via protocol",
			data: map[string]interface{}{
				"app_type": "saas",
				"protocol": "SAML",
			},
			appAuth:        "",
			wantSAML:       true,
			wantOIDC:       false,
			wantWSFED:      false,
			wantNormalized: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &schema.Resource{
				Schema: map[string]*schema.Schema{
					"app_type": {Type: schema.TypeString},
					"protocol": {Type: schema.TypeString},
				},
			}
			d := resource.Data(nil)
			for k, v := range tt.data {
				if err := d.Set(k, v); err != nil {
					t.Fatalf("Failed to set %s: %v", k, err)
				}
			}

			enableSAML, enableOIDC, enableWSFED, normalized := decideAuthFromConfig(d, tt.appAuth)
			assert.Equal(t, tt.wantSAML, enableSAML)
			assert.Equal(t, tt.wantOIDC, enableOIDC)
			assert.Equal(t, tt.wantWSFED, enableWSFED)
			assert.Equal(t, tt.wantNormalized, normalized)
		})
	}
}

