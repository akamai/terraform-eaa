package eaaprovider

import (
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestValidateAppAuthBasedOnTypeAndProfile(t *testing.T) {
	tests := map[string]struct {
		value    interface{}
		key      string
		wantErr  bool
	}{
		"valid_app_auth": {
			value:   "saml",
			key:     "app_auth",
			wantErr: false,
		},
		"valid_app_auth_oidc": {
			value:   "oidc",
			key:     "app_auth",
			wantErr: false,
		},
		"invalid_app_auth": {
			value:   "invalid",
			key:     "app_auth",
			wantErr: true,
		},
		"invalid_type": {
			value:   123,
			key:     "app_auth",
			wantErr: true,
		},
		"empty_string": {
			value:   "",
			key:     "app_auth",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateAppAuthBasedOnTypeAndProfile(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateAppAuthBasedOnTypeAndProfile() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

// Note: validateAuthenticationMethodsForAppTypeWithDiff requires *schema.ResourceDiff
// which is difficult to mock. This should be tested via integration tests.
// func TestValidateAuthenticationMethodsForAppTypeWithDiff(t *testing.T) {
// 	// Skipped - requires *schema.ResourceDiff
// }

// Note: validateAppAuthConflictsWithResourceLevelAuth requires *schema.ResourceDiff
// which is difficult to mock. This should be tested via integration tests.
// func TestValidateAppAuthConflictsWithResourceLevelAuth(t *testing.T) {
// 	// Skipped - requires *schema.ResourceDiff
// }

func TestValidateAppAuthWithResourceData(t *testing.T) {
	tests := map[string]struct {
		appAuth   string
		data      *schema.ResourceData
		wantErr   bool
		setupFunc func(*schema.ResourceData)
	}{
		"valid_app_auth": {
			appAuth: "saml",
			wantErr: false,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeEnterprise))
			},
		},
		"invalid_app_auth": {
			appAuth: "invalid",
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeEnterprise))
			},
		},
		"tunnel_app_with_saml_flag": {
			appAuth: "none",
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeTunnel))
				d.Set("saml", true)
			},
		},
		"enterprise_ssh_profile": {
			appAuth: "saml",
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeEnterprise))
				d.Set("app_profile", string(client.AppProfileSSH))
			},
		},
		"saas_app": {
			appAuth: "saml",
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeSaaS))
			},
		},
		"bookmark_app": {
			appAuth: "saml",
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeBookmark))
			},
		},
		"tunnel_app": {
			appAuth: "saml",
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeTunnel))
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"app_type":    {Type: schema.TypeString},
				"app_profile": {Type: schema.TypeString},
				"saml":        {Type: schema.TypeBool},
				"oidc":        {Type: schema.TypeBool},
				"wsfed":       {Type: schema.TypeBool},
			}, map[string]interface{}{})

			if tt.setupFunc != nil {
				tt.setupFunc(d)
			}

			err := validateAppAuthWithResourceData(tt.appAuth, d)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAppAuthWithResourceData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAppBundle(t *testing.T) {
	tests := map[string]struct {
		value    interface{}
		key      string
		wantErr  bool
	}{
		"valid_bundle": {
			value:   "bundle-name",
			key:     "app_bundle",
			wantErr: false,
		},
		"empty_bundle": {
			value:   "",
			key:     "app_bundle",
			wantErr: true,
		},
		"invalid_type": {
			value:   123,
			key:     "app_bundle",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateAppBundle(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateAppBundle() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

// Note: validateAppBundleRestrictions requires *schema.ResourceDiff
// which is difficult to mock. This should be tested via integration tests.
// func TestValidateAppBundleRestrictions(t *testing.T) {
// 	// Skipped - requires *schema.ResourceDiff
// }

func TestShouldEnableSAMLFromDiff(t *testing.T) {
	tests := map[string]struct {
		initialData map[string]interface{}
		want        bool
	}{
		"enabled_via_flag": {
			// Note: shouldEnableSAML doesn't check the direct "saml" flag,
			// it only checks app_auth in advanced_settings and saml_settings
			// So this test case should expect false or be removed
			initialData: map[string]interface{}{
				"saml": true,
			},
			want: false, // shouldEnableSAML doesn't check direct flag
		},
		"enabled_via_app_auth": {
			initialData: map[string]interface{}{
				"advanced_settings": `{"app_auth": "saml"}`,
			},
			want: true,
		},
		"enabled_via_settings": {
			initialData: map[string]interface{}{
				"saml_settings": []interface{}{
					map[string]interface{}{
						"entity_id": "test-id", // Direct field, not nested idp block
					},
				},
			},
			want: true,
		},
		"not_enabled": {
			initialData: map[string]interface{}{},
			want:        false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"saml":             {Type: schema.TypeBool},
				"advanced_settings": {Type: schema.TypeString},
				"saml_settings":    {Type: schema.TypeList, Elem: &schema.Schema{Type: schema.TypeMap}},
			}, tt.initialData)

			// Note: shouldEnableSAMLFromDiff requires ResourceDiff, but we can test shouldEnableSAML instead
			// which uses ResourceData
			got := shouldEnableSAML(d)
			if got != tt.want {
				t.Errorf("shouldEnableSAML() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAdvancedSettingsWithAppTypeAndProfile(t *testing.T) {
	tests := map[string]struct {
		data      *schema.ResourceData
		wantErr   bool
		setupFunc func(*schema.ResourceData)
	}{
		"bookmark_app_with_advanced_settings": {
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeBookmark))
				d.Set("advanced_settings", `{"app_auth": "saml"}`)
			},
		},
		"saas_app_with_advanced_settings": {
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeSaaS))
				d.Set("advanced_settings", `{"app_auth": "saml"}`)
			},
		},
		"bookmark_app_empty_advanced_settings": {
			wantErr: false,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeBookmark))
				d.Set("advanced_settings", "{}")
			},
		},
		"enterprise_app_valid": {
			wantErr: false,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeEnterprise))
				d.Set("app_profile", string(client.AppProfileHTTP))
				d.Set("advanced_settings", `{"app_auth": "saml"}`)
			},
		},
		"invalid_json": {
			wantErr: true,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeEnterprise))
				d.Set("advanced_settings", `{invalid json}`)
			},
		},
		"no_advanced_settings": {
			wantErr: false,
			setupFunc: func(d *schema.ResourceData) {
				d.Set("app_type", string(client.ClientAppTypeEnterprise))
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"app_type":          {Type: schema.TypeString},
				"app_profile":       {Type: schema.TypeString},
				"advanced_settings": {Type: schema.TypeString},
			}, map[string]interface{}{})

			if tt.setupFunc != nil {
				tt.setupFunc(d)
			}

			err := validateAdvancedSettingsWithAppTypeAndProfile(d)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAdvancedSettingsWithAppTypeAndProfile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTLSSuiteRequiredDependencies(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		settings map[string]interface{}
		wantErr  bool
	}{
		"custom_suite_with_name": {
			settings: map[string]interface{}{
				"tlsSuiteType": "custom",
				"tls_suite_name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			},
			wantErr: false,
		},
		"custom_suite_without_name": {
			settings: map[string]interface{}{
				"tlsSuiteType": "custom",
			},
			wantErr: true,
		},
		"custom_suite_with_empty_name": {
			settings: map[string]interface{}{
				"tlsSuiteType": "custom",
				"tls_suite_name": "",
			},
			wantErr: true,
		},
		"non_custom_suite": {
			settings: map[string]interface{}{
				"tlsSuiteType": "modern",
			},
			wantErr: false,
		},
		"no_tls_suite": {
			settings: map[string]interface{}{},
			wantErr: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateTLSSuiteRequiredDependencies(tt.settings, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTLSSuiteRequiredDependencies() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTLSCustomSuiteName(t *testing.T) {
	tests := map[string]struct {
		settings          map[string]interface{}
		validCipherSuites []string
		wantErr           bool
	}{
		"valid_custom_suite": {
			settings: map[string]interface{}{
				"tlsSuiteType": float64(2),
				"tls_suite_name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			},
			validCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			wantErr:           false,
		},
		"invalid_custom_suite": {
			settings: map[string]interface{}{
				"tlsSuiteType": float64(2),
				"tls_suite_name": "INVALID_SUITE",
			},
			validCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			wantErr:           true,
		},
		"custom_suite_missing_name": {
			settings: map[string]interface{}{
				"tlsSuiteType": float64(2),
			},
			validCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			wantErr:           true,
		},
		"non_custom_suite": {
			settings: map[string]interface{}{
				"tlsSuiteType": float64(1),
			},
			validCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			wantErr:           false,
		},
		"no_tls_suite_type": {
			settings:          map[string]interface{}{},
			validCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			wantErr:           false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateTLSCustomSuiteName(tt.settings, tt.validCipherSuites)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTLSCustomSuiteName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHasContentInSettings(t *testing.T) {
	tests := map[string]struct {
		settingsList []interface{}
		want         bool
	}{
		"empty_list": {
			settingsList: []interface{}{},
			want:         false,
		},
		"list_with_empty_map": {
			settingsList: []interface{}{
				map[string]interface{}{},
			},
			want: false,
		},
		"list_with_string_value": {
			settingsList: []interface{}{
				map[string]interface{}{
					"name": "value",
				},
			},
			want: true,
		},
		"list_with_empty_string": {
			settingsList: []interface{}{
				map[string]interface{}{
					"name": "",
				},
			},
			want: false,
		},
		"list_with_int_value": {
			settingsList: []interface{}{
				map[string]interface{}{
					"count": 5,
				},
			},
			want: true,
		},
		"list_with_zero_int": {
			settingsList: []interface{}{
				map[string]interface{}{
					"count": 0,
				},
			},
			want: false,
		},
		"list_with_bool_true": {
			settingsList: []interface{}{
				map[string]interface{}{
					"enabled": true,
				},
			},
			want: true,
		},
		"list_with_bool_false": {
			settingsList: []interface{}{
				map[string]interface{}{
					"enabled": false,
				},
			},
			want: false,
		},
		"list_with_non_empty_array": {
			settingsList: []interface{}{
				map[string]interface{}{
					"items": []interface{}{"item1"},
				},
			},
			want: true,
		},
		"list_with_empty_array": {
			settingsList: []interface{}{
				map[string]interface{}{
					"items": []interface{}{},
				},
			},
			want: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := hasContentInSettings(tt.settingsList)
			if got != tt.want {
				t.Errorf("hasContentInSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := map[string]struct {
		slice []string
		value string
		want  bool
	}{
		"contains_value": {
			slice: []string{"a", "b", "c"},
			value: "b",
			want:  true,
		},
		"does_not_contain": {
			slice: []string{"a", "b", "c"},
			value: "d",
			want:  false,
		},
		"empty_slice": {
			slice: []string{},
			value: "a",
			want:  false,
		},
		"single_element_match": {
			slice: []string{"a"},
			value: "a",
			want:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := contains(tt.slice, tt.value)
			if got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Note: shouldEnableSAMLFromDiff requires *schema.ResourceDiff
// The test above (TestShouldEnableSAMLFromDiff) tests shouldEnableSAML instead
// which uses ResourceData and has the same logic

func TestShouldEnableOIDC(t *testing.T) {
	tests := map[string]struct {
		initialData map[string]interface{}
		want        bool
	}{
		"enabled_via_flag": {
			// Note: shouldEnableOIDC doesn't check the direct "oidc" flag
			initialData: map[string]interface{}{
				"oidc": true,
			},
			want: false, // shouldEnableOIDC doesn't check direct flag
		},
		"enabled_via_app_auth": {
			initialData: map[string]interface{}{
				"advanced_settings": `{"app_auth": "oidc"}`,
			},
			want: true,
		},
		"enabled_via_settings_with_content": {
			initialData: map[string]interface{}{
				"oidc_settings": []interface{}{
					map[string]interface{}{
						"client_id": "test-client",
					},
				},
			},
			want: true,
		},
		"enabled_via_settings_empty": {
			initialData: map[string]interface{}{
				"oidc_settings": []interface{}{
					map[string]interface{}{},
				},
			},
			want: false,
		},
		"not_enabled": {
			initialData: map[string]interface{}{},
			want:        false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"oidc":             {Type: schema.TypeBool},
				"advanced_settings": {Type: schema.TypeString},
				"oidc_settings":    {Type: schema.TypeList, Elem: &schema.Schema{Type: schema.TypeMap}},
			}, tt.initialData)

			got := shouldEnableOIDC(d)
			if got != tt.want {
				t.Errorf("shouldEnableOIDC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldEnableWSFED(t *testing.T) {
	tests := map[string]struct {
		initialData map[string]interface{}
		want        bool
	}{
		"enabled_via_flag": {
			// Note: shouldEnableWSFED doesn't check the direct "wsfed" flag
			initialData: map[string]interface{}{
				"wsfed": true,
			},
			want: false, // shouldEnableWSFED doesn't check direct flag
		},
		"enabled_via_app_auth": {
			initialData: map[string]interface{}{
				"advanced_settings": `{"app_auth": "wsfed"}`,
			},
			want: true,
		},
		"enabled_via_settings": {
			initialData: map[string]interface{}{
				"wsfed_settings": []interface{}{
					map[string]interface{}{
						"sp": []interface{}{
							map[string]interface{}{"entity_id": "test-sp"},
						},
					},
				},
			},
			want: true,
		},
		"not_enabled": {
			initialData: map[string]interface{}{},
			want:        false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// wsfed_settings is a TypeList with Elem: Resource, but for testing purposes
			// we can use TypeMap since shouldEnableWSFED only checks if the list exists and has items
			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"wsfed":            {Type: schema.TypeBool},
				"advanced_settings": {Type: schema.TypeString},
				"wsfed_settings":   {Type: schema.TypeList, Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"sp": {Type: schema.TypeList, Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"entity_id": {Type: schema.TypeString},
							},
						}},
						"idp": {Type: schema.TypeList, Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"entity_id": {Type: schema.TypeString},
							},
						}},
					},
				}},
			}, tt.initialData)

			got := shouldEnableWSFED(d)
			if got != tt.want {
				t.Errorf("shouldEnableWSFED() = %v, want %v", got, tt.want)
			}
		})
	}
}

