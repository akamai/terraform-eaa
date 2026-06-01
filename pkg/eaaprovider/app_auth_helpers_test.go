package eaaprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthenticationMethodsForAppType_Bookmark(t *testing.T) {
	tests := map[string]struct {
		data    map[string]interface{}
		wantErr bool
	}{
		"bookmark_with_saml_rejected": {
			data: map[string]interface{}{
				"app_type": "bookmark",
				"saml":     true,
			},
			wantErr: true,
		},
		"bookmark_with_oidc_rejected": {
			data: map[string]interface{}{
				"app_type": "bookmark",
				"oidc":     true,
			},
			wantErr: true,
		},
		"bookmark_with_wsfed_rejected": {
			data: map[string]interface{}{
				"app_type": "bookmark",
				"wsfed":    true,
			},
			wantErr: true,
		},
		"bookmark_without_auth_allowed": {
			data: map[string]interface{}{
				"app_type": "bookmark",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestApplicationResourceData(t, tc.data)
			err := validateAuthenticationMethodsForAppType(d)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestShouldEnableAuthForSchema(t *testing.T) {
	tests := map[string]struct {
		data     map[string]interface{}
		config   AuthEnableConfig
		expected bool
	}{
		"saml_via_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "saml",
				},
			},
			config:   AuthEnableConfig{AppAuthValues: []string{"saml", "SAML2.0"}, SettingsKey: "saml_settings"},
			expected: true,
		},
		"oidc_via_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "oidc",
				},
			},
			config:   AuthEnableConfig{AppAuthValues: []string{"oidc", "OIDC"}, SettingsKey: "oidc_settings", CheckContent: true},
			expected: true,
		},
		"no_match": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "basic",
				},
			},
			config:   AuthEnableConfig{AppAuthValues: []string{"saml"}, SettingsKey: "saml_settings"},
			expected: false,
		},
		"empty_app_auth": {
			data:     map[string]interface{}{},
			config:   AuthEnableConfig{AppAuthValues: []string{"saml"}, SettingsKey: "saml_settings"},
			expected: false,
		},
		"saml_via_settings_block": {
			data: map[string]interface{}{
				"saml_settings": []interface{}{
					map[string]interface{}{
						"sp": []interface{}{
							map[string]interface{}{
								"entity_id": "test-entity",
							},
						},
					},
				},
			},
			config:   AuthEnableConfig{AppAuthValues: []string{"saml", "SAML2.0"}, SettingsKey: "saml_settings"},
			expected: true,
		},
		"oidc_via_settings_block_with_content": {
			data: map[string]interface{}{
				"oidc_settings": []interface{}{
					map[string]interface{}{
						"authorization_endpoint": "https://example.com/auth",
					},
				},
			},
			config:   AuthEnableConfig{AppAuthValues: []string{"oidc", "OIDC"}, SettingsKey: "oidc_settings", CheckContent: true},
			expected: true,
		},
		"oidc_via_settings_block_empty": {
			data: map[string]interface{}{
				"oidc_settings": []interface{}{
					map[string]interface{}{},
				},
			},
			config:   AuthEnableConfig{AppAuthValues: []string{"oidc", "OIDC"}, SettingsKey: "oidc_settings", CheckContent: true},
			expected: false,
		},
		"wsfed_via_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "wsfed",
				},
			},
			config:   AuthEnableConfig{AppAuthValues: []string{"wsfed", "WS-Federation"}, SettingsKey: "wsfed_settings"},
			expected: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestApplicationResourceData(t, tc.data)
			result := shouldEnableAuthForSchema(d, tc.config)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestShouldEnableSAML(t *testing.T) {
	tests := map[string]struct {
		data     map[string]interface{}
		expected bool
	}{
		"saml_in_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "saml",
				},
			},
			expected: true,
		},
		"saml2_in_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "SAML2.0",
				},
			},
			expected: true,
		},
		"saml_settings_present": {
			data: map[string]interface{}{
				"saml_settings": []interface{}{
					map[string]interface{}{
						"sp": []interface{}{
							map[string]interface{}{
								"entity_id": "test-entity",
							},
						},
					},
				},
			},
			expected: true,
		},
		"no_saml_config": {
			data:     map[string]interface{}{},
			expected: false,
		},
		"other_auth_method": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "oidc",
				},
			},
			expected: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestApplicationResourceData(t, tc.data)
			result := shouldEnableSAML(d)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestShouldEnableOIDC(t *testing.T) {
	tests := map[string]struct {
		data     map[string]interface{}
		expected bool
	}{
		"oidc_in_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "oidc",
				},
			},
			expected: true,
		},
		"oidc_full_in_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "OpenID Connect 1.0",
				},
			},
			expected: true,
		},
		"oidc_settings_with_content": {
			data: map[string]interface{}{
				"oidc_settings": []interface{}{
					map[string]interface{}{
						"authorization_endpoint": "https://example.com/auth",
					},
				},
			},
			expected: true,
		},
		"oidc_settings_empty": {
			data: map[string]interface{}{
				"oidc_settings": []interface{}{
					map[string]interface{}{},
				},
			},
			expected: false,
		},
		"no_oidc_config": {
			data:     map[string]interface{}{},
			expected: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestApplicationResourceData(t, tc.data)
			result := shouldEnableOIDC(d)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestShouldEnableWSFED(t *testing.T) {
	tests := map[string]struct {
		data     map[string]interface{}
		expected bool
	}{
		"wsfed_in_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "wsfed",
				},
			},
			expected: true,
		},
		"wsfed_full_in_app_auth": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "WS-Federation",
				},
			},
			expected: true,
		},
		"wsfed_settings_present": {
			data: map[string]interface{}{
				"wsfed_settings": []interface{}{
					map[string]interface{}{
						"sp": []interface{}{
							map[string]interface{}{
								"entity_id": "test-entity",
							},
						},
					},
				},
			},
			expected: true,
		},
		"no_wsfed_config": {
			data:     map[string]interface{}{},
			expected: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestApplicationResourceData(t, tc.data)
			result := shouldEnableWSFED(d)
			assert.Equal(t, tc.expected, result)
		})
	}
}
