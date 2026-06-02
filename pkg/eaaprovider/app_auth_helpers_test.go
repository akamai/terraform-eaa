package eaaprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
			requireErr(t, err, tc.wantErr)
		})
	}
}

// TestAppAuthConflictWithTopLevelFlags covers scenarios where app_auth in advanced_settings
// contradicts the presence of saml_settings/oidc_settings/wsfed_settings blocks.
// The shouldEnable* functions resolve these conflicts by enabling auth when EITHER
// app_auth matches OR the settings block is present (with content for OIDC).
func TestAppAuthConflictWithTopLevelFlags(t *testing.T) {
	tests := map[string]struct {
		data      map[string]interface{}
		wantSAML  bool
		wantOIDC  bool
		wantWSFED bool
	}{
		"app_auth_saml_enables_saml_without_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "saml",
				},
			},
			wantSAML: true, wantOIDC: false, wantWSFED: false,
		},
		"app_auth_oidc_enables_oidc_without_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "oidc",
				},
			},
			wantSAML: false, wantOIDC: true, wantWSFED: false,
		},
		"app_auth_wsfed_enables_wsfed_without_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "wsfed",
				},
			},
			wantSAML: false, wantOIDC: false, wantWSFED: true,
		},
		"app_auth_kerberos_with_saml_settings_enables_saml": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "kerberos",
				},
				"saml_settings": []interface{}{
					map[string]interface{}{
						"sp": []interface{}{
							map[string]interface{}{"entity_id": "test"},
						},
					},
				},
			},
			wantSAML: true, wantOIDC: false, wantWSFED: false,
		},
		"app_auth_ntlmv1_with_saml_settings_enables_saml": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "NTLMv1",
				},
				"saml_settings": []interface{}{
					map[string]interface{}{
						"sp": []interface{}{
							map[string]interface{}{"entity_id": "test"},
						},
					},
				},
			},
			wantSAML: true, wantOIDC: false, wantWSFED: false,
		},
		"app_auth_kerberos_alone_enables_nothing": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "kerberos",
				},
			},
			wantSAML: false, wantOIDC: false, wantWSFED: false,
		},
		"app_auth_none_enables_nothing": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "none",
				},
			},
			wantSAML: false, wantOIDC: false, wantWSFED: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := createTestApplicationResourceData(t, tc.data)
			assert.Equal(t, tc.wantSAML, shouldEnableSAML(d), "SAML mismatch")
			assert.Equal(t, tc.wantOIDC, shouldEnableOIDC(d), "OIDC mismatch")
			assert.Equal(t, tc.wantWSFED, shouldEnableWSFED(d), "WSFED mismatch")
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
		// Conflict: app_auth contradicts saml_settings presence.
		// saml_settings is present but app_auth=kerberos does not match SAML values,
		// so SAML is still enabled via the settings block fallback path.
		"conflict_kerberos_app_auth_with_saml_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "kerberos",
				},
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
			expected: true, // saml_settings presence wins over non-SAML app_auth
		},
		// Conflict: app_auth=NTLMv1 with saml_settings present.
		// Same fallback behavior: settings block enables SAML even though app_auth disagrees.
		"conflict_ntlmv1_app_auth_with_saml_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "NTLMv1",
				},
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
			expected: true, // saml_settings presence wins over non-SAML app_auth
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
		// Conflict: app_auth=saml but oidc_settings with content is present.
		// OIDC is enabled but app_auth=saml doesn't match OIDC values,
		// and oidc_settings requires actual content (CheckContent=true) to enable.
		"conflict_saml_app_auth_with_oidc_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "saml",
				},
				"oidc_settings": []interface{}{
					map[string]interface{}{
						"authorization_endpoint": "https://example.com/auth",
					},
				},
			},
			expected: true, // oidc_settings content wins over non-OIDC app_auth
		},
		// Conflict: app_auth=kerberos with oidc_settings present but empty.
		// OIDC requires content checking, so empty settings block does not enable OIDC.
		"conflict_kerberos_app_auth_with_empty_oidc_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "kerberos",
				},
				"oidc_settings": []interface{}{
					map[string]interface{}{},
				},
			},
			expected: false, // empty oidc_settings + non-OIDC app_auth = no OIDC
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
		// Conflict: app_auth=oidc but wsfed_settings present.
		// WSFED is enabled because wsfed_settings presence (without content check)
		// takes priority even when app_auth specifies a different auth type.
		"conflict_oidc_app_auth_with_wsfed_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "oidc",
				},
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
			expected: true, // wsfed_settings presence wins over non-WSFED app_auth
		},
		// Conflict: app_auth=NTLMv2 without wsfed_settings.
		// No WSFED signals at all, so WSFED is not enabled.
		"conflict_ntlmv2_app_auth_no_wsfed_settings": {
			data: map[string]interface{}{
				"advanced_settings": map[string]interface{}{
					"app_auth": "NTLMv2",
				},
			},
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
