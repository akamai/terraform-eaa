package client

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

// mapBackedAuthSettingsLookup is a lightweight GetOk() adapter used for unit tests.
// It mimics Terraform's GetOk behavior by treating common zero values as "not set".
type mapBackedAuthSettingsLookup map[string]interface{}

func (m mapBackedAuthSettingsLookup) GetOk(key string) (interface{}, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false
	}

	switch val := v.(type) {
	case bool:
		if !val {
			return nil, false
		}
	case string:
		if val == "" {
			return nil, false
		}
	case int:
		if val == 0 {
			return nil, false
		}
	case int64:
		if val == 0 {
			return nil, false
		}
	case float64:
		if val == 0 {
			return nil, false
		}
	case []interface{}:
		if len(val) == 0 {
			return nil, false
		}
	case map[string]interface{}:
		if len(val) == 0 {
			return nil, false
		}
	}

	return v, true
}

func TestValidateCustomHeadersConfiguration(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		errIs    error
		settings map[string]interface{}
		appType  string
		wantErr  bool
	}{
		"no_custom_headers": {
			settings: map[string]interface{}{},
			appType:  "enterprise",
		},
		"valid_enterprise_headers": {
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom",
						"attribute_type": "fixed",
						"attribute":      "my-value",
					},
				},
			},
			appType: "enterprise",
		},
		"valid_enterprise_user_type": {
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-User",
						"attribute_type": "user",
					},
				},
			},
			appType: "enterprise",
		},
		"saas_not_supported": {
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom",
						"attribute_type": "fixed",
						"attribute":      "val",
					},
				},
			},
			appType: "saas",
			wantErr: true,
			errIs:   ErrCustomHeadersNotSupportedForSaaS,
		},
		"tunnel_not_supported": {
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom",
						"attribute_type": "fixed",
						"attribute":      "val",
					},
				},
			},
			appType: "tunnel",
			wantErr: true,
			errIs:   ErrCustomHeadersNotSupportedForTunnel,
		},
		"bookmark_not_supported": {
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Custom",
						"attribute_type": "fixed",
						"attribute":      "val",
					},
				},
			},
			appType: "bookmark",
			wantErr: true,
			errIs:   ErrCustomHeadersNotSupportedForSaaS,
		},
		"not_array": {
			settings: map[string]interface{}{
				"custom_headers": "not-an-array",
			},
			appType: "enterprise",
			wantErr: true,
			errIs:   ErrCustomHeadersNotArray,
		},
		"empty_headers_sanitized": {
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "",
						"attribute_type": "",
					},
				},
			},
			appType: "enterprise",
			wantErr: false, // empty headers are sanitized out
		},
		"empty_app_type_allows_validation": {
			settings: map[string]interface{}{
				"custom_headers": []interface{}{
					map[string]interface{}{
						"header":         "X-Test",
						"attribute_type": "user",
					},
				},
			},
			appType: "",
			wantErr: false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateCustomHeadersConfiguration(tt.settings, tt.appType, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
		})
	}
}

func TestValidateCustomHeader(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		errIs   error
		header  map[string]interface{}
		wantErr bool
	}{
		"valid_fixed": {
			header: map[string]interface{}{
				"header":         "X-Custom",
				"attribute_type": "fixed",
				"attribute":      "my-value",
			},
		},
		"valid_custom": {
			header: map[string]interface{}{
				"header":         "X-Custom",
				"attribute_type": "custom",
				"attribute":      "my-expression",
			},
		},
		"valid_user": {
			header: map[string]interface{}{
				"header":         "X-User",
				"attribute_type": "user",
			},
		},
		"valid_group": {
			header: map[string]interface{}{
				"header":         "X-Group",
				"attribute_type": "group",
			},
		},
		"valid_clientip": {
			header: map[string]interface{}{
				"header":         "X-ClientIP",
				"attribute_type": "clientip",
			},
		},
		"empty_header_and_attribute_type": {
			header: map[string]interface{}{
				"header":         "",
				"attribute_type": "",
			},
			wantErr: false, // skipped as empty
		},
		"missing_header_field": {
			header:  map[string]interface{}{"attribute_type": "user"},
			wantErr: true,
			errIs:   ErrCustomHeaderMissingHeader,
		},
		"empty_header_value": {
			header: map[string]interface{}{
				"header":         "",
				"attribute_type": "user",
			},
			wantErr: true,
			errIs:   ErrCustomHeaderHeaderEmpty,
		},
		"invalid_attribute_type": {
			header: map[string]interface{}{
				"header":         "X-Custom",
				"attribute_type": "invalid-type",
			},
			wantErr: true,
			errIs:   ErrCustomHeaderAttributeTypeInvalid,
		},
		"fixed_missing_attribute": {
			header: map[string]interface{}{
				"header":         "X-Custom",
				"attribute_type": "fixed",
			},
			wantErr: true,
			errIs:   ErrCustomHeaderAttributeRequired,
		},
		"fixed_empty_attribute": {
			header: map[string]interface{}{
				"header":         "X-Custom",
				"attribute_type": "fixed",
				"attribute":      "",
			},
			wantErr: true,
			errIs:   ErrCustomHeaderAttributeEmpty,
		},
		"custom_missing_attribute": {
			header: map[string]interface{}{
				"header":         "X-Custom",
				"attribute_type": "custom",
			},
			wantErr: true,
			errIs:   ErrCustomHeaderAttributeRequired,
		},
		"attribute_without_attribute_type": {
			header: map[string]interface{}{
				"header":    "X-Custom",
				"attribute": "some-value",
			},
			wantErr: true,
			errIs:   ErrCustomHeaderAttributeNotAllowed,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateCustomHeader(tt.header, 0, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
		})
	}
}

func TestValidateIDPSelfSignedCert(t *testing.T) {
	logger := hclog.NewNullLogger()
	testError := ErrSAMLSignCertRequired

	tests := map[string]struct {
		errIs    error
		idpBlock map[string]interface{}
		wantErr  bool
	}{
		"self_signed_true": {
			idpBlock: map[string]interface{}{
				"self_signed": true,
			},
		},
		"self_signed_false_with_cert": {
			idpBlock: map[string]interface{}{
				"self_signed": false,
				"sign_cert":   "my-cert-data",
			},
		},
		"self_signed_false_missing_cert": {
			idpBlock: map[string]interface{}{
				"self_signed": false,
			},
			wantErr: true,
			errIs:   testError,
		},
		"self_signed_false_empty_cert": {
			idpBlock: map[string]interface{}{
				"self_signed": false,
				"sign_cert":   "",
			},
			wantErr: true,
			errIs:   testError,
		},
		"no_self_signed_key": {
			idpBlock: map[string]interface{}{},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateIDPSelfSignedCert(tt.idpBlock, "SAML", testError, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
		})
	}
}

func TestValidateWSFEDNestedBlocks(t *testing.T) {
	logger := hclog.NewNullLogger()
	ctx := context.Background()

	tests := map[string]struct {
		errIs      error
		lookup     mapBackedAuthSettingsLookup
		errContain string
		wantErr    bool
	}{
		"protocol_disabled_skips_validation": {
			lookup: mapBackedAuthSettingsLookup{
				"wsfed_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
		},
		"protocol_enabled_via_app_auth": {
			lookup: mapBackedAuthSettingsLookup{
				"advanced_settings": map[string]interface{}{"app_auth": "wsfed"},
				"wsfed_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
			wantErr: true,
			errIs:   ErrWSFEDSignCertRequired,
		},
		"app_auth_not_enabling_protocol_skips_validation": {
			lookup: mapBackedAuthSettingsLookup{
				"advanced_settings": map[string]interface{}{"app_auth": "saml"},
				"wsfed_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
			// should skip WSFED validation since app_auth = saml
		},
		"self_signed_false_missing_sign_cert": {
			lookup: mapBackedAuthSettingsLookup{
				"wsfed": true,
				"wsfed_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
			wantErr: true,
			errIs:   ErrWSFEDSignCertRequired,
		},
		"self_signed_false_empty_sign_cert": {
			lookup: mapBackedAuthSettingsLookup{
				"wsfed": true,
				"wsfed_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
						"sign_cert":   "",
					}},
				}},
			},
			wantErr: true,
			errIs:   ErrWSFEDSignCertRequired,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateWSFEDNestedBlocks(ctx, tt.lookup, nil, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				if tt.errContain != "" {
					assert.ErrorContains(t, err, tt.errContain)
				}
				return
			}
		})
	}
}

func TestValidateSAMLNestedBlocks(t *testing.T) {
	logger := hclog.NewNullLogger()
	ctx := context.Background()

	tests := map[string]struct {
		errIs      error
		lookup     mapBackedAuthSettingsLookup
		errContain string
		wantErr    bool
	}{
		"protocol_disabled_skips_validation": {
			lookup: mapBackedAuthSettingsLookup{
				"saml_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
		},
		"protocol_enabled_via_app_auth": {
			lookup: mapBackedAuthSettingsLookup{
				"advanced_settings": map[string]interface{}{"app_auth": "saml"},
				"saml_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
			wantErr: true,
			errIs:   ErrSAMLSignCertRequired,
		},
		"app_auth_not_enabling_protocol_skips_validation": {
			lookup: mapBackedAuthSettingsLookup{
				"advanced_settings": map[string]interface{}{"app_auth": "wsfed"},
				"saml_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
			// should skip SAML validation since app_auth = wsfed
		},
		"self_signed_false_missing_sign_cert": {
			lookup: mapBackedAuthSettingsLookup{
				"saml": true,
				"saml_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
					}},
				}},
			},
			wantErr: true,
			errIs:   ErrSAMLSignCertRequired,
		},
		"self_signed_false_empty_sign_cert": {
			lookup: mapBackedAuthSettingsLookup{
				"saml": true,
				"saml_settings": []interface{}{map[string]interface{}{
					"idp": []interface{}{map[string]interface{}{
						"self_signed": false,
						"sign_cert":   "",
					}},
				}},
			},
			wantErr: true,
			errIs:   ErrSAMLSignCertRequired,
		},
		"duplicate_attrmap_name": {
			lookup: mapBackedAuthSettingsLookup{
				"saml": true,
				"saml_settings": []interface{}{map[string]interface{}{
					"attrmap": []interface{}{
						map[string]interface{}{"name": "email"},
						map[string]interface{}{"name": "email"},
					},
				}},
			},
			wantErr:    true,
			errContain: "duplicate attribute name 'email' found in attrmap",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateSAMLNestedBlocks(ctx, tt.lookup, nil, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				if tt.errContain != "" {
					assert.ErrorContains(t, err, tt.errContain)
				}
				return
			}
		})
	}
}

func TestValidateOIDCNestedBlocks(t *testing.T) {
	logger := hclog.NewNullLogger()
	ctx := context.Background()

	tests := map[string]struct {
		errIs      error
		lookup     mapBackedAuthSettingsLookup
		errContain string
		wantErr    bool
	}{
		"protocol_disabled_skips_validation": {
			lookup: mapBackedAuthSettingsLookup{
				"oidc_settings": []interface{}{map[string]interface{}{
					"oidc_clients": []interface{}{map[string]interface{}{"response_type": "code"}},
				}},
			},
		},
		"protocol_enabled_via_app_auth": {
			lookup: mapBackedAuthSettingsLookup{
				"advanced_settings": map[string]interface{}{"app_auth": "oidc"},
				"oidc_settings": []interface{}{map[string]interface{}{
					"oidc_clients": []interface{}{map[string]interface{}{"response_type": "code"}},
				}},
			},
			wantErr: true,
			errIs:   ErrOIDCClientValidation,
		},
		"app_auth_not_enabling_protocol_skips_validation": {
			lookup: mapBackedAuthSettingsLookup{
				"advanced_settings": map[string]interface{}{"app_auth": "saml"},
				"oidc_settings": []interface{}{map[string]interface{}{
					"oidc_clients": []interface{}{map[string]interface{}{"response_type": "code"}},
				}},
			},
			// should skip OIDC validation since app_auth = saml
		},
		"empty_block_skips_validation": {
			lookup: mapBackedAuthSettingsLookup{
				"oidc":          true,
				"oidc_settings": []interface{}{map[string]interface{}{}},
			},
		},
		"invalid_nested_client_field_types_return_validation_error": {
			lookup: mapBackedAuthSettingsLookup{
				"oidc": true,
				"oidc_settings": []interface{}{map[string]interface{}{
					"oidc_clients": []interface{}{map[string]interface{}{"response_type": "code"}},
				}},
			},
			wantErr: true,
			errIs:   ErrOIDCClientValidation,
		},
		"valid_nested_client_passes": {
			lookup: mapBackedAuthSettingsLookup{
				"oidc": true,
				"oidc_settings": []interface{}{map[string]interface{}{
					"oidc_clients": []interface{}{map[string]interface{}{
						"response_type":            []interface{}{"code"},
						"redirect_uris":            []interface{}{"https://example.com/callback"},
						"javascript_origins":       []interface{}{"https://example.com"},
						"post_logout_redirect_uri": []interface{}{"https://example.com/logout"},
						"claims":                   []interface{}{map[string]interface{}{"name": "sub"}},
					}},
				}},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateOIDCNestedBlocks(ctx, tt.lookup, nil, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				if tt.errContain != "" {
					assert.ErrorContains(t, err, tt.errContain)
				}
				return
			}
		})
	}
}

func TestValidateOIDCClientNested(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		clientConfig map[string]interface{}
		errIs        error
		wantErr      bool
	}{
		"redirect_uris_not_array": {
			clientConfig: map[string]interface{}{"redirect_uris": "https://example.com/callback"},
			wantErr:      true,
			errIs:        ErrOIDCRedirectURIsNotArray,
		},
		"javascript_origins_not_array": {
			clientConfig: map[string]interface{}{"javascript_origins": "https://example.com"},
			wantErr:      true,
			errIs:        ErrOIDCJavaScriptOriginsNotArray,
		},
		"post_logout_redirect_uri_not_array": {
			clientConfig: map[string]interface{}{"post_logout_redirect_uri": "https://example.com/logout"},
			wantErr:      true,
			errIs:        ErrOIDCPostLogoutURIsNotArray,
		},
		"claims_not_array": {
			clientConfig: map[string]interface{}{"claims": "not-a-list"},
			wantErr:      true,
			errIs:        ErrOIDCClaimsNotArray,
		},
		"claim_not_object": {
			clientConfig: map[string]interface{}{"claims": []interface{}{"not-an-object"}},
			wantErr:      true,
			errIs:        ErrOIDCClaimNotObject,
		},
		"empty_claim_object": {
			clientConfig: map[string]interface{}{"claims": []interface{}{map[string]interface{}{}}},
			wantErr:      true,
			errIs:        ErrOIDCClaimValidation,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateOIDCClientNested(tt.clientConfig, 0, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
		})
	}
}

func TestValidateOIDCClaimNested(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		claim   map[string]interface{}
		errIs   error
		wantErr bool
	}{
		"empty_claim": {
			claim:   map[string]interface{}{},
			wantErr: true,
			errIs:   ErrOIDCClaimEmpty,
		},
		"non_empty_claim": {
			claim: map[string]interface{}{"name": "sub"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateOIDCClaimNested(tt.claim, 0, logger)
			if requireErr(t, err, tt.wantErr) {
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
		})
	}
}
