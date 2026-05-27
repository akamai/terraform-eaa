package client

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			if tt.wantErr {
				require.Error(t, err)
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
			require.NoError(t, err)
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
			if tt.wantErr {
				require.Error(t, err)
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
			require.NoError(t, err)
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
			if tt.wantErr {
				require.Error(t, err)
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}
