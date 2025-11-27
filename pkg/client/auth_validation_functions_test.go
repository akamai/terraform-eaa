package client

import (
	"testing"

	"github.com/hashicorp/go-hclog"
)

// mockResourceDiff is a simple mock for ResourceDiff that implements SchemaGetter
type mockResourceDiff struct {
	data map[string]interface{}
}

func (m *mockResourceDiff) GetOk(key string) (interface{}, bool) {
	val, ok := m.data[key]
	return val, ok
}

func (m *mockResourceDiff) Get(key string) interface{} {
	return m.data[key]
}

func (m *mockResourceDiff) SetNew(key string, value interface{}) error {
	if m.data == nil {
		m.data = make(map[string]interface{})
	}
	m.data[key] = value
	return nil
}

// Note: Tests for functions requiring *schema.ResourceDiff (ValidateWSFEDNestedBlocks,
// ValidateSAMLNestedBlocks, ValidateOIDCNestedBlocks) are in pkg/eaaprovider/auth_validation_resource_diff_test.go
// These use terraform-plugin-testing/helper/resource with PlanOnly: true to create proper ResourceDiff instances

func TestValidateIDPSelfSignedCert(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		idpBlock      map[string]interface{}
		protocolName  string
		signCertError error
		wantErr       bool
	}{
		"self_signed_true": {
			idpBlock: map[string]interface{}{
				"self_signed": true,
			},
			protocolName:  "SAML",
			signCertError: ErrSAMLSignCertRequired,
			wantErr:       false,
		},
		"self_signed_false_with_sign_cert": {
			idpBlock: map[string]interface{}{
				"self_signed": false,
				"sign_cert":   "cert-data",
			},
			protocolName:  "SAML",
			signCertError: ErrSAMLSignCertRequired,
			wantErr:       false,
		},
		"self_signed_false_without_sign_cert": {
			idpBlock: map[string]interface{}{
				"self_signed": false,
			},
			protocolName:  "SAML",
			signCertError: ErrSAMLSignCertRequired,
			wantErr:       true,
		},
		"self_signed_false_with_empty_sign_cert": {
			idpBlock: map[string]interface{}{
				"self_signed": false,
				"sign_cert":   "",
			},
			protocolName:  "SAML",
			signCertError: ErrSAMLSignCertRequired,
			wantErr:       true,
		},
		"no_self_signed_field": {
			idpBlock: map[string]interface{}{
				"sign_cert": "cert-data",
			},
			protocolName:  "SAML",
			signCertError: ErrSAMLSignCertRequired,
			wantErr:       false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateIDPSelfSignedCert(tt.idpBlock, tt.protocolName, tt.signCertError, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIDPSelfSignedCert() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Note: ValidateWSFEDNestedBlocks, ValidateSAMLNestedBlocks, ValidateOIDCNestedBlocks
// require *schema.ResourceDiff which is difficult to mock.
// These should be tested via integration tests using Terraform's testing framework.

func TestValidateOIDCClientNested(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		clientConfig map[string]interface{}
		index         int
		wantErr       bool
	}{
		"valid_client": {
			clientConfig: map[string]interface{}{
				"response_type": []interface{}{"code"},
				"redirect_uris": []interface{}{"https://example.com"},
			},
			index:   0,
			wantErr: false,
		},
		"invalid_response_type": {
			clientConfig: map[string]interface{}{
				"response_type": "not-an-array",
			},
			index:   0,
			wantErr: true,
		},
		"invalid_redirect_uris": {
			clientConfig: map[string]interface{}{
				"redirect_uris": "not-an-array",
			},
			index:   0,
			wantErr: true,
		},
		"valid_with_claims": {
			clientConfig: map[string]interface{}{
				"claims": []interface{}{
					map[string]interface{}{"name": "claim1"},
				},
			},
			index:   0,
			wantErr: false,
		},
		"invalid_claims_not_array": {
			clientConfig: map[string]interface{}{
				"claims": "not-an-array",
			},
			index:   0,
			wantErr: true,
		},
		"invalid_javascript_origins_not_array": {
			clientConfig: map[string]interface{}{
				"javascript_origins": "not-an-array",
			},
			index:   0,
			wantErr: true,
		},
		"invalid_post_logout_redirect_uri_not_array": {
			clientConfig: map[string]interface{}{
				"post_logout_redirect_uri": "not-an-array",
			},
			index:   0,
			wantErr: true,
		},
		"valid_with_javascript_origins": {
			clientConfig: map[string]interface{}{
				"javascript_origins": []interface{}{"https://example.com"},
			},
			index:   0,
			wantErr: false,
		},
		"valid_with_post_logout_redirect_uri": {
			clientConfig: map[string]interface{}{
				"post_logout_redirect_uri": []interface{}{"https://example.com/logout"},
			},
			index:   0,
			wantErr: false,
		},
		"valid_with_all_fields": {
			clientConfig: map[string]interface{}{
				"response_type":            []interface{}{"code"},
				"redirect_uris":            []interface{}{"https://example.com"},
				"javascript_origins":      []interface{}{"https://example.com"},
				"post_logout_redirect_uri": []interface{}{"https://example.com/logout"},
				"claims": []interface{}{
					map[string]interface{}{"name": "claim1"},
				},
			},
			index:   0,
			wantErr: false,
		},
		"invalid_claim_not_object": {
			clientConfig: map[string]interface{}{
				"claims": []interface{}{
					"not-an-object",
				},
			},
			index:   0,
			wantErr: true,
		},
		"invalid_claim_empty": {
			clientConfig: map[string]interface{}{
				"claims": []interface{}{
					map[string]interface{}{},
				},
			},
			index:   0,
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateOIDCClientNested(tt.clientConfig, tt.index, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOIDCClientNested() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOIDCClaimNested(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		claim   map[string]interface{}
		index   int
		wantErr bool
	}{
		"valid_claim": {
			claim: map[string]interface{}{
				"name": "claim1",
			},
			index:   0,
			wantErr: false,
		},
		"empty_claim": {
			claim:   map[string]interface{}{},
			index:   0,
			wantErr: true,
		},
		"claim_with_multiple_fields": {
			claim: map[string]interface{}{
				"name":  "claim1",
				"value": "value1",
			},
			index:   0,
			wantErr: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateOIDCClaimNested(tt.claim, tt.index, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOIDCClaimNested() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

