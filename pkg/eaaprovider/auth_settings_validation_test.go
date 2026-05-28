package eaaprovider

import (
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// validateSAMLSigningAlgorithm
// ---------------------------------------------------------------------------

func TestValidateSAMLSigningAlgorithm(t *testing.T) {
	tests := map[string]struct {
		val      interface{}
		wantErrs bool
	}{
		"valid_SHA1": {
			val:      string(client.SAMLSigningAlgorithmSHA1),
			wantErrs: false,
		},
		"valid_SHA256": {
			val:      string(client.SAMLSigningAlgorithmSHA256),
			wantErrs: false,
		},
		"invalid_SHA512": {
			val:      "SHA512",
			wantErrs: true,
		},
		"invalid_empty": {
			val:      "",
			wantErrs: true,
		},
		"invalid_non_string": {
			val:      123,
			wantErrs: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLSigningAlgorithm(tc.val, "sign_algo")
			assert.Empty(t, warns)
			if tc.wantErrs {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateSAMLEncryptionAlgorithm
// ---------------------------------------------------------------------------

func TestValidateSAMLEncryptionAlgorithm(t *testing.T) {
	tests := map[string]struct {
		val      interface{}
		wantErrs bool
	}{
		"valid_aes128-cbc": {
			val:      string(client.SAMLEncryptionAlgorithmAES128CBC),
			wantErrs: false,
		},
		"valid_aes256-cbc": {
			val:      string(client.SAMLEncryptionAlgorithmAES256CBC),
			wantErrs: false,
		},
		"invalid_aes192-cbc": {
			// Not in the validation function's valid list (only aes128 and aes256)
			val:      "aes192-cbc",
			wantErrs: true,
		},
		"invalid_empty": {
			val:      "",
			wantErrs: true,
		},
		"invalid_non_string": {
			val:      42,
			wantErrs: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLEncryptionAlgorithm(tc.val, "encr_algo")
			assert.Empty(t, warns)
			if tc.wantErrs {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateSAMLResponseBinding
// ---------------------------------------------------------------------------

func TestValidateSAMLResponseBinding(t *testing.T) {
	tests := map[string]struct {
		val      interface{}
		wantErrs bool
	}{
		"valid_post": {
			val:      string(client.SAMLResponseBindingPost),
			wantErrs: false,
		},
		"valid_redirect": {
			val:      string(client.SAMLResponseBindingRedirect),
			wantErrs: false,
		},
		"invalid_artifact": {
			val:      "artifact",
			wantErrs: true,
		},
		"invalid_empty": {
			val:      "",
			wantErrs: true,
		},
		"invalid_non_string": {
			val:      true,
			wantErrs: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLResponseBinding(tc.val, "resp_bind")
			assert.Empty(t, warns)
			if tc.wantErrs {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateSAMLSubjectFormat
// ---------------------------------------------------------------------------

func TestValidateSAMLSubjectFormat(t *testing.T) {
	tests := map[string]struct {
		val      interface{}
		wantErrs bool
	}{
		"valid_email": {
			val:      string(client.SAMLSubjectFormatEmail),
			wantErrs: false,
		},
		"valid_persistent": {
			val:      string(client.SAMLSubjectFormatPersistent),
			wantErrs: false,
		},
		"valid_unspecified": {
			val:      "unspecified",
			wantErrs: false,
		},
		"valid_transient": {
			val:      string(client.SAMLSubjectFormatTransient),
			wantErrs: false,
		},
		"invalid_nameid": {
			// nameid is defined in constants but NOT in the validation function's valid list
			val:      "nameid",
			wantErrs: true,
		},
		"invalid_empty": {
			val:      "",
			wantErrs: true,
		},
		"invalid_non_string": {
			val:      999,
			wantErrs: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLSubjectFormat(tc.val, "subject_fmt")
			assert.Empty(t, warns)
			if tc.wantErrs {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateOIDCClientType
// ---------------------------------------------------------------------------

func TestValidateOIDCClientType(t *testing.T) {
	tests := map[string]struct {
		val      interface{}
		wantErrs bool
	}{
		"valid_standard": {
			val:      string(client.OIDCClientTypeStandard),
			wantErrs: false,
		},
		"valid_confidential": {
			val:      string(client.OIDCClientTypeConfidential),
			wantErrs: false,
		},
		"valid_public": {
			val:      string(client.OIDCClientTypePublic),
			wantErrs: false,
		},
		"invalid_bearer": {
			val:      "bearer",
			wantErrs: true,
		},
		"invalid_empty": {
			val:      "",
			wantErrs: true,
		},
		"invalid_non_string": {
			val:      []string{"standard"},
			wantErrs: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateOIDCClientType(tc.val, "client_type")
			assert.Empty(t, warns)
			if tc.wantErrs {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateOIDCResponseType
// ---------------------------------------------------------------------------

func TestValidateOIDCResponseType(t *testing.T) {
	tests := map[string]struct {
		val      interface{}
		wantErrs bool
	}{
		"valid_code": {
			val:      string(client.OIDCResponseTypeCode),
			wantErrs: false,
		},
		"valid_id_token": {
			val:      string(client.OIDCResponseTypeIDToken),
			wantErrs: false,
		},
		"valid_token": {
			val:      string(client.OIDCResponseTypeToken),
			wantErrs: false,
		},
		"valid_code_id_token": {
			val:      string(client.OIDCResponseTypeCodeIDToken),
			wantErrs: false,
		},
		"valid_code_token": {
			val:      string(client.OIDCResponseTypeCodeToken),
			wantErrs: false,
		},
		"valid_id_token_token": {
			val:      string(client.OIDCResponseTypeIDTokenToken),
			wantErrs: false,
		},
		"valid_code_id_token_token": {
			val:      string(client.OIDCResponseTypeCodeIDTokenToken),
			wantErrs: false,
		},
		"invalid_password": {
			val:      "password",
			wantErrs: true,
		},
		"invalid_empty": {
			val:      "",
			wantErrs: true,
		},
		"invalid_non_string": {
			val:      42,
			wantErrs: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateOIDCResponseType(tc.val, "response_type")
			assert.Empty(t, warns)
			if tc.wantErrs {
				assert.NotEmpty(t, errs, "expected validation error")
			} else {
				assert.Empty(t, errs, "expected no validation errors")
			}
		})
	}
}
