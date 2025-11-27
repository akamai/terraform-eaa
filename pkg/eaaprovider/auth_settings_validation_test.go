package eaaprovider

import (
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
)

func TestValidateSAMLSigningAlgorithm(t *testing.T) {
	tests := map[string]struct {
		value   interface{}
		key     string
		wantErr bool
	}{
		"valid_sha1": {
			value:   string(client.SAMLSigningAlgorithmSHA1),
			key:     "signing_algorithm",
			wantErr: false,
		},
		"valid_sha256": {
			value:   string(client.SAMLSigningAlgorithmSHA256),
			key:     "signing_algorithm",
			wantErr: false,
		},
		"invalid_sha384": {
			value:   string(client.SAMLSigningAlgorithmSHA384),
			key:     "signing_algorithm",
			wantErr: true,
		},
		"invalid_sha512": {
			value:   string(client.SAMLSigningAlgorithmSHA512),
			key:     "signing_algorithm",
			wantErr: true,
		},
		"invalid_algorithm": {
			value:   "MD5",
			key:     "signing_algorithm",
			wantErr: true,
		},
		"invalid_type": {
			value:   123,
			key:     "signing_algorithm",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLSigningAlgorithm(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateSAMLSigningAlgorithm() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

func TestValidateSAMLEncryptionAlgorithm(t *testing.T) {
	tests := map[string]struct {
		value   interface{}
		key     string
		wantErr bool
	}{
		"valid_aes128": {
			value:   string(client.SAMLEncryptionAlgorithmAES128CBC),
			key:     "encryption_algorithm",
			wantErr: false,
		},
		"valid_aes256": {
			value:   string(client.SAMLEncryptionAlgorithmAES256CBC),
			key:     "encryption_algorithm",
			wantErr: false,
		},
		"invalid_aes192": {
			value:   string(client.SAMLEncryptionAlgorithmAES192CBC),
			key:     "encryption_algorithm",
			wantErr: true,
		},
		"invalid_tripledes": {
			value:   string(client.SAMLEncryptionAlgorithmTripleDESCBC),
			key:     "encryption_algorithm",
			wantErr: true,
		},
		"invalid_algorithm": {
			value:   "DES",
			key:     "encryption_algorithm",
			wantErr: true,
		},
		"invalid_type": {
			value:   123,
			key:     "encryption_algorithm",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLEncryptionAlgorithm(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateSAMLEncryptionAlgorithm() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

func TestValidateSAMLResponseBinding(t *testing.T) {
	tests := map[string]struct {
		value   interface{}
		key     string
		wantErr bool
	}{
		"valid_post": {
			value:   string(client.SAMLResponseBindingPost),
			key:     "response_binding",
			wantErr: false,
		},
		"valid_redirect": {
			value:   string(client.SAMLResponseBindingRedirect),
			key:     "response_binding",
			wantErr: false,
		},
		"invalid_binding": {
			value:   "GET",
			key:     "response_binding",
			wantErr: true,
		},
		"invalid_type": {
			value:   123,
			key:     "response_binding",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLResponseBinding(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateSAMLResponseBinding() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

func TestValidateSAMLSubjectFormat(t *testing.T) {
	tests := map[string]struct {
		value   interface{}
		key     string
		wantErr bool
	}{
		"valid_email": {
			value:   "email",
			key:     "subject_format",
			wantErr: false,
		},
		"invalid_nameid": {
			value:   string(client.SAMLSubjectFormatNameID),
			key:     "subject_format",
			wantErr: true,
		},
		"valid_persistent": {
			value:   "persistent",
			key:     "subject_format",
			wantErr: false,
		},
		"valid_transient": {
			value:   "transient",
			key:     "subject_format",
			wantErr: false,
		},
		"valid_unspecified": {
			value:   "unspecified",
			key:     "subject_format",
			wantErr: false,
		},
		"invalid_format": {
			value:   "invalid",
			key:     "subject_format",
			wantErr: true,
		},
		"invalid_type": {
			value:   123,
			key:     "subject_format",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateSAMLSubjectFormat(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateSAMLSubjectFormat() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

func TestValidateOIDCClientType(t *testing.T) {
	tests := map[string]struct {
		value   interface{}
		key     string
		wantErr bool
	}{
		"valid_standard": {
			value:   "standard",
			key:     "client_type",
			wantErr: false,
		},
		"valid_confidential": {
			value:   "confidential",
			key:     "client_type",
			wantErr: false,
		},
		"valid_public": {
			value:   "public",
			key:     "client_type",
			wantErr: false,
		},
		"invalid_type": {
			value:   "invalid",
			key:     "client_type",
			wantErr: true,
		},
		"invalid_value_type": {
			value:   123,
			key:     "client_type",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateOIDCClientType(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateOIDCClientType() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

func TestValidateOIDCResponseType(t *testing.T) {
	tests := map[string]struct {
		value   interface{}
		key     string
		wantErr bool
	}{
		"valid_code": {
			value:   "code",
			key:     "response_type",
			wantErr: false,
		},
		"valid_id_token": {
			value:   "id_token",
			key:     "response_type",
			wantErr: false,
		},
		"valid_token": {
			value:   "token",
			key:     "response_type",
			wantErr: false,
		},
		"valid_code_id_token": {
			value:   "code id_token",
			key:     "response_type",
			wantErr: false,
		},
		"valid_code_token": {
			value:   "code token",
			key:     "response_type",
			wantErr: false,
		},
		"valid_id_token_token": {
			value:   "id_token token",
			key:     "response_type",
			wantErr: false,
		},
		"valid_code_id_token_token": {
			value:   "code id_token token",
			key:     "response_type",
			wantErr: false,
		},
		"invalid_response_type": {
			value:   "invalid",
			key:     "response_type",
			wantErr: true,
		},
		"invalid_type": {
			value:   123,
			key:     "response_type",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			warns, errs := validateOIDCResponseType(tt.value, tt.key)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateOIDCResponseType() errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(warns) > 0 {
				t.Logf("Warnings: %v", warns)
			}
		})
	}
}

