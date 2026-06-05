package eaaprovider

import (
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
)

func TestValidateSAMLSigningAlgorithm(t *testing.T) {
	testValidateFunc(t, validateSAMLSigningAlgorithm, "sign_algo", map[string]validateFuncCase{
		"valid_SHA1":         {val: string(client.SAMLSigningAlgorithmSHA1)},
		"valid_SHA256":       {val: string(client.SAMLSigningAlgorithmSHA256)},
		"invalid_SHA512":     {val: "SHA512", wantErr: true},
		"invalid_empty":      {val: "", wantErr: true},
		"invalid_non_string": {val: 123, wantErr: true},
	})
}

func TestValidateSAMLEncryptionAlgorithm(t *testing.T) {
	testValidateFunc(t, validateSAMLEncryptionAlgorithm, "encr_algo", map[string]validateFuncCase{
		"valid_aes128-cbc":   {val: string(client.SAMLEncryptionAlgorithmAES128CBC)},
		"valid_aes256-cbc":   {val: string(client.SAMLEncryptionAlgorithmAES256CBC)},
		"invalid_aes192-cbc": {val: "aes192-cbc", wantErr: true},
		"invalid_empty":      {val: "", wantErr: true},
		"invalid_non_string": {val: 42, wantErr: true},
	})
}

func TestValidateSAMLResponseBinding(t *testing.T) {
	testValidateFunc(t, validateSAMLResponseBinding, "resp_bind", map[string]validateFuncCase{
		"valid_post":         {val: string(client.SAMLResponseBindingPost)},
		"valid_redirect":     {val: string(client.SAMLResponseBindingRedirect)},
		"invalid_artifact":   {val: "artifact", wantErr: true},
		"invalid_empty":      {val: "", wantErr: true},
		"invalid_non_string": {val: true, wantErr: true},
	})
}

func TestValidateSAMLSubjectFormat(t *testing.T) {
	testValidateFunc(t, validateSAMLSubjectFormat, "subject_fmt", map[string]validateFuncCase{
		"valid_email":        {val: string(client.SAMLSubjectFormatEmail)},
		"valid_persistent":   {val: string(client.SAMLSubjectFormatPersistent)},
		"valid_unspecified":  {val: "unspecified"},
		"valid_transient":    {val: string(client.SAMLSubjectFormatTransient)},
		"invalid_nameid":     {val: "nameid", wantErr: true}, // defined in constants but NOT in validation's valid list
		"invalid_empty":      {val: "", wantErr: true},
		"invalid_non_string": {val: 999, wantErr: true},
	})
}

func TestValidateOIDCClientType(t *testing.T) {
	testValidateFunc(t, validateOIDCClientType, "client_type", map[string]validateFuncCase{
		"valid_standard":     {val: string(client.OIDCClientTypeStandard)},
		"valid_confidential": {val: string(client.OIDCClientTypeConfidential)},
		"valid_public":       {val: string(client.OIDCClientTypePublic)},
		"invalid_bearer":     {val: "bearer", wantErr: true},
		"invalid_empty":      {val: "", wantErr: true},
		"invalid_non_string": {val: []string{"standard"}, wantErr: true},
	})
}

func TestValidateOIDCResponseType(t *testing.T) {
	testValidateFunc(t, validateOIDCResponseType, "response_type", map[string]validateFuncCase{
		"valid_code":                {val: string(client.OIDCResponseTypeCode)},
		"valid_id_token":            {val: string(client.OIDCResponseTypeIDToken)},
		"valid_token":               {val: string(client.OIDCResponseTypeToken)},
		"valid_code_id_token":       {val: string(client.OIDCResponseTypeCodeIDToken)},
		"valid_code_token":          {val: string(client.OIDCResponseTypeCodeToken)},
		"valid_id_token_token":      {val: string(client.OIDCResponseTypeIDTokenToken)},
		"valid_code_id_token_token": {val: string(client.OIDCResponseTypeCodeIDTokenToken)},
		"invalid_password":          {val: "password", wantErr: true},
		"invalid_empty":             {val: "", wantErr: true},
		"invalid_non_string":        {val: 42, wantErr: true},
	})
}
